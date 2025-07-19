import os
from textwrap import dedent
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep
from datetime import datetime, timedelta

# Thanks @Shad0wC0ntr0ller for the idea of removing the hardcoded date that could be used as an IOC
# Modified by @Defte_ so that output on multiples lines are printed correctly (28/04/2025)
# Modified by @Defte_ so that we can upload a custom binary to execute using the BINARY option (28/04/2025)


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, task_name=None, run_task_as=None, upload_task_binary=None, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
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
        self.smbConnection = None
        self.upload_task_binary = upload_task_binary
        # Specifies that the task should be run as SYSTEM (S-1-5-18) or the run_task_as username
        self.run_task_as = "S-1-5-18" if run_task_as is None else run_task_as
        # Specified the task name or a random one
        self.task_name = task_name if task_name is not None else gen_random_string(8)

        # Default places to upload a binary
        self.temp_dir = "\\Windows\\Temp\\"

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = rf"ncacn_np:{self.__target}[\pipe\atsvc]"
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

    def gen_xml(self, command):
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
        <Triggers>
            <RegistrationTrigger>
            <EndBoundary>{self.get_end_boundary()}</EndBoundary>
            </RegistrationTrigger>
        </Triggers>
        <Principals>
            <Principal id="LocalSystem">
            <UserId>{self.run_task_as}</UserId>
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
            self.__output_filename = f"{self.temp_dir}\{gen_random_string(6)}"
            argument_xml = f"      <Arguments>/C {command} &gt; {self.__output_filename} 2&gt;&amp;1</Arguments>"

        elif self.__retOutput is False:
            argument_xml = f"      <Arguments>/C {command}</Arguments>"

        self.logger.debug("Generated argument XML: " + argument_xml)
        xml += argument_xml

        xml += """
            </Exec>
        </Actions>
        </Task>
        """
        # Removing identation in the final computed XML file
        return dedent(xml)

    def execute_handler(self, command):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()

        # Creates a fully working SMB connection used to upload/delete files
        self.smbConnection = self.__rpctransport.get_smb_connection()

        # Uploads the binary that will be run via the scheduled task
        if self.upload_task_binary is not None:
            if os.path.isfile(self.upload_task_binary):
                self.logger.success(f"Binary {self.upload_task_binary} successfully uploaded")
                upload_task_binary = self.upload_task_binary
                # Strip the binary_name in case a path is provided
                binary_name = os.path.basename(upload_task_binary)
                # Uploads the file to \\Windows\Temp\binary.exe
                with open(upload_task_binary, "rb") as binary_content:
                    self.smbConnection.putFile(self.__share, f"{self.temp_dir}{binary_name}", binary_content.read)
                # Modifies the command to run to include full path
                command = f"{self.temp_dir}{command}"
            else:
                self.logger.fail(f"Cannot open {self.upload_task_binary}, canceling task creation")
                return

        xml = self.gen_xml(command)
        self.logger.debug(f"Creating task \\{self.task_name} with XML: {xml}")
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{self.task_name}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("Scheduled task creation was blocked.")
            # That error implies that it was not possible to translate the username to a valid windows station session ID
            elif hex(e.error_code) == "0x80070534":
                self.logger.fail(f"User {self.run_task_as} does not have a valid windows station session, cannot run the task.")
            else:
                self.logger.fail(f"Unknown atexec error: {e}")
            return

        done = False
        while not done:
            self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{self.task_name}")
            resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{self.task_name}")
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
            else:
                sleep(2)

        self.logger.info(f"Deleting task \\{self.task_name}")
        tsch.hSchRpcDelete(dce, f"\\{self.task_name}")

        if self.__retOutput:
            tries = 1
            # Give the command a bit of time to execute before we try to read the output, 0.4 seconds was good in testing
            sleep(0.4)
            while True:
                try:
                    self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                    self.smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
                    break
                except Exception as e:
                    if tries >= self.__tries:
                        self.logger.fail("ATEXEC: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method")
                        break
                    if "STATUS_BAD_NETWORK_NAME" in str(e):
                        self.logger.fail(f"ATEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                        break
                    elif "STATUS_VIRUS_INFECTED" in str(e):
                        self.logger.fail("Command did not run because a virus was detected")
                        break
                    # When executing powershell and the command is still running, we get a sharing violation
                    # We can use that information to wait longer than if the file is not found (probably av or something)
                    if "STATUS_SHARING_VIOLATION" in str(e):
                        self.logger.info(f"File {self.__share}\\{self.__output_filename} is still in use with {self.__tries - tries} tries left, retrying...")
                        tries += 1
                        sleep(1)
                    elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                        self.logger.info(f"File {self.__share}\\{self.__output_filename} not found with {self.__tries - tries} tries left, deducting 10 tries and retrying...")
                        tries += 10
                        sleep(1)
                    else:
                        self.logger.debug(f"Exception when trying to read output file: {e!s}. {self.__tries - tries} tries left, retrying...")
                        tries += 1
                        sleep(1)

            # Removes the output response file
            try:
                self.logger.debug(f"Deleting file {self.__share}\\{self.__output_filename}")
                self.smbConnection.deleteFile(self.__share, self.__output_filename)
            except Exception as e:
                self.logger.fail(f"Error while deleting file {self.__share}\{self.__output_filename}: {e}")

            # Removes the uploaded binary that was run via the scheduled task
            if self.upload_task_binary is not None:
                try:
                    self.logger.success(f"Binary {self.temp_dir}{binary_name} successfully deleted")
                    self.smbConnection.deleteFile(self.__share, f"{self.temp_dir}{binary_name}")
                except Exception as e:
                    self.logger.fail(f"Couldn't remove {self.temp_dir}{binary_name}: {e}")

        dce.disconnect()
