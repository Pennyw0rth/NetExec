# Author: xiaolichan # noqa: ERA001
# Link: https://github.com/XiaoliChan/wmiexec-Pro
# Note: windows version under NT6 not working with this command execution way, it need Win32_ScheduledJob.
#       https://github.com/XiaoliChan/wmiexec-Pro/blob/main/lib/modules/exec_command.py
# Description:
#   For more details, please check out my repository.
#   https://github.com/XiaoliChan/wmiexec-Pro/blob/main/lib/modules/exec_command.py
# Workflow:
#   Stage 1:
#       Generate vbs with command.
#
#   Stage 2:
#       Execute vbs via wmi event, the vbs will write back the command result into new instance in ActiveScriptEventConsumer.Name="{command_ResultInstance}"
#
#   Stage 3:
#       Get result from reading wmi object ActiveScriptEventConsumer.Name="{command_ResultInstance}"
#
#   Stage 4:
#       Remove everything in wmi object

import time
import uuid
import base64
import sys

from io import StringIO
from nxc.helpers.powershell import get_ps_script
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login, WBEMSTATUS


class WMIEXEC_EVENT:
    def __init__(self, target, username, password, domain, lmhash, nthash, doKerberos, kdcHost, remoteHost, aesKey, logger, exec_timeout, codec):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__remoteHost = remoteHost
        self.__aesKey = aesKey
        self.__outputBuffer = ""
        self.__retOutput = True

        self.logger = logger
        self.__exec_timeout = exec_timeout
        self.__codec = codec
        self.__instanceID = f"windows-object-{uuid.uuid4()!s}"
        self.__instanceID_StoreResult = f"windows-object-{uuid.uuid4()!s}"

        self.__dcom = DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost, aesKey=self.__aesKey, remoteHost=self.__remoteHost)
        iInterface = self.__dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        self.__iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
        iWbemLevel1Login.RemRelease()

    def execute(self, command, output=False):
        if "'" in command:
            command = command.replace("'", r'"')
        self.__retOutput = output
        self.execute_handler(command)

        self.__dcom.disconnect()

        return self.__outputBuffer

    def execute_remote(self, command):
        self.logger.info(f"Executing command: {command}")
        try:
            self.execute_vbs(self.process_vbs(command))
        except Exception as e:
            self.logger.error(str(e))

    def execute_handler(self, command):
        # Generate vbsript and execute it
        self.logger.debug(f"{self.__target}: Execute command via wmi event, job instance id: {self.__instanceID}, command result instance id: {self.__instanceID_StoreResult}")
        self.execute_remote(command)

        # Get command results
        self.logger.info(f"Waiting {self.__exec_timeout}s for command completely executed.")
        time.sleep(self.__exec_timeout)

        if self.__retOutput:
            self.get_command_result()

        # Clean up
        self.remove_instance()

    def process_vbs(self, command):
        schedule_taskname = str(uuid.uuid4())
        # Link: https://github.com/XiaoliChan/wmiexec-Pro/blob/main/lib/vbscripts/Exec-Command-WithOutput.vbs
        # The reason why need to encode command to base64:
        #   because if some special charters in command like chinese,
        #   when wmi doing put instance, it will throwing a exception about data type error (lantin-1),
        #   but we can base64 encode it and submit the data without spcial charters to avoid it.
        if self.__retOutput:
            output_file = f"{uuid.uuid4()!s}.txt"
            with open(get_ps_script("wmiexec_event_vbscripts/Exec_Command_WithOutput.vbs")) as vbs_file:
                vbs = vbs_file.read()
            vbs = vbs.replace("REPLACE_ME_BASE64_COMMAND", base64.b64encode(command.encode()).decode())
            vbs = vbs.replace("REPLACE_ME_OUTPUT_FILE", output_file)
            vbs = vbs.replace("REPLACE_ME_INSTANCEID", self.__instanceID_StoreResult)
            vbs = vbs.replace("REPLACE_ME_TEMP_TASKNAME", schedule_taskname)
        else:
            # From wmihacker
            # Link: https://github.com/rootclay/WMIHACKER/blob/master/WMIHACKER_0.6.vbs
            with open(get_ps_script("wmiexec_event_vbscripts/Exec_Command_Silent.vbs")) as vbs_file:
                vbs = vbs_file.read()
            vbs = vbs.replace("REPLACE_ME_BASE64_COMMAND", base64.b64encode(command.encode()).decode())
            vbs = vbs.replace("REPLACE_ME_TEMP_TASKNAME", schedule_taskname)
        return vbs

    def check_error(self, banner, call_status):
        if call_status != 0:
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = "Unknown"
            self.logger.debug(f"{banner} - ERROR: {error_name} (0x{call_status:08x})")
        else:
            self.logger.debug(f"{banner} - OK")

    def execute_vbs(self, vbs_content):
        # Copy from wmipersist.py
        # Install ActiveScriptEventConsumer
        active_script, _ = self.__iWbemServices.GetObject("ActiveScriptEventConsumer")
        active_script = active_script.SpawnInstance()
        active_script.Name = self.__instanceID
        active_script.ScriptingEngine = "VBScript"
        active_script.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        active_script.ScriptText = vbs_content
        # Don't output impacket default verbose
        current = sys.stdout
        sys.stdout = StringIO()
        resp = self.__iWbemServices.PutInstance(active_script.marshalMe())
        sys.stdout = current
        self.check_error(f'Adding ActiveScriptEventConsumer.Name="{self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        # Timer means the amount of milliseconds after the script will be triggered, hard coding to 1 second it in this case.
        wmi_timer, _ = self.__iWbemServices.GetObject("__IntervalTimerInstruction")
        wmi_timer = wmi_timer.SpawnInstance()
        wmi_timer.TimerId = self.__instanceID
        wmi_timer.IntervalBetweenEvents = 1000
        # Don't output verbose
        current = sys.stdout
        sys.stdout = StringIO()
        resp = self.__iWbemServices.PutInstance(wmi_timer.marshalMe())
        sys.stdout = current
        self.check_error(f'Adding IntervalTimerInstruction.TimerId="{self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        # EventFilter
        event_filter, _ = self.__iWbemServices.GetObject("__EventFilter")
        event_filter = event_filter.SpawnInstance()
        event_filter.Name = self.__instanceID
        event_filter.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        event_filter.Query = f'select * from __TimerEvent where TimerID = "{self.__instanceID}" '
        event_filter.QueryLanguage = "WQL"
        event_filter.EventNamespace = r"root\subscription"
        # Don't output verbose
        current = sys.stdout
        sys.stdout = StringIO()
        resp = self.__iWbemServices.PutInstance(event_filter.marshalMe())
        sys.stdout = current
        self.check_error(f'Adding EventFilter.Name={self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        # Binding EventFilter & EventConsumer
        filter_binding, _ = self.__iWbemServices.GetObject("__FilterToConsumerBinding")
        filter_binding = filter_binding.SpawnInstance()
        filter_binding.Filter = f'__EventFilter.Name="{self.__instanceID}"'
        filter_binding.Consumer = f'ActiveScriptEventConsumer.Name="{self.__instanceID}"'
        filter_binding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
        # Don't output verbose
        current = sys.stdout
        sys.stdout = StringIO()
        resp = self.__iWbemServices.PutInstance(filter_binding.marshalMe())
        sys.stdout = current
        self.check_error(rf'Adding FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"{self.__instanceID}\"", Filter="__EventFilter.Name=\"{self.__instanceID}\""', resp.GetCallStatus(0) & 0xFFFFFFFF)

    def get_command_result(self):
        try:
            command_result_object, _ = self.__iWbemServices.GetObject(f'ActiveScriptEventConsumer.Name="{self.__instanceID_StoreResult}"')
            record = dict(command_result_object.getProperties())
            self.__outputBuffer = base64.b64decode(record["ScriptText"]["value"]).decode(self.__codec, errors="replace")
        except Exception:
            self.logger.fail("WMIEXEC-EVENT: Could not retrieve output file, it may have been detected by AV. Please try increasing the timeout with the '--exec-timeout' option. If it is still failing, try the 'smb' protocol or another exec method")

    def remove_instance(self):
        if self.__retOutput:
            resp = self.__iWbemServices.DeleteInstance(f'ActiveScriptEventConsumer.Name="{self.__instanceID_StoreResult}"')
            self.check_error(f'Removing ActiveScriptEventConsumer.Name="{self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        resp = self.__iWbemServices.DeleteInstance(f'ActiveScriptEventConsumer.Name="{self.__instanceID}"')
        self.check_error(f'Removing ActiveScriptEventConsumer.Name="{self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        resp = self.__iWbemServices.DeleteInstance(f'__IntervalTimerInstruction.TimerId="{self.__instanceID}"')
        self.check_error(f'Removing IntervalTimerInstruction.TimerId="{self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        resp = self.__iWbemServices.DeleteInstance(f'__EventFilter.Name="{self.__instanceID}"')
        self.check_error(f'Removing EventFilter.Name="{self.__instanceID}"', resp.GetCallStatus(0) & 0xFFFFFFFF)

        resp = self.__iWbemServices.DeleteInstance(rf'__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"{self.__instanceID}\"",Filter="__EventFilter.Name=\"{self.__instanceID}\""')
        self.check_error(rf'Removing FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\"{self.__instanceID}\"", Filter="__EventFilter.Name=\"{self.__instanceID}\""', resp.GetCallStatus(0) & 0xFFFFFFFF)
