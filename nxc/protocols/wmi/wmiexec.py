# Author: xiaolichan # noqa: ERA001
# Link: https://github.com/XiaoliChan/wmiexec-RegOut/blob/main/wmiexec-regOut.py
# Note: windows version under NT6 not working with this command execution way
#       https://github.com/XiaoliChan/wmiexec-RegOut/blob/main/wmiexec-reg-sch-UnderNT6-wip.py -- WIP
# Description:
#   For more details, please check out my repository.
#   https://github.com/XiaoliChan/wmiexec-RegOut
# Workflow:
#   Stage 1:
#       cmd.exe /Q /c {command} > C:\windows\temp\{random}.txt (aka command results)
#       powershell convert the command results into base64, and save it into C:\windows\temp\{random2}.txt (now the command results was base64 encoded)
#       Create registry path: HKLM:\Software\Classes\hello, then add C:\windows\temp\{random2}.txt into HKLM:\Software\Classes\hello\{NewKey}
#   Stage 2:
#       WQL query the HKLM:\Software\Classes\hello\{NewKey} and get results, after the results(base64 strings) retrieved, removed

import time
import uuid
import base64

from nxc.helpers.misc import gen_random_string
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login


class WMIEXEC:
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
        self.logger = logger
        self.__exec_timeout = exec_timeout
        self.__registry_Path = ""
        self.__outputBuffer = ""
        self.__retOutput = True

        self.__shell = "cmd.exe /Q /c "
        self.__pwd = "C:\\"
        self.__codec = codec

        self.__dcom = DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost, aesKey=self.__aesKey, remoteHost=self.__remoteHost)
        iInterface = self.__dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        self.__iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()
        self.__win32Process, _ = self.__iWbemServices.GetObject("Win32_Process")

    def execute(self, command, output=False):
        self.__retOutput = output
        if self.__retOutput:
            self.execute_WithOutput(command)
        else:
            command = self.__shell + command
            self.execute_remote(command)

        self.__dcom.disconnect()

        return self.__outputBuffer

    def execute_remote(self, command):
        self.logger.info(f"Executing command: {command}")
        try:
            self.__win32Process.Create(command, self.__pwd, None)
        except Exception as e:
            self.logger.error(str(e))

    def execute_WithOutput(self, command):
        result_output = f"C:\\windows\\temp\\{uuid.uuid4()!s}.txt"
        result_output_b64 = f"C:\\windows\\temp\\{uuid.uuid4()!s}.txt"
        keyName = str(uuid.uuid4())
        self.__registry_Path = f"Software\\Classes\\{gen_random_string(6)}"

        command = rf"""{self.__shell} {command} 1> {result_output} 2>&1 && certutil -encodehex -f {result_output} {result_output_b64} 0x40000001 && for /F "usebackq" %G in ("{result_output_b64}") do reg add HKLM\{self.__registry_Path} /v {keyName} /t REG_SZ /d "%G" /f && del /q /f /s {result_output} {result_output_b64}"""

        self.execute_remote(command)
        self.logger.info(f"Waiting {self.__exec_timeout}s for command completely executed.")
        time.sleep(self.__exec_timeout)

        self.queryRegistry(keyName)

    def queryRegistry(self, keyName):
        try:
            self.logger.debug(f"Querying registry key: HKLM\\{self.__registry_Path}")
            descriptor, _ = self.__iWbemServices.GetObject("StdRegProv")
            descriptor = descriptor.SpawnInstance()
            retVal = descriptor.GetStringValue(2147483650, self.__registry_Path, keyName)
            self.__outputBuffer = base64.b64decode(retVal.sValue).decode(self.__codec, errors="replace").rstrip("\r\n")
        except Exception:
            self.logger.fail("WMIEXEC: Could not retrieve output file, it may have been detected by AV. Please try increasing the timeout with the '--exec-timeout' option. If it is still failing, try the 'smb' protocol or another exec method")

        try:
            self.logger.debug(f"Removing temporary registry path: HKLM\\{self.__registry_Path}")
            retVal = descriptor.DeleteKey(2147483650, self.__registry_Path)
        except Exception as e:
            self.logger.debug(f"Target: {self.__target} removing temporary registry path error: {e!s}")
