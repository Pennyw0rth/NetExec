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


class WMIEXEC:
    def __init__(self, target, iWbemLevel1Login, logger, exec_timeout, codec):
        self.__target = target
        self.__iWbemLevel1Login = iWbemLevel1Login
        self.logger = logger
        self.__exec_timeout = exec_timeout
        self.__registry_Path = ""
        self.__outputBuffer = ""
        self.__shell = "cmd.exe /Q /c "
        self.__pwd = "C:\\"
        self.__codec = codec

        self.__iWbemServices = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.__iWbemLevel1Login.RemRelease()
        self.__win32Process, _ = self.__iWbemServices.GetObject("Win32_Process")

    def execute(self, command, output=False, use_powershell=False):
        """Execute a command on the remote host using WMI.
        Options:
        - No output
        - Output with bash (limited to ~1MB)
        - Output with PowerShell (recommended for larger outputs)
        """
        if output and not use_powershell:
            self.execute_WithOutput(command)
        elif output and use_powershell:
            self.execute_WithOutput_psh(command)
        else:
            command = self.__shell + command
            self.execute_remote(command)

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
        self.__registry_Path = f"Software\\Classes\\{gen_random_string(8)}"

        # 1. Run the command and write output to file
        self.execute_remote(f'{self.__shell} ({command}) 1> "{result_output}" 2>&1')
        self.logger.info(f"Waiting {self.__exec_timeout}s for command to complete.")
        time.sleep(self.__exec_timeout)

        # 2. Base64 encode the file
        self.execute_remote(f"{self.__shell} certutil -encodehex -f {result_output} {result_output_b64} 0x40000001")
        time.sleep(0.5)

        # 3. Store content in registry
        self.execute_remote(f'{self.__shell} for /F "usebackq" %G in ("{result_output_b64}") do reg add HKLM\\{self.__registry_Path} /v {keyName} /t REG_SZ /d "%G" /f')
        time.sleep(0.1)

        self.queryRegistry(keyName)
        self.clean_up(result_output, result_output_b64)

    def queryRegistry(self, keyName):
        try:
            # Spawn an instance of StdRegProv to access the registry
            self.logger.debug(f"Retrieving output from: HKLM\\{self.__registry_Path}")
            descriptor, _ = self.__iWbemServices.GetObject("StdRegProv")
            descriptor = descriptor.SpawnInstance()

            # Retrieve the base64 content from the registry
            for _ in range(10):
                self.logger.debug(f"Retrieving key: {keyName}")
                outputBuffer_b64 = descriptor.GetStringValue(0x80000002, self.__registry_Path, keyName).sValue
                if outputBuffer_b64 is not None:
                    break
                time.sleep(1)
            self.__outputBuffer = base64.b64decode(outputBuffer_b64).decode(self.__codec, errors="replace").rstrip("\r\n")
        except Exception:
            self.logger.fail("WMIEXEC: Could not retrieve output file! Either command timed out or AV killed the process. Please try increasing the timeout: '--exec-timeout 10'")

    def execute_WithOutput_psh(self, command):
        """Same functionality as execute_WithOutput, but uses PowerShell to handle larger outputs by splitting the base64 content into chunks and storing it in the registry."""
        result_output = f"C:\\windows\\temp\\{uuid.uuid4()!s}.txt"
        result_output_b64 = f"C:\\windows\\temp\\{uuid.uuid4()!s}.txt"
        keyName = str(uuid.uuid4())
        self.__registry_Path = f"Software\\Classes\\{gen_random_string(8)}"

        # 1. Run the command and write output to file
        if not command.lower().startswith("powershell"):
            command = f'powershell -Command "& {{{command}}}"'
        self.execute_remote(f'{command} > "{result_output}" 2>&1')
        self.logger.info(f"Waiting {self.__exec_timeout}s for command to complete.")
        time.sleep(self.__exec_timeout)

        # 2. Base64 encode the file using PowerShell
        self.execute_remote(f'powershell -Command "[Convert]::ToBase64String([IO.File]::ReadAllBytes(\'{result_output}\')) | Out-File -Encoding ASCII \'{result_output_b64}\'"')
        time.sleep(0.5)

        # 3. Use PowerShell to split base64 content into 16KB chunks and store in registry
        self.execute_remote(
            f'powershell -Command "$b64 = Get-Content -Raw \'{result_output_b64}\'; '
            f'$chunksize = 16000; '
            f'$count = [math]::Ceiling($b64.Length / $chunksize); '
            f'for ($i = 0; $i -lt $count; $i++) {{ '
            f'  $chunk = $b64.Substring($i * $chunksize, [math]::Min($chunksize, $b64.Length - ($i * $chunksize))); '
            f'  $name = \\"{keyName}_chunk_$i\\"; '
            f'  reg add \\"HKLM\\{self.__registry_Path}\\" /v $name /t REG_SZ /d $chunk /f }}; '
            f'reg add \\"HKLM\\{self.__registry_Path}\\" /v \\"{keyName}\\" /t REG_DWORD /d $count /f"'
        )
        time.sleep(0.1)

        self.queryRegistry_psh(keyName)
        self.clean_up(result_output, result_output_b64)

    def queryRegistry_psh(self, keyName):
        try:
            # Spawn an instance of StdRegProv to access the registry
            self.logger.debug(f"Retrieving output from: HKLM\\{self.__registry_Path}")
            descriptor, _ = self.__iWbemServices.GetObject("StdRegProv")
            descriptor = descriptor.SpawnInstance()

            # Get the number of chunks stored in the registry
            num_chunks = None
            for _ in range(10):
                self.logger.debug(f"Retrieving number of chunks for key: {keyName}")
                num_chunks = descriptor.GetDWORDValue(0x80000002, self.__registry_Path, keyName).uValue
                if num_chunks is not None:
                    break
                time.sleep(1)

            self.logger.debug(f"Number of chunks: {num_chunks}")

            # Retrieve each chunk and decode the base64 content
            outputBuffer_b64 = ""
            for i in range(num_chunks):
                chunk_name = f"{keyName}_chunk_{i}"
                self.logger.debug(f"Retrieving chunk: {chunk_name}")
                outputBuffer_b64 += descriptor.GetStringValue(0x80000002, self.__registry_Path, chunk_name).sValue
            self.__outputBuffer = base64.b64decode(outputBuffer_b64).decode("utf-16le", errors="replace").rstrip("\r\n").lstrip("\ufeff")  # Remove BOM if present
        except Exception:
            self.logger.fail("WMIEXEC: Could not retrieve output file! Either command timed out or AV killed the process. Please try increasing the timeout: '--exec-timeout 10'")

    def clean_up(self, result_output, result_output_b64):
        """Deletes the output file, the base64 output file, and the registry path where the base64 content was stored."""
        self.execute_remote(f'{self.__shell} del /q /f "{result_output}" "{result_output_b64}"')

        try:
            self.logger.debug(f"Removing temporary registry path: HKLM\\{self.__registry_Path}")
            descriptor, _ = self.__iWbemServices.GetObject("StdRegProv")
            descriptor = descriptor.SpawnInstance()
            descriptor.DeleteKey(0x80000002, self.__registry_Path)
        except Exception as e:
            self.logger.fail(f"Target: {self.__target} removing temporary registry path error: {e!s}")
