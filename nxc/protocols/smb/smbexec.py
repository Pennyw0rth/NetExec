import os
from os.path import join as path_join
from time import sleep
from impacket.dcerpc.v5 import scmr
from nxc.helpers.misc import gen_random_string
from nxc.paths import TMP_PATH
from nxc.helpers.rpc import NXCRPCConnection


class SMBEXEC:
    def __init__(self, connection, share=None, logger=None, tries=None):
        self.__connection = connection
        self.__share = share
        self.logger = logger
        self.__tries = tries

        self.__serviceName = gen_random_string()
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = b""
        self.__shell = "%COMSPEC% /Q /c "
        self.__retOutput = False

        rpc = NXCRPCConnection(self.__connection)
        self.__scmr = rpc.connect(r"\svcctl", scmr.MSRPC_UUID_SCMR)
        self.__rpctransport = rpc.transport

        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp["lpScHandle"]

    def execute(self, command, output=False):
        self.__retOutput = output
        if os.path.isfile(command):
            with open(command) as commands:
                for c in commands:
                    self.execute_remote(c.strip())
        else:
            self.execute_remote(command)
        self.finish()
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_remote(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + ".bat"

        command = self.__shell + "echo " + data + f" ^> \\\\%COMPUTERNAME%\\{self.__share}\\{self.__output} 2^>^&1 > %TEMP%\\{self.__batchFile} & %COMSPEC% /Q /c %TEMP%\\{self.__batchFile} & %COMSPEC% /Q /c del %TEMP%\\{self.__batchFile}" if self.__retOutput else self.__shell + data

        with open(path_join(TMP_PATH, self.__batchFile), "w") as batch_file:
            batch_file.write(command)

        self.logger.debug("Hosting batch file with command: " + command)
        self.logger.debug("Command to execute: " + command)
        self.logger.debug(f"Remote service {self.__serviceName} created.")

        try:
            resp = scmr.hRCreateServiceW(
                self.__scmr,
                self.__scHandle,
                self.__serviceName,
                self.__serviceName,
                lpBinaryPathName=command,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service = resp["lpServiceHandle"]
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                self.logger.fail("SMBEXEC: Create services got blocked.")
            else:
                self.logger.fail(str(e))

            return self.__outputBuffer

        try:
            self.logger.debug(f"Remote service {self.__serviceName} started.")
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception:
            pass

        try:
            self.logger.debug(f"Remote service {self.__serviceName} deleted.")
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception:
            pass

        self.get_output_remote()

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ""
            return

        tries = 1
        while True:
            try:
                self.logger.info(f"Attempting to read {self.__share}\\{self.__output}")
                self.__connection.conn.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if tries >= self.__tries:
                    self.logger.fail("SMBEXEC: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method")
                    break
                if "STATUS_BAD_NETWORK_NAME" in str(e):
                    self.logger.fail(f"SMBEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                    break
                elif "STATUS_VIRUS_INFECTED" in str(e):
                    self.logger.fail("Command did not run because a virus was detected")
                    break
                # When executing powershell and the command is still running, we get a sharing violation
                # We can use that information to wait longer than if the file is not found (probably av or something)
                if "STATUS_SHARING_VIOLATION" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} is still in use with {self.__tries - tries} tries left, retrying...")
                    tries += 1
                    sleep(1)
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} not found with {self.__tries - tries} tries left, deducting 10 tries and retrying...")
                    tries += 10
                    sleep(1)
                else:
                    self.logger.debug(f"Exception when trying to read output file: {e!s}. {self.__tries - tries} tries left, retrying...")
                    tries += 1
                    sleep(1)

        try:
            self.logger.debug(f"Deleting file {self.__share}\\{self.__output}")
            self.__connection.conn.deleteFile(self.__share, self.__output)
        except Exception:
            pass

    def finish(self):
        # Just in case the service is still created
        try:
            self.__scmr = self.__rpctransport.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp["lpScHandle"]
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp["lpServiceHandle"]
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except Exception:
            pass
