import os
from time import sleep

from impacket import ntlm
from impacket.dcerpc.v5 import epm, scmr, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class SCSHELL:
    def __init__(
        self,
        target,
        username="",
        password="",
        domain="",
        doKerberos=False,
        aesKey=None,
        remoteHost=None,
        kdcHost=None,
        hashes=None,
        logger=None,
        service_name="RemoteRegistry",
        no_cmd=False,
        wait_time=5,
    ):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__serviceName = service_name
        self.__noCmd = no_cmd
        self.__waitTime = wait_time
        self.__rpctransport = None
        self.__scmr = None
        self.__scHandle = None
        self.__serviceHandle = None
        self.__binaryPath = None
        self.__startType = None
        self.__errorControl = None
        self.__outputBuffer = b""
        self.logger = logger

        if hashes is not None:
            if ":" in hashes:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        self._connect()

    def _connect(self):
        stringbinding = epm.hept_map(self.__target, scmr.MSRPC_UUID_SCMR, protocol="ncacn_ip_tcp")
        self.logger.debug(f"StringBinding {stringbinding}")
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self.__rpctransport, "setRemoteHost") and self.__remoteHost:
            self.__rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(self.__rpctransport, "set_credentials"):
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
            try:
                self.__scmr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            except Exception:
                pass

        try:
            self.__scmr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        except Exception:
            self.__scmr.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp["lpScHandle"]
        self.logger.debug(f"Opening service {self.__serviceName}")

        resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
        self.__serviceHandle = resp["lpServiceHandle"]

        resp = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
        service_config = resp["lpServiceConfig"]
        self.__binaryPath = service_config["lpBinaryPathName"]
        self.__startType = service_config["dwStartType"]
        self.__errorControl = service_config["dwErrorControl"]
        self.logger.debug(f"({self.__serviceName}) Current service binary path {self.__binaryPath}")

    def execute(self, command, output=False):
        self.__outputBuffer = b""
        if output:
            self.logger.info("SCSHELL does not support output retrieval, executing without output")

        if self.__noCmd:
            self.logger.info("SCSHELL is running in raw mode, the command should use a full binary path")

        try:
            if os.path.isfile(command):
                with open(command) as commands:
                    for line in commands:
                        line = line.strip()
                        if line:
                            self.execute_remote(line)
            else:
                self.execute_remote(command)
        finally:
            self.finish()

        return self.__outputBuffer

    def execute_remote(self, command):
        final_command = command if self.__noCmd else rf"C:\windows\system32\cmd.exe /Q /c {command}"
        self.logger.debug(f"({self.__serviceName}) Updating service binary path to {final_command}")

        try:
            scmr.hRChangeServiceConfigW(
                self.__scmr,
                self.__serviceHandle,
                scmr.SERVICE_NO_CHANGE,
                scmr.SERVICE_DEMAND_START,
                scmr.SERVICE_ERROR_IGNORE,
                final_command,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
            )
        except Exception as e:
            self.logger.fail(f"SCSHELL: Failed to update service {self.__serviceName}: {e}")
            return

        try:
            self.logger.debug(f"Starting service {self.__serviceName}")
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
        except Exception as e:
            error = str(e)
            if "ERROR_SERVICE_REQUEST_TIMEOUT" not in error:
                self.logger.fail(error)
        finally:
            sleep(self.__waitTime)
            self._restore_service_config()

    def _restore_service_config(self):
        if not self.__serviceHandle:
            return

        self.logger.debug(f"({self.__serviceName}) Reverting binary path to {self.__binaryPath}")
        try:
            scmr.hRChangeServiceConfigW(
                self.__scmr,
                self.__serviceHandle,
                scmr.SERVICE_NO_CHANGE,
                self.__startType,
                self.__errorControl,
                self.__binaryPath,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
            )
        except Exception as e:
            self.logger.fail(f"SCSHELL: Failed to restore service {self.__serviceName}: {e}")

    def finish(self):
        if self.__serviceHandle:
            try:
                scmr.hRCloseServiceHandle(self.__scmr, self.__serviceHandle)
            except Exception:
                pass
            finally:
                self.__serviceHandle = None

        if self.__scHandle:
            try:
                scmr.hRCloseServiceHandle(self.__scmr, self.__scHandle)
            except Exception:
                pass
            finally:
                self.__scHandle = None

        if self.__scmr:
            try:
                self.__scmr.disconnect()
            except Exception:
                pass
