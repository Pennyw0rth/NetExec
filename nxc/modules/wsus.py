from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError

class NXCModule:
    """
    Check if the WSUS configuration on the target is vulnerable by inspecting the WUServer registry value.
    Module by @Tw1sm
    Modified for WSUS by @H4ckT0Th3Futur3
    """

    name = "wsus"
    description = "Checks if WSUS server is vulnerable by inspecting if WUServer registry value starts with 'http://'."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        self.output = "WSUS VULNERABLE: {} - WUServer URL = {}"
        self.suspect_prefix = module_options.get("SUSPECT_PREFIX", "http://")

    def on_admin_login(self, context, connection):
        try:
            # Initialiser les opérations à distance
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()

            # Vérifier si RemoteOperations est actif
            if remote_ops._RemoteOperations__rrp:
                # Ouvrir la clé de registre HKEY_LOCAL_MACHINE
                ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
                reg_handle = ans["phKey"]

                # Ouvrir la sous-clé de WSUS
                ans = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp,
                    reg_handle,
                    "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
                )
                key_handle = ans["phkResult"]
                
                try:
                    # Récupérer la valeur de WUServer
                    rtype, data = rrp.hBaseRegQueryValue(
                        remote_ops._RemoteOperations__rrp,
                        key_handle,
                        "WUServer\x00"
                    )

                    # Vérifier si la valeur de WUServer commence par le préfixe suspect
                    if data and data.startswith(self.suspect_prefix):
                        context.log.highlight(self.output.format(connection.conn.getRemoteHost(), data))
                    else:
                        context.log.info("WSUS is not vulnerable or WUServer registry value is secure.")
                
                except rrp.DCERPCSessionError:
                    context.log.debug("Unable to find WUServer, registry key may not exist or is not accessible.")
            
        except DCERPCSessionError as e:
            context.log.debug(f"Error connecting to RemoteRegistry: {e}")
        finally:
            # Fermer proprement la connexion au registre
            remote_ops.finish()
