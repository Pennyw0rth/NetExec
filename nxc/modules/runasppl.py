from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError


class NXCModule:
    # Reworked by @Defte_ 13/10/2024 to remove unecessary execute operation
    name = "runasppl"
    description = "Check if the registry value RunAsPPL is set or not"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """"""

    def on_admin_login(self, context, connection):
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()

            if remote_ops._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
                reg_handle = ans["phKey"]
                ans = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp,
                    reg_handle,
                    "SYSTEM\\CurrentControlSet\\Control\\Lsa"
                )
                key_handle = ans["phkResult"]
                _ = data = None
                try:
                    _, data = rrp.hBaseRegQueryValue(
                        remote_ops._RemoteOperations__rrp,
                        key_handle,
                        "RunAsPPL\x00",
                    )
                except rrp.DCERPCSessionError as e:
                    context.log.debug(f"RunAsPPL error {e} on host {connection.host}")

                if data is None or data not in [1, 2]:
                    context.log.highlight("RunAsPPL disabled")
                else:
                    context.log.highlight("RunAsPPL enabled")
                
        except DCERPCSessionError as e:
            context.log.debug(f"Error connecting to RemoteRegistry {e} on host {connection.host}")
        finally:
            remote_ops.finish()
