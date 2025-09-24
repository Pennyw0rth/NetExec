from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from nxc.helpers.misc import CATEGORY


class NXCModule:
    # Reworked by @Defte_ 13/10/2024 to remove unecessary execute operation
    name = "runasppl"
    description = "Check if the registry value RunAsPPL is set or not"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @staticmethod
    def register_module_options(subparsers):
        return subparsers

    def __init__(self, context=None, connection=None, module_options=None):
        self.context = context
        self.connection = connection

    def on_admin_login(self):
        try:
            remote_ops = RemoteOperations(self.connection.conn, False)
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
                    self.context.log.debug(f"RunAsPPL error {e} on host {self.connection.host}")

                if data is None or data not in [1, 2]:
                    self.context.log.highlight("RunAsPPL disabled")
                else:
                    self.context.log.highlight("RunAsPPL enabled")

        except DCERPCSessionError as e:
            self.context.log.debug(f"Error connecting to RemoteRegistry {e} on host {self.connection.host}")
        finally:
            remote_ops.finish()
