from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations


class NXCModule:
    """Module by @joaovarelas"""

    name = "hyperv-host"
    description = "Performs a registry query on the VM to lookup its HyperV Host"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """"""

    def on_admin_login(self, context, connection):
        self.context = context

        path = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"
        key = "HostName"

        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()

            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            # Query
            try:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, path)
                key_handle = ans["phkResult"]

                data_type, reg_value = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, key)
                self.context.log.highlight(f"{key}: {reg_value}")

                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

            except DCERPCException as e:
                self.context.log.debug(f"Registry key {path}\\{key} does not exist: {e}")

        except DCERPCException as e:
            self.context.log.fail(f"DCERPC Error while querying registry: {e}")
        except Exception as e:
            self.context.log.fail(f"Error while querying registry: {e}")
        finally:
            remote_ops.finish()
