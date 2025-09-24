from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Detect if the target's LmCompatibilityLevel will allow NTLMv1 authentication
    Module by @Tw1sm
    Modified by Deft (08/02/2024)
    """

    name = "ntlmv1"
    description = "Detect if lmcompatibilitylevel on the target is set to lower than 3 (which means ntlmv1 is enabled)"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @staticmethod
    def register_module_options(subparsers):
        return subparsers

    def __init__(self, context=None, connection=None, module_options=None):
        self.context = context
        self.connection = connection
        self.output = "NTLMv1 allowed on: {} - LmCompatibilityLevel = {}"

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
                    self.context.log.debug("Unable to reference lmcompatabilitylevel, which probably means ntlmv1 is not set")

                # Changed by Defte
                # Unless this keys is set to 3 or higher, NTLMv1 can be used
                if data in [0, 1, 2]:
                    self.context.log.highlight(self.output.format(self.connection.conn.getRemoteHost(), data))

        except DCERPCSessionError as e:
            self.context.log.debug(f"Error connecting to RemoteRegistry: {e}")
        finally:
            remote_ops.finish()
