
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "uac"
    description = "Checks UAC status"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @staticmethod
    def register_module_options(subparsers):
        return subparsers

    def __init__(self, context=None, connection=None, module_options=None):
        self.context = context
        self.connection = connection

    def on_admin_login(self):
        remoteOps = RemoteOperations(self.connection.conn, False)
        remoteOps.enableRegistry()

        ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
        regHandle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(
            remoteOps._RemoteOperations__rrp,
            regHandle,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        )
        keyHandle = ans["phkResult"]
        _, uac_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "EnableLUA")

        if uac_value == 1:
            self.context.log.highlight("UAC Status: 1 (UAC Enabled)")
        elif uac_value == 0:
            self.context.log.highlight("UAC Status: 0 (UAC Disabled)")

        rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        remoteOps.finish()
