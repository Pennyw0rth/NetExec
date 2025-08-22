import json
import logging
import operator
import os.path
import time

from impacket.system_errors import ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND, ERROR_OBJECT_NOT_FOUND
from termcolor import colored

from nxc.logger import nxc_logger
from nxc.paths import NXC_PATH
from impacket.dcerpc.v5 import rrp, samr, scmr
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError as SMBSessionError
from impacket.examples.secretsdump import RemoteOperations

# Configuration variables
OUTDATED_THRESHOLD = 30
DEFAULT_OUTPUT_FILE = "./wcc_results.json"
DEFAULT_OUTPUT_FORMAT = "json"
VALID_OUTPUT_FORMATS = ["json", "csv"]

# Registry value types
REG_VALUE_TYPE_UNDEFINED = 0
REG_VALUE_TYPE_UNICODE_STRING = 1
REG_VALUE_TYPE_UNICODE_STRING_WITH_ENV = 2
REG_VALUE_TYPE_BINARY = 3
REG_VALUE_TYPE_32BIT_LE = 4
REG_VALUE_TYPE_32BIT_BE = 5
REG_VALUE_TYPE_UNICODE_STRING_SEQUENCE = 7
REG_VALUE_TYPE_64BIT_LE = 11

checks_results = {}


class ConfigCheck:
    """Class for performing the checks and holding the results"""

    module = None

    def __init__(self, name, description="", category="Other", checkers=None, checker_args=None, checker_kwargs=None):
        if checker_kwargs is None:
            checker_kwargs = [{}]
        if checker_args is None:
            checker_args = [[]]
        if checkers is None:
            checkers = [None]
        self.check_id = None
        self.name = name
        self.description = description
        self.category = category
        assert len(checkers) == len(checker_args)
        assert len(checkers) == len(checker_kwargs)
        self.checkers = checkers
        self.checker_args = checker_args
        self.checker_kwargs = checker_kwargs
        self.ok = True
        self.reasons = []

    def run(self):
        for checker, args, kwargs in zip(self.checkers, self.checker_args, self.checker_kwargs, strict=True):
            if checker is None:
                checker = HostChecker.check_registry

            ok, reasons = checker(*args, **kwargs)
            self.ok = self.ok and ok
            self.reasons.extend(reasons)

    def log(self, context):
        result = "passed" if self.ok else "did not pass"
        reasons = ", ".join(self.reasons)
        self.module.wcc_logger.info(f'{self.connection.host}: Check "{self.name}" {result} because: {reasons}')
        if self.module.quiet:
            return

        status = colored("OK", "green", attrs=["bold"]) if self.ok else colored("KO", "red", attrs=["bold"])
        reasons = ": " + ", ".join(self.reasons)
        msg = f"{status} {self.name}"
        info_msg = f"{status} {self.name}{reasons}"
        context.log.highlight(msg)
        context.log.info(info_msg)


class NXCModule:
    """
    Windows Configuration Checker

    Module author: @__fpr (Orange Cyberdefense)
    """

    name = "wcc"
    description = "Check various security configuration items on Windows machines"
    supported_protocols = ["smb"]

    def __init__(self):
        self.context = None
        self.module_options = None

        self.wcc_logger = logging.getLogger("WCC")
        self.wcc_logger.propagate = False
        log_filename = nxc_logger.init_log_file()
        log_filename = log_filename.replace("log_", "wcc_")
        self.wcc_logger.setLevel(logging.INFO)
        wcc_file_handler = logging.FileHandler(log_filename)
        wcc_file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.wcc_logger.addHandler(wcc_file_handler)
        self.checks_results_path = NXC_PATH + "/tmp/wcc_checks_results.json"

        self.host_checker = HostChecker()

    def options(self, context, module_options):
        """
        CHECKS          Only perform checks whose name or category matches the ones listed
        LIST            List checks, grouped in categories. All checks are listed by default, but it is possible to query a specific category (case insensitive)
        OUTPUT_FORMAT   Format for report (Default: 'json')
        OUTPUT          Path for report
        QUIET           Do not print results to stdout (Default: False)
        """
        # Organize checks by category
        checks_by_category = {}
        for check in self.host_checker.checks:
            checks_by_category.setdefault(check.category, [])
            checks_by_category[check.category].append(check)

        if "LIST" in module_options:
            for category in sorted(checks_by_category.keys()):
                if module_options["LIST"].lower() not in ("", "*", "all") and category.lower() != module_options["LIST"].lower():
                    continue
                print(colored(f"[{category}]", "yellow", attrs=["bold"]))
                for check in checks_by_category[category]:
                    print(colored("[*]", "blue", attrs=["bold"]), f"{colored(check.name, attrs=['bold'])}: {check.description}")
                print()
            exit()

        self.output = module_options.get("OUTPUT")
        self.output_format = module_options.get("OUTPUT_FORMAT", DEFAULT_OUTPUT_FORMAT)
        if self.output_format not in VALID_OUTPUT_FORMATS:
            self.output_format = DEFAULT_OUTPUT_FORMAT
        self.quiet = module_options.get("QUIET", "false").lower() in ("true", "1")

        checks_filters = module_options.get("CHECKS", "")
        checks_to_perform = []

        # Only keep checks that match the filters provided
        if checks_filters:
            checks_filters = checks_filters.split(",")
            for _filter in checks_filters:
                _filter = _filter.lower()
                checks_to_perform.extend([check for check in self.host_checker.checks
                    if _filter in check.category.lower()
                    or _filter in check.name.lower()])
            self.host_checker.checks = checks_to_perform

        ConfigCheck.module = self
        HostChecker.module = self

        # Load intermediary results into checks_results
        if self.output and os.path.isfile(self.checks_results_path):
            with open(self.checks_results_path) as f:
                checks_results.update(json.load(f))

    def on_admin_login(self, context, connection):
        self.context = context
        self.host_checker.setup_remops(context, connection)
        self.host_checker.run()
        if self.output is not None:
            self.export_results()

    def add_result(self, host, result):
        checks_results.setdefault(host, {"checks": []})
        d = {"Check": result.name, "Description": result.description, "Status": "OK" if result.ok else "KO", "Reasons": result.reasons}
        if d not in checks_results[host]["checks"]:
            checks_results[host]["checks"].append(d)

    def export_results(self):
        with open(self.output, "w") as output:
            if self.output_format == "json":
                json.dump(checks_results, output)
            elif self.output_format == "csv":
                output.write("Host,Check,Description,Status,Reasons")
                for host in checks_results:
                    for result in checks_results[host]["checks"]:
                        output.write(f"\n{host}")
                        for field in (result["Check"], result["Description"], result["Status"], " ; ".join(result["Reasons"]).replace("\x00", "")):
                            if "," in field:
                                field = field.replace('"', '""')
                                field = f'"{field}"'
                            output.write(f",{field}")

        # Save intermediary results
        with open(self.checks_results_path, "w") as f:
            json.dump(checks_results, f)

        self.context.log.success(f"Results written to {self.output}")


class HostChecker:
    module = None

    def __init__(self):
        self.context = None
        self.connection = None
        self.dce = None

        # Declare the checks to do and how to do them
        self.checks = [
            ConfigCheck(
                name="Last successful update age",
                description="Checks how old is the last successful update",
                category="Updates",
                checkers=[self.check_last_successful_update]
            ),
            ConfigCheck(
                name="LAPS installed",
                description="Checks if LAPS is installed",
                category="Authentication",
                checkers=[self.check_laps]
            ),
            ConfigCheck(
                name="Administrator account renamed",
                description="Checks if Administror user name has been changed",
                category="Accounts",
                checkers=[self.check_administrator_name]
            ),
            ConfigCheck(
                name="UAC configuration",
                description="Checks if UAC configuration is secure",
                checker_args=[[self,
                    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", 1),
                    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "LocalAccountTokenFilterPolicy", 0)
                ]]
            ),
            ConfigCheck(
                name="LM hash storage disabled",
                description="Checks if storing  hashes in LM format is disabled",
                category="Authentication",
                checker_args=[[self, ("HKLM\\System\\CurrentControlSet\\Control\\Lsa", "NoLMHash", 1)]]
            ),
            ConfigCheck(
                name="Always install elevated disabled",
                description="Checks if AlwaysInstallElevated is disabled",
                checker_args=[[self, ("HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", "AlwaysInstallElevated", 0)]]
            ),
            ConfigCheck(
                name="IPv4 preferred over IPv6",
                description="Checks if IPv4 is preferred over IPv6",
                category="Network",
                checker_args=[[self, ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", "DisabledComponents", (32, 255), in_)]]
            ),
            ConfigCheck(
                name="Spooler service disabled",
                description="Checks if the spooler service is disabled",
                checkers=[self.check_spooler_service]
            ),
            ConfigCheck(
                name="WDigest authentication disabled",
                description="Checks if WDigest authentication is disabled",
                category="Authentication",
                checker_args=[[self, ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", 0)]]
            ),
            ConfigCheck(
                name="WSUS configuration",
                description="Checks if WSUS configuration uses HTTPS",
                category="Updates",
                checkers=[self.check_wsus_running, None],
                checker_args=[
                    [],
                    [self,
                     ("HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate", "WUServer", "https://", startswith),
                     ("HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "UseWUServer", 0, operator.eq)
                    ]
                ],
                checker_kwargs=[{}, {"options": {"lastWins": True}}]
            ),
            ConfigCheck(
                name="Small LSA cache",
                description="Checks how many logons are kept in the LSA cache",
                category="Authentication",
                checker_args=[[self, ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "CachedLogonsCount", 2, le)]]
            ),
            ConfigCheck(
                name="AppLocker rules defined",
                description="Checks if there are AppLocker rules defined",
                checkers=[self.check_applocker]
            ),
            ConfigCheck(
                name="RDP expiration time",
                description="Checks RDP session timeout",
                category="RDP",
                checker_args=[[self,
                    ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "MaxDisconnectionTime", 0, operator.gt),
                    ("HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "MaxDisconnectionTime", 0, operator.gt)
                ]]
            ),
            ConfigCheck(
                name="CredentialGuard enabled",
                description="Checks if CredentialGuard is enabled",
                category="LSASS",
                checker_args=[[self,
                    ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", "EnableVirtualizationBasedSecurity", 1),
                    ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "LsaCfgFlags", 1)
                ]]
            ),
            ConfigCheck(
                name="Lsass run as PPL",
                description="Checks if lsass runs as a protected process",
                category="LSASS",
                checker_args=[[self, ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL", 1)]]
            ),
            ConfigCheck(
                name="No Powershell v2",
                description="Checks if powershell v2 is available",
                category="Powershell",
                checker_args=[[self, ("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", "PSCompatibleVersion", "2.0", not_(operator.contains))]]
            ),
            ConfigCheck(
                name="LLMNR disabled",
                description="Checks if LLMNR is disabled",
                category="Network",
                checker_args=[[self, ("HKLM\\Software\\policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast", 0)]]
            ),
            ConfigCheck(
                name="LmCompatibilityLevel == 5",
                description="Checks if LmCompatibilityLevel is set to 5",
                category="Authentication",
                checker_args=[[self, ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel", 5, operator.ge)]]
            ),
            ConfigCheck(
                name="NBTNS disabled",
                description="Checks if NBTNS is disabled on all interfaces",
                category="Network",
                checkers=[self.check_nbtns]
            ),
            ConfigCheck(
                name="mDNS disabled",
                description="Checks if mDNS is disabled",
                category="Network",
                checker_args=[[self, ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNScache\\Parameters", "EnableMDNS", 0)]]
            ),
            ConfigCheck(
                name="SMB signing enabled",
                description="Checks if SMB signing is enabled",
                category="Network",
                checker_args=[[self, ("HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "requiresecuritysignature", 1)]]
            ),
            ConfigCheck(
                name="LDAP signing enabled",
                description="Checks if LDAP signing is enabled",
                category="Network",
                checker_args=[[self,
                    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", "LDAPServerIntegrity", 2),
                    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS", "LdapEnforceChannelBinding", 2)
                ]]
            ),
            ConfigCheck(
                name="SMB encryption enabled",
                description="Checks if SMB encryption is enabled",
                category="Network",
                checker_args=[[self, ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "EncryptData", 1)]]
            ),
            ConfigCheck(
                name="RDP authentication",
                description="Checks RDP authentication configuration (NLA auth and restricted admin mode)",
                category="RDP",
                checker_args=[[self,
                    ("HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\", "UserAuthentication", 1),
                    ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA", "RestrictedAdminMode", 1)
                ]]
            ),
            ConfigCheck(
                name="BitLocker configuration",
                description="Checks the BitLocker configuration (based on https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-94859)",
                checker_args=[[self,
                    ("HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE", "UseAdvancedStartup", 1),
                    ("HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE", "UseTPMPIN", 1)
                ]]
            ),
            ConfigCheck(
                name="Guest account disabled",
                description="Checks if the guest account is disabled",
                category="Accounts",
                checkers=[self.check_guest_account_disabled]
            ),
            ConfigCheck(
                name="Automatic session lock enabled",
                description="Checks if the session is automatically locked on after a period of inactivity",
                checker_args=[[self,
                    ("HKCU\\Control Panel\\Desktop", "ScreenSaverIsSecure", 1),
                    ("HKCU\\Control Panel\\Desktop", "ScreenSaveTimeOut", 300, le)
                ]]
            ),
            ConfigCheck(
                name='Powershell Execution Policy == "Restricted"',
                description='Checks if the Powershell execution policy is set to "Restricted"',
                category="Powershell",
                checker_args=[[self,
                    ("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell", "ExecutionPolicy", "Restricted\x00"),
                    ("HKCU\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell", "ExecutionPolicy", "Restricted\x00")
                ]],
                checker_kwargs=[{"options": {"KOIfMissing": False, "lastWins": True}}]
            ),
            ConfigCheck(
                name="Defender service running",
                description="Checks if defender service is enabled",
                category="Defender",
                checkers=[self.check_defender_service]
            ),
            ConfigCheck(
                name="Defender Tamper Protection enabled",
                description="Check if Defender Tamper Protection is enabled",
                category="Defender",
                checker_args=[[self, ("HKLM\\Software\\Microsoft\\Windows Defender\\Features", "TamperProtection", 5)]]
            ),
            ConfigCheck(
                name="Defender RealTime Monitoring enabled",
                description="Check if Defender RealTime Monitoring is enabled",
                category="Defender",
                checker_args=[[self,
                    ("HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 0),
                    ("HKLM\\Software\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 0)
                ]],
                checker_kwargs=[{"options": {"lastWins": True, "stopOnOK": True}}]
            ),
            ConfigCheck(
                name="Defender IOAV Protection enabled",
                description="Check if Defender IOAV Protection is enabled",
                category="Defender",
                checker_args=[[self,
                    ("HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableIOAVProtection", 0),
                    ("HKLM\\Software\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableIOAVProtection", 0)
                ]],
                checker_kwargs=[{"options": {"lastWins": True, "stopOnOK": True}}]
            ),
            ConfigCheck(
                name="Defender Behaviour Monitoring enabled",
                description="Check if Defender Behaviour Monitoring is enabled",
                category="Defender",
                checker_args=[[self,
                    ("HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableBehaviourMonitoring", 0),
                    ("HKLM\\Software\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableBehaviourMonitoring", 0)
                ]],
                checker_kwargs=[{"options": {"lastWins": True, "stopOnOK": True}}]
            ),
            ConfigCheck(
                name="Defender Script Scanning enabled",
                description="Check if Defender Script Scanning is enabled",
                category="Defender",
                checker_args=[[self,
                    ("HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableScriptScanning", 0),
                    ("HKLM\\Software\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableScriptScanning", 0)
                ]],
                checker_kwargs=[{"options": {"lastWins": True, "stopOnOK": True}}]
            ),
            ConfigCheck(
                name="Defender no path exclusions",
                description="Checks Defender path exclusion",
                category="Defender",
                checkers=[self.check_defender_exclusion],
                checker_args=[("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths")]
            ),
            ConfigCheck(
                name="Defender no extension exclusions",
                description="Checks Defender extension exclusion",
                category="Defender",
                checkers=[self.check_defender_exclusion],
                checker_args=[("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions")])
        ]

    def setup_remops(self, context, connection):
        self.context = context
        self.connection = connection
        remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
        remoteOps.enableRegistry()
        self.dce = remoteOps._RemoteOperations__rrp

    def run(self):
        self.init_checks()
        self.check_config()

    def init_checks(self):

        # Add check to conf_checks table if missing
        db_checks = self.connection.db.get_checks()
        [check._asdict()["name"].strip().lower() for check in db_checks]
        added = []
        for i, check in enumerate(self.checks):
            check.connection = self.connection
            missing = True
            for db_check in db_checks:
                db_check = db_check._asdict()
                if check.name.strip().lower() == db_check["name"].strip().lower():
                    missing = False
                    self.checks[i].check_id = db_check["id"]
                    break

            if missing:
                self.connection.db.add_check(check.name, check.description)
                added.append(check)

        # Update check_id for checks added to the db
        db_checks = self.connection.db.get_checks()
        for i, check in enumerate(added):
            check_id = None
            for db_check in db_checks:
                db_check = db_check._asdict()
                if db_check["name"].strip().lower() == check.name.strip().lower():
                    check_id = db_check["id"]
                    break
            added[i].check_id = check_id

    def check_config(self):
        # Get host ID from db
        host_id = None
        hosts = self.connection.db.get_hosts(self.connection.host)
        for host in hosts:
            host = host._asdict()
            if host["ip"] == self.connection.host and host["hostname"] == self.connection.hostname and host["domain"] == self.connection.domain:
                host_id = host["id"]
                break

        # Perform all the checks and store the results
        for check in self.checks:
            try:
                check.run()
            except Exception as e:
                self.context.log.error(f"HostChecker.check_config(): Error while performing check {check.name}: {e}")
            check.log(self.context)
            self.module.add_result(self.connection.host, check)
            if host_id is not None:
                self.connection.db.add_check_result(host_id, check.check_id, check.ok, ", ".join(check.reasons).replace("\x00", ""))

    def check_registry(self, *specs, options=None, stop_on_error=False):
        """
        Perform checks that only require to compare values in the registry with expected values, according to the specs
        a spec may be either a 3-tuple: (key name, value name, expected value), or a 4-tuple (key name, value name, expected value, operation), where operation is a function that implements a comparison operator
        """
        if options is None:
            options = {}
        default_options = {"lastWins": False, "stopOnOK": False, "stopOnKO": False, "KOIfMissing": True}
        default_options.update(options)
        options = default_options
        op = operator.eq
        ok = True
        reasons = []

        for spec in specs:
            try:
                if len(spec) == 3:
                    (key, value_name, expected_value) = spec
                    op = operator.eq
                elif len(spec) == 4:
                    (key, value_name, expected_value, op) = spec
                else:
                    ok = False
                    reasons = ["Check could not be performed (invalid specification provided)"]
                    return ok, reasons
            except Exception as e:
                self.context.log.error(f"Check could not be performed. Details: specs={specs}, dce={self.dce}, error: {e}")
                return ok, reasons

            if op == operator.eq:
                opstring = "{left} == {right}"
                nopstring = "{left} != {right}"
            elif op == operator.contains:
                opstring = "{left} in {right}"
                nopstring = "{left} not in {right}"
            elif op == operator.gt:
                opstring = "{left} > {right}"
                nopstring = "{left} <= {right}"
            elif op == operator.ge:
                opstring = "{left} >= {right}"
                nopstring = "{left} < {right}"
            elif op == operator.lt:
                opstring = "{left} < {right}"
                nopstring = "{left} >= {right}"
            elif op == operator.le:
                opstring = "{left} <= {right}"
                nopstring = "{left} > {right}"
            elif op == operator.ne:
                opstring = "{left} != {right}"
                nopstring = "{left} == {right}"
            else:
                opstring = f"{op.__name__}({{left}}, {{right}}) == True"
                nopstring = f"{op.__name__}({{left}}, {{right}}) == True"

            value = self.reg_query_value(self.dce, self.connection, key, value_name)

            if isinstance(value, DCERPCSessionError):
                if options["KOIfMissing"]:
                    ok = False
                if value.error_code in (ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND):
                    reasons.append(f"{key}: Key not found")
                elif value.error_code == ERROR_OBJECT_NOT_FOUND:
                    reasons.append(f"{value_name}: Value not found")
                else:
                    ok = False
                    reasons.append(f"Error while retrieving value of {key}\\{value_name}: {value}")
                if stop_on_error:
                    ok = None
                    return ok, reasons
                continue

            if op(value, expected_value):
                if options["lastWins"]:
                    ok = True
                reasons.append(opstring.format(left=f"{key}\\{value_name} ({value})", right=expected_value))
            else:
                reasons.append(nopstring.format(left=f"{key}\\{value_name} ({value})", right=expected_value))
                ok = False
            if ok and options["stopOnOK"]:
                break
            if not ok and options["stopOnKO"]:
                break

        return ok, reasons

    def check_laps(self):
        reasons = []
        success = False
        lapsv2_ad_key_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS"
        lapsv2_aad_key_name = "Software\\Microsoft\\Policies\\LAPS"

        # Checking LAPSv2
        ans = self._open_root_key(self.dce, self.connection, "HKLM")

        if ans is None:
            return False, ["Could not query remote registry"]

        root_key_handle = ans["phKey"]
        try:
            ans = rrp.hBaseRegOpenKey(self.dce, root_key_handle, lapsv2_ad_key_name)
            reasons.append(f"HKLM\\{lapsv2_ad_key_name} found, LAPSv2 AD installed")
            success = True
            return success, reasons
        except DCERPCSessionError as e:
            if e.error_code != ERROR_FILE_NOT_FOUND:
                reasons.append(f"HKLM\\{lapsv2_ad_key_name} not found")

        try:
            ans = rrp.hBaseRegOpenKey(self.dce, root_key_handle, lapsv2_aad_key_name)
            reasons.append(f"HKLM\\{lapsv2_aad_key_name} found, LAPSv2 AAD installed")
            success = True
            return success, reasons
        except DCERPCSessionError as e:
            if e.error_code != ERROR_FILE_NOT_FOUND:
                reasons.append(f"HKLM\\{lapsv2_aad_key_name} not found")

        # LAPSv2 does not seems to be installed, checking LAPSv1
        lapsv1_key_name = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPextensions"
        subkeys = self.reg_get_subkeys(self.dce, self.connection, lapsv1_key_name)
        laps_path = "\\Program Files\\LAPS\\CSE"

        for subkey in subkeys:
            value = self.reg_query_value(self.dce, self.connection, lapsv1_key_name + "\\" + subkey, "DllName")
            if isinstance(value, str) and "laps\\cse\\admpwd.dll" in value.lower():
                reasons.append(f"{lapsv1_key_name}\\...\\DllName matches AdmPwd.dll")
                success = True
                laps_path = "\\".join(value.split("\\")[1:-1])
                break
        if not success:
            reasons.append(f"No match found in {lapsv1_key_name}\\...\\DllName")

        file_listing = self.ls(self.connection, laps_path)
        if file_listing:
            reasons.append("Found LAPS folder at " + laps_path)
        else:
            success = False
            reasons.append("LAPS folder does not exist")
            return success, reasons

        file_listing = self.ls(self.connection, laps_path + "\\AdmPwd.dll")
        if file_listing:
            reasons.append(f"Found {laps_path}\\AdmPwd.dll")
        else:
            success = False
            reasons.append(f"{laps_path}\\AdmPwd.dll not found")

        return success, reasons

    def check_last_successful_update(self):
        records = self.connection.wmi(wmi_query="Select TimeGenerated FROM Win32_ReliabilityRecords Where EventIdentifier=19", namespace="root\\cimv2")
        if isinstance(records, bool) or len(records) == 0:
            return False, ["No update found"]
        most_recent_update_date = records[0]["TimeGenerated"]["value"]
        most_recent_update_date = most_recent_update_date.split(".")[0]
        most_recent_update_date = time.strptime(most_recent_update_date, "%Y%m%d%H%M%S")
        most_recent_update_date = time.mktime(most_recent_update_date)
        now = time.time()
        days_since_last_update = (now - most_recent_update_date) // 86400
        if days_since_last_update <= OUTDATED_THRESHOLD:
            return True, [f"Last update was {days_since_last_update} <= {OUTDATED_THRESHOLD} days ago"]
        else:
            return False, [f"Last update was {days_since_last_update} > {OUTDATED_THRESHOLD} days ago"]

    def check_administrator_name(self):
        user_info = self.get_user_info(self.connection, rid=500)
        name = user_info["UserName"]
        ok = name not in ("Administrator", "Administrateur")
        reasons = [f"Administrator name changed to {name}" if ok else "Administrator name unchanged"]
        return ok, reasons

    def check_guest_account_disabled(self):
        user_info = self.get_user_info(self.connection, rid=501)
        uac = user_info["UserAccountControl"]
        disabled = bool(uac & samr.USER_ACCOUNT_DISABLED)
        reasons = ["Guest account disabled" if disabled else "Guest account enabled"]
        return disabled, reasons

    def check_spooler_service(self):
        ok = False
        service_config, service_status = self.get_service("Spooler", self.connection)
        if service_config["dwStartType"] == scmr.SERVICE_DISABLED:
            ok = True
            reasons = ["Spooler service disabled"]
        else:
            reasons = ["Spooler service enabled"]
            if service_status == scmr.SERVICE_RUNNING:
                reasons.append("Spooler service running")
            elif service_status == scmr.SERVICE_STOPPED:
                ok = True
                reasons.append("Spooler service not running")

        return ok, reasons

    def check_wsus_running(self):
        ok = True
        reasons = []
        service_config, service_status = self.get_service("wuauserv", self.connection)
        if service_config["dwStartType"] == scmr.SERVICE_DISABLED:
            reasons = ["WSUS service disabled"]
        elif service_status != scmr.SERVICE_RUNNING:
            reasons = ["WSUS service not running"]
        return ok, reasons

    def check_nbtns(self):
        adapters_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
        key_name = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces"
        subkeys = self.reg_get_subkeys(self.dce, self.connection, key_name)
        success = False
        reasons = []
        missing = 0
        nbtns_enabled = 0

        for subkey in subkeys:
            # Ignore Microsoft Kernel Debug Network Adapter
            kdnic_key = adapters_key + "\\0000"
            kdnic_uuid = self.reg_query_value(self.dce, self.connection, kdnic_key, "NetCfgInstanceId")
            if subkey.lower() == ("Tcpip_" + kdnic_uuid).replace("\x00", "").lower():
                continue

            value = self.reg_query_value(self.dce, self.connection, key_name + "\\" + subkey, "NetbiosOptions")
            if isinstance(value, DCERPCSessionError):
                if value.error_code == ERROR_OBJECT_NOT_FOUND:
                    missing += 1
                continue
            if value != 2:
                nbtns_enabled += 1
        if missing > 0:
            reasons.append(f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\<interface>\\NetbiosOption: value not found on {missing} interfaces")
        if nbtns_enabled > 0:
            reasons.append(f"NBTNS enabled on {nbtns_enabled} interfaces out of {len(subkeys)}")
        if missing == 0 and nbtns_enabled == 0:
            success = True
            reasons.append("NBTNS disabled on all interfaces")
        return success, reasons

    def check_applocker(self):
        key_name = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2"
        subkeys = self.reg_get_subkeys(self.dce, self.connection, key_name)
        rule_count = 0
        for collection in subkeys:
            collection_key_name = key_name + "\\" + collection
            rules = self.reg_get_subkeys(self.dce, self.connection, collection_key_name)
            rule_count += len(rules)
        success = rule_count > 0
        reasons = [f"Found {rule_count} AppLocker rules defined"]

        return success, reasons

    def get_exclusions(self, key_name):
        exclusions = []
        try:
            values = self.reg_query_value(self.dce, self.connection, key_name, valueName=None, all_value=True)
            for _, value_name, _ in values:
                exclusions.append(value_name)
        except Exception:
            self.context.log.debug("No defender exclusion policies")

        return len(exclusions), exclusions

    def check_defender_exclusion(self, *spec, options=None):
        try:
            if len(spec) == 2:
                (policy_key_name, key_name) = spec
            else:
                ok = False
                reasons = ["Check could not be performed (invalid specification provided)"]
                return ok, reasons
        except Exception as e:
            self.context.log.error(f"Check could not be performed. Details: spec={spec}, dce={self.dce}, error: {e}")
            return ok, reasons

        reasons = []
        success = True

        count, exclusions_p = self.get_exclusions(policy_key_name)
        reasons = [f"Policy: [{', '.join(exclusions_p)}]"]
        count_k, exclusions_k = self.get_exclusions(key_name)
        reasons.append(f"Manual: [{', '.join(exclusions_k)}]")
        count += count_k

        if count > 0:
            success = False

        return success, reasons

    def check_defender_service(self):
        ok = True
        raised = False
        reasons = []
        try:
            service_config, service_status = self.get_service("windefend", self.connection)
            if service_status == scmr.SERVICE_RUNNING:
                reasons.append("windefend service running")
            elif service_status == scmr.SERVICE_STOPPED:
                ok = False
                reasons.append("windefend service not running")
        except DCERPCException as e:
            ok = True
            raised = True
            reasons = [f"windefend service check error({e})"]
        if ok is False or raised is True:
            try:
                service_config, service_status = self.get_service("sense", self.connection)
                if service_status == scmr.SERVICE_RUNNING:
                    reasons.append("sense service running")
                elif service_status == scmr.SERVICE_STOPPED:
                    ok = False
                    reasons.append("sense service not running")
            except DCERPCException as e:
                ok = True
                raised = True
                reasons.append(f"sense service check error({e})")
        if raised is True:
            reasons_save = reasons
            args = ("HKLM\\SOFTWARE\\Microsoft\\Windows Defender", "IsServiceRunning", 1)
            ok, reasons = self.check_registry(args)
            reasons.extend(reasons_save)

        return ok, reasons

    def _open_root_key(self, dce, connection, root_key):
        ans = None
        retries = 1
        opener = {"HKLM": rrp.hOpenLocalMachine, "HKCR": rrp.hOpenClassesRoot, "HKU": rrp.hOpenUsers, "HKCU": rrp.hOpenCurrentUser, "HKCC": rrp.hOpenCurrentConfig}

        while retries > 0:
            try:
                ans = opener[root_key.upper()](dce)
                break
            except KeyError:
                self.context.log.error(f"HostChecker._open_root_key():{connection.host}: Invalid root key. Must be one of HKCR, HKCC, HKCU, HKLM or HKU")
                break
            except Exception as e:
                self.context.log.error(f"HostChecker._open_root_key():{connection.host}: Error while trying to open {root_key.upper()}: {e}")
                if "Broken pipe" in e.args:
                    self.context.log.error("Retrying")
                    retries -= 1
        return ans

    def reg_get_subkeys(self, dce, connection, key_name):
        root_key, subkey = key_name.split("\\", 1)
        ans = self._open_root_key(dce, connection, root_key)
        subkeys = []
        if ans is None:
            return subkeys

        root_key_handle = ans["phKey"]
        try:
            ans = rrp.hBaseRegOpenKey(dce, root_key_handle, subkey)
        except DCERPCSessionError as e:
            if e.error_code != ERROR_FILE_NOT_FOUND:
                self.context.log.error(f"HostChecker.reg_get_subkeys(): Could not retrieve subkey {subkey}: {e}\n")
            return subkeys
        except Exception as e:
            self.context.log.error(f"HostChecker.reg_get_subkeys(): Error while trying to retrieve subkey {subkey}: {e}\n")
            return subkeys

        subkey_handle = ans["phkResult"]
        i = 0
        while True:
            try:
                ans = rrp.hBaseRegEnumKey(dce=dce, hKey=subkey_handle, dwIndex=i)
                subkeys.append(ans["lpNameOut"][:-1])
                i += 1
            except DCERPCSessionError:
                break
        return subkeys

    def reg_query_value(self, dce, connection, keyName, valueName=None, all_value=False):
        """Query remote registry data for a given registry value"""

        def subkey_values(subkey_handle):
            dw_index = 0
            while True:
                try:
                    value_type, value_name, value_data = get_value(subkey_handle, dw_index)
                    yield value_type, value_name, value_data
                    dw_index += 1
                except DCERPCSessionError as e:
                    if e.error_code == ERROR_NO_MORE_ITEMS:
                        break
                    else:
                        self.context.log.error(f"HostChecker.reg_query_value()->sub_key_values(): Received error code {e.error_code}")
                        return

        def get_value(subkey_handle, dwIndex=0):
            ans = rrp.hBaseRegEnumValue(dce=dce, hKey=subkey_handle, dwIndex=dwIndex)
            value_type = ans["lpType"]
            value_name = ans["lpValueNameOut"]
            value_data = ans["lpData"]

            # Do any conversion necessary depending on the registry value type
            if value_type in (REG_VALUE_TYPE_UNICODE_STRING, REG_VALUE_TYPE_UNICODE_STRING_WITH_ENV, REG_VALUE_TYPE_UNICODE_STRING_SEQUENCE):
                value_data = b"".join(value_data).decode("utf-16")
            else:
                value_data = b"".join(value_data)
                if value_type in (REG_VALUE_TYPE_32BIT_LE, REG_VALUE_TYPE_64BIT_LE):
                    value_data = int.from_bytes(value_data, "little")
                elif value_type == REG_VALUE_TYPE_32BIT_BE:
                    value_data = int.from_bytes(value_data, "big")

            return value_type, value_name[:-1], value_data

        try:
            root_key, subkey = keyName.split("\\", 1)
        except ValueError:
            self.context.log.error(f"HostChecker.reg_query_value(): Could not split keyname {keyName}")

        ans = self._open_root_key(dce, connection, root_key)
        if ans is None:
            return ans

        root_key_handle = ans["phKey"]
        try:
            ans = rrp.hBaseRegOpenKey(dce, root_key_handle, subkey)
        except DCERPCSessionError as e:
            if e.error_code == ERROR_FILE_NOT_FOUND:
                return e

        subkey_handle = ans["phkResult"]

        if valueName is None and all_value is False:
            return get_value(subkey_handle)[2]
        elif valueName is None and all_value is True:
            return subkey_values(subkey_handle)
        else:
            for _, name, data in subkey_values(subkey_handle):
                if name.upper() == valueName.upper():
                    return data
            return DCERPCSessionError(error_code=ERROR_OBJECT_NOT_FOUND)

    def get_service(self, service_name, connection):
        """Get the service status and configuration for specified service"""
        remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
        machine_name, _ = remoteOps.getMachineNameAndDomain()
        remoteOps._RemoteOperations__connectSvcCtl()
        dce = remoteOps._RemoteOperations__scmr
        scm_handle = scmr.hROpenSCManagerW(dce, machine_name)["lpScHandle"]
        service_handle = scmr.hROpenServiceW(dce, scm_handle, service_name)["lpServiceHandle"]
        service_config = scmr.hRQueryServiceConfigW(dce, service_handle)["lpServiceConfig"]
        service_status = scmr.hRQueryServiceStatus(dce, service_handle)["lpServiceStatus"]["dwCurrentState"]
        remoteOps.finish()

        return service_config, service_status

    def get_user_info(self, connection, rid=501):
        """Get user information for the user with the specified RID"""
        remote_ops = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
        machine_name, domain_name = remote_ops.getMachineNameAndDomain()

        try:
            remote_ops.connectSamr(machine_name)
        except samr.DCERPCSessionError:
            # If connecting to machine_name didn't work, it's probably because
            # we're dealing with a domain controller, so we need to use the
            # actual domain name instead of the machine name, because DCs don't
            # use the SAM
            remote_ops.connectSamr(domain_name)

        dce = remote_ops._RemoteOperations__samr
        domain_handle = remote_ops._RemoteOperations__domainHandle
        user_handle = samr.hSamrOpenUser(dce, domain_handle, userId=rid)["UserHandle"]
        user_info = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
        user_info = user_info["Buffer"]["All"]
        remote_ops.finish()
        return user_info

    def ls(self, smb, path="\\", share="C$"):
        file_listing = []
        try:
            file_listing = smb.conn.listPath(share, path)
        except SMBSessionError as e:
            if e.getErrorString()[0] not in ("STATUS_NO_SUCH_FILE", "STATUS_OBJECT_NAME_NOT_FOUND"):
                self.context.log.error(f"ls(): C:\\{path} {e.getErrorString()}")
        except Exception as e:
            self.context.log.error(f"ls(): C:\\{path} {e}\n")
        return file_listing


def le(reg_sz_string, number):
    return int(reg_sz_string[:-1]) <= number


def in_(obj, seq):
    return obj in seq


def startswith(string, start):
    return string.startswith(start)


def not_(boolean_operator):
    def wrapper(*args, **kwargs):
        return not boolean_operator(*args, **kwargs)

    wrapper.__name__ = f"not_{boolean_operator.__name__}"
    return wrapper
