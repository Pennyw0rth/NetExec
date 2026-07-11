import re
from io import BytesIO
from impacket.ldap import ldap as ldap_impacket
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Module to retrieve privileges assigned via Group Policy Objects (GPOs) by parsing GptTmpl.inf files
    and resolving SIDs using LDAP.
    """

    name = "gpp_privileges"
    description = "Extracts privileges assigned via GPOs and resolves SIDs via LDAP."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    WELL_KNOWN_SIDS = {
        "S-1-0": "Null Authority",
        "S-1-0-0": "Nobody",
        "S-1-1": "World Authority",
        "S-1-1-0": "Everyone",
        "S-1-2": "Local Authority",
        "S-1-2-0": "Local",
        "S-1-2-1": "Console Logon",
        "S-1-3": "Creator Authority",
        "S-1-3-0": "Creator Owner",
        "S-1-3-1": "Creator Group",
        "S-1-3-2": "Creator Owner Server",
        "S-1-3-3": "Creator Group Server",
        "S-1-3-4": "Owner Rights",
        "S-1-5-80-0": "All Services",
        "S-1-4": "Non-unique Authority",
        "S-1-5": "NT Authority",
        "S-1-5-1": "Dialup",
        "S-1-5-2": "Network",
        "S-1-5-3": "Batch",
        "S-1-5-4": "Interactive",
        "S-1-5-6": "Service",
        "S-1-5-7": "Anonymous",
        "S-1-5-8": "Proxy",
        "S-1-5-9": "Enterprise Domain Controllers",
        "S-1-5-10": "Principal Self",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-12": "Restricted Code",
        "S-1-5-13": "Terminal Server Users",
        "S-1-5-14": "Remote Interactive Logon",
        "S-1-5-15": "This Organization",
        "S-1-5-17": "This Organization",
        "S-1-5-18": "Local System",
        "S-1-5-19": "NT Authority",
        "S-1-5-20": "NT Authority",
        "S-1-5-32-544": "Administrators",
        "S-1-5-32-545": "Users",
        "S-1-5-32-546": "Guests",
        "S-1-5-32-547": "Power Users",
        "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators",
        "S-1-5-32-552": "Replicators",
        "S-1-5-64-10": "NTLM Authentication",
        "S-1-5-64-14": "SChannel Authentication",
        "S-1-5-64-21": "Digest Authority",
        "S-1-5-80": "NT Service",
        "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
        "S-1-16-0": "Untrusted Mandatory Level",
        "S-1-16-4096": "Low Mandatory Level",
        "S-1-16-8192": "Medium Mandatory Level",
        "S-1-16-8448": "Medium Plus Mandatory Level",
        "S-1-16-12288": "High Mandatory Level",
        "S-1-16-16384": "System Mandatory Level",
        "S-1-16-20480": "Protected Process Mandatory Level",
        "S-1-16-28672": "Secure Process Mandatory Level",
        "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
        "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
        "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
        "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
        "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
        "S-1-5-32-559": "BUILTIN\\Performance Log Users",
        "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
        "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
        "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
        "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
        "S-1-5-32-573": "BUILTIN\\Event Log Readers",
        "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
        "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
        "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
        "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
        "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
        "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
        "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    }

    def options(self, context, module_options):
        """NO_LDAP      If set to True, disables LDAP queries for resolving SIDs."""
        self.no_ldap = module_options.get("NO_LDAP", False)

    def on_login(self, context, connection):
        self.context = context
        try:
            connection.conn.listPath("SYSVOL", "*")
        except Exception as e:
            self.context.log.fail(f"Failed to list shares: {e}")
            return

        self.context.log.display("Searching for GptTmpl.inf files")
        paths = connection.spider("SYSVOL", pattern=["GptTmpl.inf"])

        if not paths:
            self.context.log.warning("No GptTmpl.inf files found in SYSVOL.")
            return

        for path in paths:
            if "6AC1786C-016F-11D2-945F-00C04fB984F9" in path:  # Default Domain Policy
                self.context.log.success(f"Found Default Domain Policy GptTmpl.inf: {path}")
            else:
                self.context.log.info(f"Found GptTmpl.inf: {path}")

            buf = BytesIO()
            connection.conn.getFile("SYSVOL", path, buf.write)

            try:
                content = buf.getvalue().decode("utf-16le")
            except UnicodeDecodeError as e:
                self.context.log.error(f"Failed to decode {path} as UTF-16LE: {e}")
                continue

            privileges = self.extract_privileges(content)
            if privileges:
                ldap_connection = None
                if not self.no_ldap:
                    ldap_connection = self.initialize_ldap_connection(connection)

                self.context.log.success(f"Privileges extracted from {path}:")
                for privilege, sids in privileges.items():
                    resolved_sids = [self.resolve_sid(sid, ldap_connection) for sid in sids]
                    self.context.log.highlight(f"{privilege}: {', '.join(resolved_sids)}")

                if ldap_connection:
                    ldap_connection.close()

    def extract_privileges(self, content):
        """Parses the content of GptTmpl.inf to extract privilege rights."""
        privileges = {}
        in_priv_section = False

        for line in content.splitlines():
            if line.strip() == "[Privilege Rights]":
                in_priv_section = True
                continue
            if in_priv_section and line.strip() == "":
                break
            if in_priv_section:
                match = re.match(r"^(.*?)\s*=\s*(.*)$", line)
                if match:
                    privilege, sids = match.groups()
                    privileges[privilege] = [sid.strip("*") for sid in sids.split(",")]

        return privileges

    def initialize_ldap_connection(self, connection):
        """
        Initializes an LDAP connection using impacket with LDAPS first, then falls back to plaintext LDAP if LDAPS fails.
        Attempts to retrieve the base DN from the Root DSE or derive it from the domain name.
        """
        ldap_connection = None
        try:
            ldap_connection = ldap_impacket.LDAPConnection(url=f"ldap://{connection.remoteName}", dstIp=connection.host)
            if connection.kerberos:
                ldap_connection.kerberosLogin(
                    connection.username,
                    connection.password or "",
                    connection.domain,
                    connection.lmhash,
                    connection.nthash,
                    connection.aesKey or "",
                    kdcHost=connection.kdcHost,
                    useCache=bool(connection.use_kcache),
                )
            else:
                ldap_connection.login(
                    user=connection.username,
                    password=connection.password or "",
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                )
            self.context.log.success("Connected to LDAP.")
        except Exception as e:
            self.context.log.fail(f"LDAP connection failed: {e}")
            return None
        return ldap_connection

    def resolve_sid(self, sid, ldap_connection):
        """Resolves a SID to a human-readable name using well-known mappings or LDAP queries."""
        if sid in self.WELL_KNOWN_SIDS:
            return self.WELL_KNOWN_SIDS[sid]

        if ldap_connection:
            try:
                resp = ldap_connection.search(
                    searchFilter=f"(objectSid={sid})",
                    attributes=["sAMAccountName"],
                )
                parsed_result = parse_result_attributes(resp)

                if parsed_result and "sAMAccountName" in parsed_result[0]:
                    return f"{parsed_result[0]['sAMAccountName']}"
                else:
                    self.context.log.warning(f"SID {sid} not found in LDAP. Returning raw SID.")

            except ldap_impacket.LDAPSearchError:
                self.context.log.warning(f"SID {sid} not found in LDAP. Returning raw SID.")
            except ldap_impacket.LDAPFilterSyntaxError:
                self.context.log.warning(f"Invalid LDAP filter syntax for SID {sid}. Returning raw SID.")
            except Exception as e:
                self.context.log.error(f"Failed while resolving SID {sid} via LDAP: {e}")
        else:
            self.context.log.warning(f"LDAP connection not established. Returning raw SID: {sid}")

        return sid
