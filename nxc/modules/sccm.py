import json
import re
from impacket.ldap import ldap, ldaptypes, ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from nxc.parsers.ldap_results import parse_result_attributes

SAM_MACHINE_ACCOUNT = 0x30000001
SAM_GROUP_OBJECT = 0x10000000

# Universal SIDs
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


class NXCModule:
    """
    Implementation of the SCCM RECON-1 technique to find SCCM related objects in Active Directory.
    See: https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-1/recon-1_description.md

    Module by @NeffIsBack
    """

    name = "sccm"
    description = "Find a SCCM infrastructure in the Active Directory"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.sAMAccountNames = []
        self.base_dn = ""

    def options(self, context, module_options):
        """BASE_DN            The base domain name for the LDAP query"""
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]

    def on_login(self, context, connection):
        """On a successful LDAP login we perform a search for all PKI Enrollment Server or Certificate Templates Names."""
        self.context = context
        self.connection = connection
        self.base_dn = connection.ldapConnection._baseDN if not self.base_dn else self.base_dn
        self.sc = ldap.SimplePagedResultsControl()

        search_filter = f"(distinguishedName=CN=System Management,CN=System,{self.base_dn})"
        controls = security_descriptor_control(sdflags=0x04)
        context.log.display(f"Starting LDAP search with search filter '{search_filter}'")

        try:

            result = connection.ldapConnection.search(
                searchFilter=search_filter,
                attributes=["nTSecurityDescriptor"],
                sizeLimit=0,
                searchControls=controls,
                searchBase=self.base_dn,
            )
            for item in result:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry):
                    raw_sec_descriptor = str(item[1][0][1][0]).encode("latin-1")
                    principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sec_descriptor)
                    context.log.highlight(f"Found SCCM object: {item[0]}")
                    self.parse_dacl(principal_security_descriptor["Dacl"])
                    self.context.log.highlight(f"Found sAMAccountNames: {self.sAMAccountNames}")


        except LDAPSearchError as e:
            context.log.fail(f"Obtained unexpected exception: {e}")

    def parse_dacl(self, dacl):
        """Parses a DACL and extracts the sAMAccountNames with full control."""
        parsed_dacl = []
        self.context.log.debug("Parsing DACL")
        for ace in dacl["Data"]:
            parsed_ace = self.parse_ace(ace)
            parsed_dacl.append(parsed_ace)

    def parse_ace(self, ace):
        """Parses an ACE and appends the sAMAccountName to the list of known sAMAccountNames if the SID of the ACE has full control."""
        if ace["TypeName"] in ["ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"]:
            ace = ace["Ace"]
            sid = ace["Sid"].formatCanonical()
            mask = ace["Mask"]
            fullcontrol = 0xf01ff
            if mask.hasPriv(fullcontrol):
                self.context.log.debug(f"Full control for {sid}")
                print(f"SID: {sid}, sAMAccountName: {self.resolveSID(sid)}")
                self.sAMAccountNames.append(str(self.resolveSID(sid)))

    def resolveSID(self, sid) -> str:
        """Tries to resolve a SID and returns the corresponding sAMAccountName if found."""
        try:
            result = self.connection.ldapConnection.search(
                searchBase=self.base_dn,
                searchFilter=f"(objectSid={sid})",
                attributes=["sAMAccountName", "sAMAccountType", "member", "dNSHostName"],
            )
            parsed_result = parse_result_attributes(result)
            if not parsed_result:
                return ""
            else:
                parsed_result = parsed_result[0]

            if int(parsed_result["sAMAccountType"]) == SAM_MACHINE_ACCOUNT:
                print(f"{parsed_result['sAMAccountName']} IS MACHINE ACCOUNT")
                return parsed_result["sAMAccountName"]
            elif int(parsed_result["sAMAccountType"]) == SAM_GROUP_OBJECT:
                print(f"{parsed_result['sAMAccountName']} IS GROUP OBJECT")
                print(parsed_result["member"])
            return ""


        except Exception as e:
            print(e.with_traceback())
            self.context.log.debug(f"SID not found in LDAP: {sid}, {e}")
            return ""
