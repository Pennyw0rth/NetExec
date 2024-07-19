import json
import re
from impacket.ldap import ldap, ldaptypes, ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from nxc.parsers.ldap_results import parse_result_attributes

SAM_MACHINE_ACCOUNT = 0x30000001
SAM_GROUP_OBJECT = 0x10000000


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
        self.sccm_sites = []
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
                    self.context.log.highlight(f"Found sccm_sites: {self.sccm_sites}")

        except LDAPSearchError as e:
            context.log.fail(f"Obtained unexpected exception: {e}")

    def parse_dacl(self, dacl):
        """Parses a DACL and extracts the dns host names with full control over the SCCM object."""
        self.context.log.debug("Parsing DACL")
        for ace in dacl["Data"]:
            self.parse_ace(ace)

    def parse_ace(self, ace):
        """Parses an ACE and resolves the SID if the SID of the ACE has full control."""
        if ace["TypeName"] in ["ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"]:
            ace = ace["Ace"]
            sid = ace["Sid"].formatCanonical()
            mask = ace["Mask"]
            fullcontrol = 0xf01ff
            if mask.hasPriv(fullcontrol):
                self.resolve_SID(sid)

    def resolve_SID(self, sid):
        """Tries to resolve a SID and add the dNSHostName to the sccm site list."""
        try:
            self.context.log.debug(f"Resolving SID: {sid}")
            result = self.connection.ldapConnection.search(
                searchBase=self.base_dn,
                searchFilter=f"(objectSid={sid})",
                attributes=["sAMAccountName", "sAMAccountType", "member", "dNSHostName"],
            )
            parsed_result = parse_result_attributes(result)
            if not parsed_result:
                return None
            else:
                parsed_result = parsed_result[0]    # We only have one result as we always query a single SID

            if int(parsed_result["sAMAccountType"]) == SAM_MACHINE_ACCOUNT:
                self.context.log.debug(f"Found object with full control over SCCM object. SID: {sid}, dns_hostname: {parsed_result['dNSHostName']}")
                self.sccm_sites.append(parsed_result["dNSHostName"])
            elif int(parsed_result["sAMAccountType"]) == SAM_GROUP_OBJECT:
                if isinstance(parsed_result["member"], list):
                    for member in parsed_result["member"]:
                        member_sid = self.dn_to_sid(member)
                        if member_sid:
                            self.resolve_SID(member_sid)
                else:   # Group has only one member
                    member_sid = self.dn_to_sid(parsed_result["member"])
                    if member_sid:
                        self.resolve_SID(member_sid)

        except Exception as e:
            self.context.log.debug(f"SID not found in LDAP: {sid}, {e}")
            return ""

    def dn_to_sid(self, dn) -> str:
        """Tries to resolve a DN to a SID."""
        try:
            result = self.connection.ldapConnection.search(
                searchBase=self.base_dn,
                searchFilter=f"(distinguishedName={dn})",
                attributes=["sAMAccountName", "objectSid"],
            )
            parsed_result = parse_result_attributes(result)[0]
            self.context.log.highlight(f"Found object for DN {dn}: {parsed_result[0]}")
            if not parsed_result:
                return ""
            else:
                parsed_result = parsed_result[0]
            return parsed_result["objectSid"]
        except Exception as e:
            self.context.log.debug(f"DN not found in LDAP: {dn}, {e}")
            return ""
