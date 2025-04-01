from impacket.ldap import ldap, ldaptypes, ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPSearchError
from ldap3.protocol.microsoft import security_descriptor_control
from nxc.parsers.ldap_results import parse_result_attributes

SAM_USER_OBJECT = 0x30000000
SAM_MACHINE_ACCOUNT = 0x30000001
SAM_GROUP_OBJECT = 0x10000000
LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"


class NXCModule:
    """
    Implementation of the SCCM RECON-1 technique to find SCCM related objects in Active Directory.
    See:
    https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-1/recon-1_description.md
    https://github.com/garrettfoster13/sccmhunter

    Module by @NeffIsBack
    """

    name = "sccm"
    description = "Find a SCCM infrastructure in the Active Directory"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.sccm_site_servers = []     # List of dns host names of the SCCM site servers
        self.sccm_sites = {}            # List of SCCM sites with their management points (Sorted by site code)
        self.base_dn = ""
        self.recursive_resolve = False

        self.user_objects = []
        self.computer_objects = []
        self.group_objects = {}

    def options(self, context, module_options):
        """
        BASE_DN            The base domain name for the LDAP query
        REC_RESOLVE        Resolve members of groups recursively. Default: False
        """
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]
        if module_options and "REC_RESOLVE" in module_options:
            self.recursive_resolve = bool(module_options["REC_RESOLVE"])

    def on_login(self, context, connection):
        """On a successful LDAP login we perform a search for all PKI Enrollment Server or Certificate Templates Names."""
        self.context = context
        self.connection = connection
        self.base_dn = connection.ldap_connection._baseDN if not self.base_dn else self.base_dn
        self.sc = ldap.SimplePagedResultsControl()

        # Basic SCCM enumeration
        try:
            # Search for SCCM root object
            search_filter = f"(distinguishedName=CN=System Management,CN=System,{self.base_dn})"
            controls = security_descriptor_control(sdflags=0x04)
            context.log.display(f"Looking for the SCCM container with filter: '{search_filter}'")
            result = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=["nTSecurityDescriptor"],
                sizeLimit=0,
                searchControls=controls,
                searchBase=self.base_dn,
            )

            # There should be only one result
            for item in result:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry):
                    self.context.log.success(f"Found SCCM object: {item[0]}")
                    self.get_site_servers(item)
                    self.get_sites()
                    self.get_management_points()

                    # Print results
                    self.context.log.success(f"Found {len(self.sccm_site_servers)} Site Servers:")
                    for site in self.sccm_site_servers:
                        ip = self.connection.resolver(site)
                        self.context.log.highlight(f"{site} - {ip['host'] if ip else 'unknown'}")
                    self.context.log.success(f"Found {len(self.sccm_sites)} SCCM Sites:")
                    for site in self.sccm_sites:
                        self.context.log.highlight(f"{self.sccm_sites[site]['cn']}")
                        self.context.log.highlight(f"  Site Code: {site.rjust(14)}")
                        self.context.log.highlight(f"  Assignment Site Code: {self.sccm_sites[site]['AssignmentSiteCode'].rjust(3)}")

                        # If there aren't Management Points, it's a Central Administration Site
                        if self.sccm_sites[site]["ManagementPoints"]:
                            self.context.log.highlight(f"  CAS: {' ':<17}{False}")
                            self.context.log.highlight("  Management Points:")
                            for mp in self.sccm_sites[site]["ManagementPoints"]:
                                self.context.log.highlight(f"    CN:{' ':<12}{mp['cn']}")
                                self.context.log.highlight(f"    DNS Hostname:{' ':<2}{mp['dNSHostName']}")
                                self.context.log.highlight(f"    IP Address:{' ':<4}{mp['IPAddress']}")
                                self.context.log.highlight(f"    Default MP:{' ':<4}{mp['mSSMSDefaultMP']}")
                        else:
                            self.context.log.highlight(f"  CAS: {' ':<17}{True}")
                    self.context.log.highlight("")
        except LDAPSearchError as e:
            context.log.fail(f"Got unexpected exception: {e}")

        # SCCM named objects enumeration
        self.get_sccm_named_objects(context, connection)
        if self.user_objects:
            context.log.success(f"Found {len(self.user_objects)} SCCM related user objects:")
            for user in self.user_objects:
                context.log.highlight(user)
        if self.computer_objects:
            context.log.success(f"Found {len(self.computer_objects)} SCCM related computer objects:")
            for computer in self.computer_objects:
                context.log.highlight(computer)
        if self.group_objects:
            context.log.success(f"Found {len(self.group_objects)} SCCM related group objects:")
            for group in self.group_objects:
                context.log.highlight(self.group_objects[group]["sAMAccountName"])
                for child in self.group_objects[group]["children"]:
                    if int(child["sAMAccountType"]) == SAM_USER_OBJECT:
                        context.log.highlight(f"  {child['sAMAccountName']} -> User")
                    elif int(child["sAMAccountType"]) == SAM_MACHINE_ACCOUNT:
                        context.log.highlight(f"  {child['sAMAccountName']} -> Computer")
                    elif int(child["sAMAccountType"]) == SAM_GROUP_OBJECT:
                        context.log.highlight(f"  {child['sAMAccountName']} -> Group")

    def get_sccm_named_objects(self, context, connection):
        """Enumerate users/groups/computers with "SCCM" in their name"""
        # hippity hoppity your code is now my property, filter stolen from the awesome sccmhunter repository
        # https://github.com/garrettfoster13/sccmhunter
        try:
            yoinkers = "(|(samaccountname=*sccm*)(samaccountname=*mecm*)(description=*sccm*)(description=*mecm*)(name=*sccm*)(name=*mecm*))"
            context.log.display("Searching for SCCM related objects")
            result = connection.ldap_connection.search(
                searchFilter=yoinkers,
                searchBase=self.base_dn,
                attributes=["sAMAccountName", "distinguishedName", "sAMAccountType"],
            )

            result = parse_result_attributes(result)
            for res in result:
                if "sAMAccountType" in res and int(res["sAMAccountType"]) == SAM_USER_OBJECT:
                    self.user_objects.append(res["sAMAccountName"])
                elif "sAMAccountType" in res and int(res["sAMAccountType"]) == SAM_MACHINE_ACCOUNT:
                    self.computer_objects.append(res["sAMAccountName"])
                elif "sAMAccountType" in res and int(res["sAMAccountType"]) == SAM_GROUP_OBJECT:
                    self.group_objects[res["distinguishedName"]] = {
                        "sAMAccountName": res["sAMAccountName"],
                        "children": [],
                    }
                    if self.recursive_resolve:
                        self.resolve_recursive(res["distinguishedName"])

        except LDAPSearchError as e:
            context.log.fail(f"Got unexpected exception: {e}")

    def resolve_recursive(self, dn):
        """Recursively resolve members of a group."""
        try:
            self.context.log.debug(f"Resolving group members recursively for {dn}")
            # Somehow BaseDN is not working together with the LDAP_MATCHING_RULE_IN_CHAIN
            result = self.connection.ldap_connection.search(
                searchFilter=f"(memberOf:{LDAP_MATCHING_RULE_IN_CHAIN}:={dn})",
                attributes=["sAMAccountName", "distinguishedName", "sAMAccountType"],
            )

            result = parse_result_attributes(result)
            for res in result:
                self.group_objects[dn]["children"].append({
                    "sAMAccountName": res["sAMAccountName"],
                    "distinguishedName": res["distinguishedName"],
                    "sAMAccountType": res["sAMAccountType"],
                })

        except LDAPSearchError as e:
            self.context.log.error(f"Error resolving group members: {e}")

    def get_management_points(self):
        """Searches for all SCCM management points in the Active Directory and maps them to their SCCM site via the site code."""
        try:
            response = self.connection.ldap_connection.search(
                searchBase=self.base_dn,
                searchFilter="(objectClass=mSSMSManagementPoint)",
                attributes=["cn", "dNSHostName", "mSSMSDefaultMP", "mSSMSSiteCode"],
            )

            response_parsed = parse_result_attributes(response)

            for mp in response_parsed:
                ip = self.connection.resolver(mp["dNSHostName"])
                self.sccm_sites[mp["mSSMSSiteCode"]]["ManagementPoints"].append({
                    "cn": mp["cn"],
                    "dNSHostName": mp["dNSHostName"],
                    "IPAddress": ip["host"] if ip else "-",
                    "mSSMSDefaultMP": mp["mSSMSDefaultMP"],
                })

        except LDAPSearchError as e:
            self.context.log.error(f"Error searching for management points: {e}")

    def get_sites(self):
        """Searches for all SCCM sites in the Active Directory, sorted by site code."""
        try:
            response = self.connection.ldap_connection.search(
                searchBase=self.base_dn,
                searchFilter="(objectClass=mSSMSSite)",
                attributes=["cn", "mSSMSSiteCode", "mSSMSAssignmentSiteCode"],
            )

            response_parsed = parse_result_attributes(response)

            for site in response_parsed:
                self.sccm_sites[site["mSSMSSiteCode"]] = {
                    "cn": site["cn"],
                    "AssignmentSiteCode": site["mSSMSAssignmentSiteCode"],
                    "ManagementPoints": []
                }

        except LDAPSearchError as e:
            self.context.log.error(f"Error searching for sites: {e}")

    def get_site_servers(self, item):
        """Extracts the site servers from the root SCCM object."""
        raw_sec_descriptor = str(item[1][0][1][0]).encode("latin-1")
        principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sec_descriptor)
        self.parse_dacl(principal_security_descriptor["Dacl"])
        self.sccm_site_servers = set(self.sccm_site_servers)    # Make list unique

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
            result = self.connection.ldap_connection.search(
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
                self.sccm_site_servers.append(parsed_result["dNSHostName"])
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
        result = self.connection.ldap_connection.search(
            searchBase=self.base_dn,
            searchFilter=f"(distinguishedName={dn})",
            attributes=["sAMAccountName", "objectSid"],
        )

        # Extract the SID of the object
        sid_raw = bytes(result[0][1][0][1].components[0])
        return ldaptypes.LDAP_SID(data=sid_raw).formatCanonical()
