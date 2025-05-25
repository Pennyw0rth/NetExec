from impacket.ldap import ldaptypes
from nxc.parsers.ldap_results import parse_result_attributes
from ldap3.protocol.microsoft import security_descriptor_control

RELEVANT_OBJECT_TYPES = {
    "00000000-0000-0000-0000-000000000000": "All Objects",
    "0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount",
}

EXCLUDED_SIDS_SUFFIXES = ["-512", "-519"]  # Domain Admins, Enterprise Admins
EXCLUDED_SIDS = ["S-1-5-32-544", "S-1-5-18"]  # Builtin Administrators, Local SYSTEM

# Define all access rights
ACCESS_RIGHTS = {
    # Generic Rights
    "GenericRead": 0x80000000,  # ADS_RIGHT_GENERIC_READ
    "GenericWrite": 0x40000000,  # ADS_RIGHT_GENERIC_WRITE
    "GenericExecute": 0x20000000,  # ADS_RIGHT_GENERIC_EXECUTE
    "GenericAll": 0x10000000,  # ADS_RIGHT_GENERIC_ALL

    # Maximum Allowed access type
    "MaximumAllowed": 0x02000000,

    # Access System Acl access type
    "AccessSystemSecurity": 0x01000000,  # ADS_RIGHT_ACCESS_SYSTEM_SECURITY

    # Standard access types
    "Synchronize": 0x00100000,  # ADS_RIGHT_SYNCHRONIZE
    "WriteOwner": 0x00080000,  # ADS_RIGHT_WRITE_OWNER
    "WriteDACL": 0x00040000,  # ADS_RIGHT_WRITE_DAC
    "ReadControl": 0x00020000,  # ADS_RIGHT_READ_CONTROL
    "Delete": 0x00010000,  # ADS_RIGHT_DELETE

    # Specific rights
    "AllExtendedRights": 0x00000100,  # ADS_RIGHT_DS_CONTROL_ACCESS
    "ListObject": 0x00000080,  # ADS_RIGHT_DS_LIST_OBJECT
    "DeleteTree": 0x00000040,  # ADS_RIGHT_DS_DELETE_TREE
    "WriteProperties": 0x00000020,  # ADS_RIGHT_DS_WRITE_PROP
    "ReadProperties": 0x00000010,  # ADS_RIGHT_DS_READ_PROP
    "Self": 0x00000008,  # ADS_RIGHT_DS_SELF
    "ListChildObjects": 0x00000004,  # ADS_RIGHT_ACTRL_DS_LIST
    "DeleteChild": 0x00000002,  # ADS_RIGHT_DS_DELETE_CHILD
    "CreateChild": 0x00000001,  # ADS_RIGHT_DS_CREATE_CHILD
}

# Define which rights are considered relevant for potential abuse
RELEVANT_RIGHTS = {
    "GenericAll": ACCESS_RIGHTS["GenericAll"],
    "GenericWrite": ACCESS_RIGHTS["GenericWrite"],
    "WriteOwner": ACCESS_RIGHTS["WriteOwner"],
    "WriteDACL": ACCESS_RIGHTS["WriteDACL"],
    "CreateChild": ACCESS_RIGHTS["CreateChild"],
    "WriteProperties": ACCESS_RIGHTS["WriteProperties"],
    "AllExtendedRights": ACCESS_RIGHTS["AllExtendedRights"]
}

FUNCTIONAL_LEVELS = {
    "Windows 2000": 0,
    "Windows Server 2003": 1,
    "Windows Server 2003 R2": 2,
    "Windows Server 2008": 3,
    "Windows Server 2008 R2": 4,
    "Windows Server 2012": 5,
    "Windows Server 2012 R2": 6,
    "Windows Server 2016": 7,
    "Windows Server 2019": 8,
    "Windows Server 2022": 9,
    "Windows Server 2025": 10,
}


class NXCModule:
    """
    -------
    Module by @mpgn based on https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#credentials
    and https://raw.githubusercontent.com/akamai/BadSuccessor/refs/heads/main/Get-BadSuccessorOUPermissions.ps1
    """

    name = "badsuccessor"
    description = "Check if vulnerable to bad successor attack (DMSA)"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options available"""

    def is_excluded_sid(self, sid, domain_sid):
        if sid in EXCLUDED_SIDS:
            return True
        return any(sid.startswith(domain_sid) and sid.endswith(suffix) for suffix in EXCLUDED_SIDS_SUFFIXES)

    def get_domain_sid(self, ldap_session, base_dn):
        """Retrieve the domain SID from the domain object in LDAP"""
        r = ldap_session.search(
            searchBase=base_dn,
            searchFilter="(objectClass=domain)",
            attributes=["objectSid"]
        )
        parsed = parse_result_attributes(r)
        if parsed and "objectSid" in parsed[0]:
            return parsed[0]["objectSid"]

    def find_bad_successor_ous(self, ldap_session, entries, base_dn):
        domain_sid = self.get_domain_sid(ldap_session, base_dn)
        results = {}
        parsed = parse_result_attributes(entries)
        for entry in parsed:
            dn = entry["distinguishedName"]
            sd_data = entry["nTSecurityDescriptor"]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)

            for ace in sd["Dacl"]["Data"]:
                if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue

                has_relevant_right = False
                mask = int(ace["Ace"]["Mask"]["Mask"])
                for right_value in RELEVANT_RIGHTS.values():
                    if mask & right_value:
                        has_relevant_right = True
                        break

                if not has_relevant_right:
                    continue  # Skip this ACE if it doesn't have any relevant rights

                object_type = getattr(ace, "ObjectType", None)
                if object_type:
                    object_guid = ldaptypes.bin_to_string(object_type).lower()
                    if object_guid not in RELEVANT_OBJECT_TYPES:
                        continue

                sid = ace["Ace"]["Sid"].formatCanonical()
                if self.is_excluded_sid(sid, domain_sid):
                    continue

                results.setdefault(sid, []).append(dn)

            if hasattr(sd, "OwnerSid"):
                owner_sid = str(sd["OwnerSid"])
                if not self.is_excluded_sid(owner_sid, domain_sid):
                    results.setdefault(owner_sid, []).append(dn)
        return results

    def resolve_sid_to_name(self, ldap_session, sid, base_dn):
        """
        Resolves a SID to a samAccountName using LDAP

        Args:
        ----
            ldap_session: The LDAP connection
            sid: The SID to resolve
            base_dn: The base DN for the LDAP search

        Returns:
        -------
            str: The samAccountName if found, otherwise the original SID
        """
        try:
            search_filter = f"(objectSid={sid})"
            response = ldap_session.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["sAMAccountName"]
            )

            parsed = parse_result_attributes(response)
            if parsed and "sAMAccountName" in parsed[0]:
                return parsed[0]["sAMAccountName"]
            return sid
        except Exception:
            return sid

    def on_login(self, context, connection):
        # Check for a domain controller with Windows Server 2025
        resp = connection.ldap_connection.search(
            searchBase=connection.ldap_connection._baseDN,
            searchFilter="(&(objectCategory=computer)(primaryGroupId=516))",
            attributes=["operatingSystem", "dNSHostName"]
        )
        parsed_resp = parse_result_attributes(resp)

        for dc in parsed_resp:
            if "2025" in dc["operatingSystem"]:
                out = connection.resolver(dc["dNSHostName"])
                dc_ip = out[0] if out else "Unknown IP"
                context.log.success(f"Found domain controller with operating system Windows Server 2025: {dc_ip} ({dc['dNSHostName']})")
            else:
                context.log.fail("No domain controller with operating system Windows Server 2025 found, attack not possible. Enumerate dMSA objects anyway.")

        # Enumerate dMSA objects
        controls = security_descriptor_control(sdflags=0x07)  # OWNER_SECURITY_INFORMATION
        resp = connection.ldap_connection.search(
            searchBase=connection.ldap_connection._baseDN,
            searchFilter="(objectClass=organizationalUnit)",
            attributes=["distinguishedName", "nTSecurityDescriptor"],
            searchControls=controls)  # Fixed parameter name

        context.log.debug(f"Found {len(resp)} entries")

        results = self.find_bad_successor_ous(connection.ldap_connection, resp, connection.ldap_connection._baseDN)

        if results:
            context.log.success(f"Found {len(results)} results")
        else:
            context.log.highlight("No account found")

        for sid, ous in results.items():
            samaccountname = self.resolve_sid_to_name(
                connection.ldap_connection,
                sid,
                connection.ldap_connection._baseDN
            )

            for ou in ous:
                if sid == samaccountname:
                    context.log.highlight(f"{sid}, {ou}")
                else:
                    context.log.highlight(f"{samaccountname} ({sid}), {ou}")
