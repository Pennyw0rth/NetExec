from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldaptypes
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes, sid_to_str


class NXCModule:
    """
    Module by Shutdown and Podalirius
    Modified by @azoxlpf to handle null session errors and avoid IndexError when no LDAP results are returned.

    Initial module:
      https://github.com/ShutdownRepo/CrackMapExec-MachineAccountQuota

    Authors:
      Shutdown: @_nwodtuhs
      Podalirius: @podalirius_
    """

    name = "maq"
    description = "Retrieves the MachineAccountQuota domain-level attribute"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        USER    Username to enumerate machine-join count for (optional)
        """
        self.user = module_options.get("USER", None)

    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota")

        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        context.log.highlight(f"MachineAccountQuota: {entries[0]['ms-DS-MachineAccountQuota']}")

        if self.user:
            self._enum_user_machines(context, connection, self.user, int(entries[0]["ms-DS-MachineAccountQuota"]))

    def _enum_user_machines(self, context, connection, username, maq):
        context.log.display(f"Resolving SID for user: {username}")

        user_resp = connection.search(f"(sAMAccountName={username})", ["objectSid"])
        user_entries = parse_result_attributes(user_resp)
        if not user_entries:
            context.log.fail(f"Could not resolve SID for user: {username}")
            return

        user_sid = user_entries[0]["objectSid"]
        context.log.debug(f"User SID: {user_sid}")

        context.log.display("Querying computers...")

        # SD flags control: OWNER_SECURITY_INFORMATION = 1
        # Needed to retrieve nTSecurityDescriptor owner for LDAP-created accounts (addcomputer.py)
        sd_control = ldapasn1_impacket.Control()
        sd_control["controlType"] = "1.2.840.113556.1.4.801"
        sd_control["criticality"] = False
        sd_control["controlValue"] = b"\x30\x03\x02\x01\x01"

        paged_control = ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)

        comp_resp = connection.ldap_connection.search(
            searchBase=connection.baseDN,
            searchFilter="(objectCategory=computer)",
            attributes=["name", "ms-DS-CreatorSID", "nTSecurityDescriptor"],
            sizeLimit=0,
            searchControls=[paged_control, sd_control],
        )
        computers = parse_result_attributes(comp_resp)

        user_computers = []
        for comp in computers:
            matched = False

            # Method 1: ms-DS-CreatorSID — set by DC for SAMR domain joins
            raw_sid = comp.get("ms-DS-CreatorSID")
            if raw_sid is not None:
                matched = sid_to_str(raw_sid) == user_sid

            # Method 2: nTSecurityDescriptor owner — set for direct LDAP creation (addcomputer.py)
            if not matched:
                raw_sd = comp.get("nTSecurityDescriptor")
                if raw_sd is not None:
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
                    sd.fromString(raw_sd)
                    matched = sd["OwnerSid"].formatCanonical() == user_sid

            if matched:
                user_computers.append(comp.get("name", "Unknown"))

        count = len(user_computers)
        remaining = maq - count

        context.log.highlight(f"Machines joined by '{username}': {count}/{maq} (remaining quota: {remaining})")
        if remaining <= 0:
            context.log.fail(f"'{username}' has reached the MachineAccountQuota — cannot join additional machines!")

        for name in user_computers:
            context.log.highlight(f"  Computer: {name}")
