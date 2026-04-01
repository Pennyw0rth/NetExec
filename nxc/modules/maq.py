import struct
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


def _sid_to_str(sid):
    try:
        revision = int(sid[0])
        sub_authorities = int(sid[1])
        identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
        if identifier_authority >= 2**32:
            identifier_authority = hex(identifier_authority)
        sub_authority = "-" + "-".join(
            [str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder="little")) for i in range(sub_authorities)]
        )
        return "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
    except Exception:
        return sid


def _owner_sid_from_sd(sd_bytes):
    """Extract the owner SID from a Windows security descriptor binary blob."""
    try:
        offset_owner = struct.unpack("<I", sd_bytes[4:8])[0]
        if offset_owner == 0 or offset_owner >= len(sd_bytes):
            return None
        return _sid_to_str(sd_bytes[offset_owner:])
    except Exception:
        return None


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
        USER    Username to check machine-join count for (default: authenticated user).
                Omit to show MAQ only; supply any value to also enumerate joined machines.
        """
        self.user = module_options.get("USER", None)

    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota")

        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        maq = int(entries[0]["ms-DS-MachineAccountQuota"])
        context.log.highlight(f"MachineAccountQuota: {maq}")

        if self.user is None:
            return

        target_user = self.user if self.user else connection.username
        if not target_user:
            context.log.fail("Could not determine target username.")
            return

        self._enum_user_machines(context, connection, target_user, maq)

    def _enum_user_machines(self, context, connection, username, maq):
        context.log.display(f"Resolving SID for user: {username}")

        user_resp = connection.search(f"(sAMAccountName={username})", ["objectSid"])
        user_entries = parse_result_attributes(user_resp)
        if not user_entries or "objectSid" not in user_entries[0]:
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
                creator_sid = _sid_to_str(raw_sid) if isinstance(raw_sid, bytes) else raw_sid
                matched = creator_sid == user_sid

            # Method 2: nTSecurityDescriptor owner — set for direct LDAP creation (addcomputer.py)
            if not matched:
                sd = comp.get("nTSecurityDescriptor")
                if sd is not None and isinstance(sd, bytes):
                    matched = _owner_sid_from_sd(sd) == user_sid

            if matched:
                user_computers.append(comp.get("name", "Unknown"))

        count = len(user_computers)
        remaining = maq - count

        context.log.highlight(f"Machines joined by '{username}': {count}/{maq} (remaining quota: {remaining})")
        if remaining <= 0:
            context.log.fail(f"'{username}' has reached the MachineAccountQuota — cannot join additional machines!")

        for name in user_computers:
            context.log.highlight(f"  Computer: {name}")
