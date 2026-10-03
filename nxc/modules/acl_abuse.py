from impacket.ldap.ldapasn1 import SDFlagsControl
from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import SearchResultEntry
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
import json
import uuid

ACCESS_ALLOWED_ACE = 0x00
ACCESS_ALLOWED_OBJECT_ACE = 0x05

INTERESTING_RIGHTS = {
    0x00040000: "WriteDACL",
    0x000F01FF: "GenericAll",
    0x00080000: "WriteOwner",
    0x00000020: "WriteProperty",
}

EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
}

PROPERTY_GUIDS = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
}

ATTACK_SUGGESTIONS = {
    "GenericAll":                             "Full object control — reset password, add to group, write SPN, set shadow credentials",
    "WriteDACL":                              "Modify DACL to grant yourself GenericAll, then escalate",
    "WriteOwner":                             "Take ownership of object, then modify DACL",
    "ForceChangePassword":                    "Reset target password without knowing current: net rpc password <user>",
    "WriteProperty (member)":                 "Add yourself or another principal to this group",
    "WriteProperty (servicePrincipalName)":   "Set SPN then Kerberoast the account",
    "WriteProperty (msDS-KeyCredentialLink)": "Shadow credentials attack — obtain TGT + NTLM hash via PKINIT",
    "DS-Replication-Get-Changes-All":         "DCSync attack — dump all domain hashes with secretsdump",
    "DS-Replication-Get-Changes":             "Partial replication rights — pair with Get-Changes-All for DCSync",
}


class NXCModule:
    name = "acl_abuse"
    description = "Map ACL abuse chains (WriteDACL, GenericAll, GenericWrite, ForceChangePassword)"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        TARGET_USER     SamAccountName to check outbound rights FROM (default: current auth user)
        TARGET_GROUP    Also check rights from members of this group (optional)
        SHOW_ALL        Show all interesting ACEs, not just paths to privileged objects (default: False)
        OUTPUT_FILE     Write findings as JSON to this path (optional)
        """
        self.target_user = module_options.get("TARGET_USER", "")
        self.target_group = module_options.get("TARGET_GROUP", "")
        self.show_all = module_options.get("SHOW_ALL", "false").lower() == "true"
        self.output_file = module_options.get("OUTPUT_FILE", "")
        self.findings = []

    def on_login(self, context, connection):
        self.context = context
        self.conn = connection
        self.base_dn = connection.baseDN

        principal_sids = self._resolve_principal_sids()
        if not principal_sids:
            context.log.fail("Could not resolve target principal — check TARGET_USER or auth credentials")
            return

        context.log.display(f"Resolved {len(principal_sids)} principal SID(s), enumerating ACEs...")

        objects = self._get_ad_objects()
        if not objects:
            context.log.fail("No AD objects returned — check permissions")
            return

        context.log.display(f"Fetched {len(objects)} AD objects, parsing ACEs...")

        for obj in objects:
            self._parse_object_aces(obj, principal_sids)

        self._report_findings()

        if self.output_file:
            try:
                with open(self.output_file, "w") as f:
                    json.dump(self.findings, f, indent=2)
                context.log.success(f"Findings written to {self.output_file}")
            except Exception as e:
                context.log.fail(f"Failed to write output file: {e}")

    def _resolve_principal_sids(self):
        sids = set()

        username = self.target_user if self.target_user else self.conn.username
        if not username:
            self.context.log.fail("Could not determine current username — use TARGET_USER option")
            return sids

        self.context.log.display(f"Resolving SIDs for: {username}")

        user_resp = self.conn.search(
            searchFilter=f"(&(objectClass=user)(sAMAccountName={username}))",
            attributes=["objectSid", "memberOf", "distinguishedName", "sAMAccountName"],
        )
        user_entries = parse_result_attributes(user_resp)
        if not user_entries:
            self.context.log.fail(f"User '{username}' not found in directory")
            return sids

        user_attrs = user_entries[0]
        user_sid = user_attrs.get("objectSid")
        if user_sid:
            sids.add(user_sid)
            self.context.log.display(f"User SID: {user_sid}")

        member_of = user_attrs.get("memberOf", [])
        if isinstance(member_of, str):
            member_of = [member_of]

        for group_dn in member_of:
            group_resp = self.conn.search(
                searchFilter=f"(distinguishedName={group_dn})",
                attributes=["objectSid", "sAMAccountName"],
            )
            group_entries = parse_result_attributes(group_resp)
            if group_entries:
                group_sid = group_entries[0].get("objectSid")
                if group_sid:
                    sids.add(group_sid)

        self.context.log.display(f"Total SIDs (user + groups): {len(sids)}")
        return sids

    def _get_ad_objects(self):
        sd_control = [SDFlagsControl(criticality=True, flags=0x04)]
        resp = self.conn.search(
            searchFilter="(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=domain))",
            attributes=["distinguishedName", "sAMAccountName", "objectClass", "objectSid", "nTSecurityDescriptor", "adminCount"],
            searchControls=sd_control,
        )
        # Return raw entries — we need nTSecurityDescriptor as bytes not decoded string
        return [e for e in resp if isinstance(e, SearchResultEntry)]

    def _parse_object_aces(self, obj, principal_sids):
        # Use parse_result_attributes for normal fields
        parsed = parse_result_attributes([obj])
        if not parsed:
            return
        attrs = parsed[0]

        # Get raw nTSecurityDescriptor bytes directly from entry
        raw_sd = None
        for attr in obj["attributes"]:
            if str(attr["type"]) == "nTSecurityDescriptor":
                try:
                    raw_sd = attr["vals"][0].__bytes__()
                except Exception:
                    return
                break

        if not raw_sd:
            return

        obj_name = attrs.get("sAMAccountName") or attrs.get("distinguishedName", "unknown")
        obj_dn = attrs.get("distinguishedName", "")
        obj_classes = attrs.get("objectClass", [])
        is_privileged = bool(attrs.get("adminCount"))

        if isinstance(obj_classes, str):
            obj_classes = [obj_classes]

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        except Exception as e:
            self.context.log.debug(f"Failed to parse SD for {obj_name}: {e}")
            return

        if not sd["Dacl"]:
            return

        for ace in sd["Dacl"]["Data"]:
            ace_type = ace["AceType"]
            if ace_type not in (ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE):
                continue

            ace_sid = self._ace_sid_str(ace)
            if ace_sid not in principal_sids:
                continue

            mask = ace["Ace"]["Mask"]["Mask"]

            for right_mask, right_name in INTERESTING_RIGHTS.items():
                if mask & right_mask != right_mask:
                    continue
                if right_name == "WriteProperty" and ace_type == ACCESS_ALLOWED_OBJECT_ACE:
                    object_type = self._guid_str(ace["Ace"]["ObjectType"] if "ObjectType" in ace["Ace"].fields else b"")
                    prop_name = PROPERTY_GUIDS.get(object_type)
                    if prop_name:
                        self._add_finding(obj_name, obj_dn, obj_classes, f"WriteProperty ({prop_name})", is_privileged)
                    elif self.show_all:
                        self._add_finding(obj_name, obj_dn, obj_classes, "WriteProperty (generic)", is_privileged)
                elif right_name != "WriteProperty":
                    self._add_finding(obj_name, obj_dn, obj_classes, right_name, is_privileged)

            if ace_type == ACCESS_ALLOWED_OBJECT_ACE:
                object_type = self._guid_str(ace["Ace"]["ObjectType"] if "ObjectType" in ace["Ace"].fields else b"")
                if object_type not in PROPERTY_GUIDS:
                    ext_name = EXTENDED_RIGHTS.get(object_type)
                    if ext_name:
                        self._add_finding(obj_name, obj_dn, obj_classes, ext_name, is_privileged)
                    elif object_type and self.show_all:
                        self._add_finding(obj_name, obj_dn, obj_classes, f"ExtendedRight ({object_type})", is_privileged)

    def _add_finding(self, obj_name, obj_dn, obj_classes, right, is_privileged):
        is_critical = is_privileged or right in (
            "GenericAll", "WriteDACL", "WriteOwner",
            "DS-Replication-Get-Changes-All",
            "WriteProperty (msDS-KeyCredentialLink)",
        )
        severity = "CRITICAL" if is_critical else "HIGH"
        suggestion = ATTACK_SUGGESTIONS.get(right, "Review manually")

        finding = {
            "object": obj_name,
            "dn": obj_dn,
            "right": right,
            "object_classes": obj_classes if isinstance(obj_classes, list) else [obj_classes],
            "is_privileged_target": bool(is_privileged),
            "severity": severity,
            "suggestion": suggestion,
        }
        self.findings.append(finding)

        if is_privileged or self.show_all or is_critical:
            if is_critical:
                self.context.log.highlight(f"{right} on {obj_name} -> {suggestion}")
            else:
                self.context.log.success(f"{right} on {obj_name} -> {suggestion}")

    def _report_findings(self):
        total = len(self.findings)
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = total - critical

        if not total:
            self.context.log.display("No abusable ACEs found for the target principal")
            return

        self.context.log.success(f"Found {total} abusable ACE(s) — {critical} CRITICAL, {high} HIGH")
        self.context.log.display("Summary by right:")

        by_right = {}
        for f in self.findings:
            by_right.setdefault(f["right"], []).append(f["object"])

        for right, targets in sorted(by_right.items()):
            preview = ", ".join(targets[:3])
            overflow = f" (+{len(targets) - 3} more)" if len(targets) > 3 else ""
            self.context.log.highlight(f"  {right} -> {preview}{overflow}")

    @staticmethod
    def _ace_sid_str(ace):
        try:
            return ldaptypes.LDAP_SID(data=ace["Ace"]["Sid"].getData()).formatCanonical()
        except Exception:
            return ""

    @staticmethod
    def _guid_str(raw_guid):
        if not raw_guid:
            return ""
        try:
            guid_bytes = raw_guid if isinstance(raw_guid, bytes) else bytes(raw_guid)
            if len(guid_bytes) < 16:
                return ""
            return str(uuid.UUID(bytes_le=guid_bytes))
        except Exception:
            return ""
