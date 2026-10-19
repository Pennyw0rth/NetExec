import sys
from impacket.ldap import ldaptypes
from impacket.ldap.ldap import MODIFY_REPLACE
from impacket.ldap.ldapasn1 import SDFlagsControl
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY

OWNER_SECURITY_INFORMATION = 0x1


class NXCModule:
    """
    Module for reading or changing the owner of an Active Directory object
    Module by @termanix
    """

    name = "modify-owner"
    description = "Read or change the owner of an AD object (WriteOwner permission required for modification)"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        """
        TARGET      sAMAccountName of the target AD object (required)
        OWNER       sAMAccountName of the new owner (optional)

        Examples
        --------
        Read the current owner of an object:
            netexec ldap <DC_IP> -u user -p password -M modify-owner -o TARGET=user2

        Change the owner of an object:
            netexec ldap <DC_IP> -u user -p password -M modify-owner -o TARGET=user2 OWNER=newuser
            netexec ldap <DC_IP> -u user -p password -M modify-owner -o TARGET='Domain Admins' OWNER=newuser
        """
        self.target = module_options.get("TARGET")
        self.owner = module_options.get("OWNER")

        if not self.target:
            context.log.fail("TARGET parameter is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        if self.owner:
            self.modify_owner()
        else:
            self.read_owner()

    def read_owner(self):
        sd_control = [SDFlagsControl(flags=OWNER_SECURITY_INFORMATION)]
        resp = self.connection.search(
            searchFilter=f"(sAMAccountName={self.target})",
            attributes=["nTSecurityDescriptor"],
            searchControls=sd_control,
        )
        parsed = parse_result_attributes(resp)
        if not parsed or "nTSecurityDescriptor" not in parsed[0]:
            self.context.log.fail(f"Could not read nTSecurityDescriptor for: {self.target}")
            return

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=parsed[0]["nTSecurityDescriptor"])
        owner_sid = sd["OwnerSid"].formatCanonical()
        owner_name = self.resolve_sid(owner_sid) or owner_sid
        self.context.log.highlight(f"Owner of '{self.target}': {owner_name} ({owner_sid})")

    def modify_owner(self):
        # Find target DN
        target_entries = self.find_object(self.target, ["distinguishedName"])
        if not target_entries:
            self.context.log.fail(f"Target object not found: {self.target}")
            return
        target_dn = target_entries[0]["distinguishedName"]
        self.context.log.debug(f"Target DN: {target_dn}")

        # Find new owner's SID
        owner_entries = self.find_object(self.owner, ["objectSid"])
        if not owner_entries:
            self.context.log.fail(f"Owner object not found: {self.owner}")
            return
        new_owner_sid = owner_entries[0].get("objectSid")
        if not new_owner_sid:
            self.context.log.fail(f"Could not retrieve objectSid for: {self.owner}")
            return
        self.context.log.debug(f"New owner SID: {new_owner_sid}")

        # Read the full security descriptor (Owner + Group + DACL) so getData() produces a valid SD
        full_sd_control = [SDFlagsControl(flags=0x07)]
        resp = self.connection.search(searchFilter=f"(sAMAccountName={self.target})", attributes=["nTSecurityDescriptor"], searchControls=full_sd_control)
        parsed = parse_result_attributes(resp)
        if not parsed or "nTSecurityDescriptor" not in parsed[0]:
            self.context.log.fail(f"Could not read nTSecurityDescriptor for: {self.target}")
            return

        raw_sd = parsed[0]["nTSecurityDescriptor"]
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)

        old_owner_sid = sd["OwnerSid"].formatCanonical()
        self.context.log.debug(f"Current owner SID: {old_owner_sid}")

        if old_owner_sid == new_owner_sid:
            self.context.log.fail(f"{self.owner} ({new_owner_sid}) is already the owner of '{self.target}'")
            return

        old_owner_name = self.resolve_sid(old_owner_sid) or old_owner_sid

        # Replace owner SID and write back — send only the owner portion to the DC
        sd["OwnerSid"].fromCanonical(new_owner_sid)
        owner_sd_control = [SDFlagsControl(flags=OWNER_SECURITY_INFORMATION)]

        try:
            self.connection.ldap_connection.modify(target_dn, {"nTSecurityDescriptor": [(MODIFY_REPLACE, [sd.getData()])]}, controls=owner_sd_control)
            self.context.log.success(f"Owner of '{self.target}' changed: {old_owner_name} ({old_owner_sid}) -> {self.owner} ({new_owner_sid})")
        except Exception as e:
            if "insufficientAccessRights" in str(e):
                self.context.log.fail(f"Permission denied: '{self.connection.username}' does not have WriteOwner on '{self.target}'")
            elif "constraintViolation" in str(e):
                self.context.log.fail(f"WriteOwner only allows setting yourself or a group you belong to as owner of '{self.target}'")
            else:
                self.context.log.fail(f"Failed to modify owner of '{self.target}': {e}")

    def find_object(self, sam_account_name, attributes):
        resp = self.connection.search(
            searchFilter=f"(sAMAccountName={sam_account_name})",
            attributes=attributes,
        )
        return parse_result_attributes(resp)

    def resolve_sid(self, sid):
        resp = self.connection.search(
            searchFilter=f"(objectSid={sid})",
            attributes=["sAMAccountName"],
        )
        parsed = parse_result_attributes(resp)
        if parsed and "sAMAccountName" in parsed[0]:
            return parsed[0]["sAMAccountName"]
        return None
