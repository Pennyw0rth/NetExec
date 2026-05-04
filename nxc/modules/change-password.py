import contextlib
import sys

from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.ldap.ldap import LDAPSessionError, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for changing or resetting user passwords.
    Module by Fagan Afandiyev, termanix and NeffIsBack.
    Refactored by azoxlpf to support SMB (SAMR) and LDAP backends, including Kerberos auth.
    """

    name = "change-password"
    description = "Change or reset user passwords via SAMR (SMB) or LDAP"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    MUST_CHANGE_STATUSES = (
        "STATUS_PASSWORD_MUST_CHANGE",
        "STATUS_PASSWORD_EXPIRED",
        "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
    )

    def options(self, context, module_options):
        """
        Required (one of):
        NEWPASS     The new password of the user.
        NEWNTHASH   The new NT hash of the user (SMB protocol only).

        Optional:
        USER        The user account if the target is not the current user.

        Examples
        --------
        Self password/hash change (e.g. STATUS_PASSWORD_MUST_CHANGE / STATUS_PASSWORD_EXPIRED):
            nxc smb <DC_IP> -u username -p oldpass -M change-password -o NEWPASS='newpass'
            nxc smb <DC_IP> -u username -H oldnthash -M change-password -o NEWNTHASH='newnthash'
            nxc ldap <DC_IP> -u username -p oldpass -M change-password -o NEWPASS='newpass'

        Reset another user's password (ForceChangePassword right or admin):
            nxc smb  <DC_IP> -u admin -p password -M change-password -o USER='target' NEWPASS='newpass'
            nxc smb  <DC_IP> -u admin -p password -M change-password -o USER='target' NEWNTHASH='newnthash'
            nxc ldap <DC_IP> -u admin -p password -M change-password -o USER='target' NEWPASS='newpass'
        """
        self.newpass = module_options.get("NEWPASS")
        self.newhash = module_options.get("NEWNTHASH")
        self.target_user = module_options.get("USER")

        if not self.newpass and not self.newhash:
            context.log.fail("Either NEWPASS or NEWNTHASH is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.target_username = self.target_user or connection.username
        self.target_domain = connection.domain
        self.is_self_change = self.target_username.lower() == connection.username.lower()

        if self.newhash:
            try:
                _, self.new_nthash = self.newhash.split(":")
            except ValueError:
                self.new_nthash = self.newhash
        else:
            self.new_nthash = ""

        if connection.args.protocol == "smb":
            self.do_samr()
        elif connection.args.protocol == "ldap":
            self.do_ldap()

    def db_remove_credential(self):
        try:
            db = self.context.db
            domain = self.connection.domain
            rows = db.get_user(domain, self.computer_name) if hasattr(db, "get_user") else db.get_credentials(filter_term=self.computer_name)
            db.remove_credentials([row[0] for row in rows])
        except Exception as e:
            self.context.log.debug(f"Could not remove credentials from DB: {e}")

    def db_add_credential(self):
        if self.new_nthash:
            self.context.db.add_credential("hash", self.target_domain, self.target_username, self.new_nthash)
        else:
            self.context.db.add_credential("plaintext", self.target_domain, self.target_username, self.newpass)

    def do_samr(self):
        dce = self.samr_connect()
        if dce is None:
            return
        try:
            self.samr_execute(dce)
        finally:
            with contextlib.suppress(Exception):
                dce.disconnect()

    def samr_connect(self):
        try:
            return self.samr_bind()
        except Exception as e:
            err = str(e)

            if "STATUS_LOGON_FAILURE" in err:
                self.context.log.fail("Authentication failure: wrong credentials.")
                return None

            must_change = not self.connection.kerberos and any(s in err for s in self.MUST_CHANGE_STATUSES)
            if not must_change:
                self.context.log.fail(f"Failed to connect to SAMR: {e}")
                return None

            self.context.log.warning("Password must be changed. Falling back to null session over ncacn_ip_tcp.")
            try:
                return self.samr_bind(dce_protocol="ncacn_ip_tcp", anonymous=True)
            except Exception as e2:
                self.context.log.fail(f"Failed to bind to SAMR with null session: {e2}")
                return None

    def samr_bind(self, dce_protocol="ncacn_np", anonymous=False):
        target = self.connection.host if not self.connection.kerberos else f"{self.connection.hostname}.{self.connection.domain}"
        string_binding = epm.hept_map(target, samr.MSRPC_UUID_SAMR, protocol=dce_protocol)
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.setRemoteHost(target)

        if anonymous:
            rpc_transport.set_credentials("", "", "", "", "", "")
            rpc_transport.set_kerberos(False, None)
            self.context.log.info("Connecting with null session credentials.")
        else:
            rpc_transport.set_credentials(
                self.connection.username,
                self.connection.password,
                self.connection.domain,
                self.connection.lmhash,
                self.connection.nthash,
                aesKey=self.connection.aesKey,
            )
            rpc_transport.set_kerberos(self.connection.kerberos, kdcHost=self.connection.kdcHost)
            self.context.log.info(f"Connecting as {self.connection.domain}\\{self.connection.username} (kerberos={self.connection.kerberos})")

        dce = rpc_transport.get_dce_rpc()
        if not anonymous and self.connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    def samr_execute(self, dce):
        if self.is_self_change and not self.connection.password and not self.connection.nthash:
            self.context.log.fail("Self-change over SAMR requires the current password (-p) or NT hash (-H).")
            return

        try:
            if not self.is_self_change:
                user_handle = self.samr_open_user(dce, self.target_username)
                samr.hSamrSetNTInternal1(dce, user_handle, self.newpass, self.new_nthash)
                self.context.log.success(f"Successfully reset password for '{self.target_username}'")
            elif self.newpass:
                samr.hSamrUnicodeChangePasswordUser2(dce, "\x00", self.target_username, self.connection.password, self.newpass, "", self.connection.nthash)
                self.context.log.success(f"Successfully changed password for '{self.target_username}'")
            else:
                user_handle = self.samr_open_user(dce, self.target_username)
                samr.hSamrChangePasswordUser(dce, user_handle, self.connection.password, "", self.connection.nthash, "aad3b435b51404eeaad3b435b51404ee", self.new_nthash)
                self.context.log.success(f"Successfully changed password hash for '{self.target_username}'")
                self.context.log.highlight("Note: password must be changed at next logon.")

            self.db_remove_credential()
            self.db_add_credential()
        except Exception as e:
            err = str(e)
            if "STATUS_ACCESS_DENIED" in err:
                action = "change" if self.is_self_change else "reset"
                self.context.log.fail(f"{self.connection.username} does not have the right to {action} password for '{self.target_username}'")
            elif "STATUS_NONE_MAPPED" in err:
                self.context.log.fail(f"User '{self.target_username}' not found or not resolvable")
            elif "STATUS_PASSWORD_RESTRICTION" in err:
                self.context.log.fail(f"Password does not meet the domain policy for '{self.target_username}'")
            elif "STATUS_WRONG_PASSWORD" in err:
                self.context.log.fail("Wrong current password or NT hash provided for self-change")
            else:
                self.context.log.fail(f"SMB-SAMR password change failed: {e}")

    def samr_open_user(self, dce, username):
        server_handle = samr.hSamrConnect(dce, self.connection.host + "\x00")["ServerHandle"]
        domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.connection.domain)["DomainId"]
        domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
        user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (username,))["RelativeIds"]["Element"][0]
        return samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)["UserHandle"]

    def do_ldap(self):
        if self.newhash:
            self.context.log.fail("Cannot set NEWNTHASH over LDAP. Use the smb protocol instead.")
            return
        if self.is_self_change and not self.connection.password:
            self.context.log.fail("Cannot perform self password change over LDAP without plaintext (-p). Use the smb protocol instead.")
            return

        user_dn = self.ldap_find_user_dn(self.target_username)
        if user_dn is None:
            return

        if self.is_self_change:
            self.ldap_self_change(user_dn)
        else:
            self.ldap_admin_reset(user_dn)

    def ldap_find_user_dn(self, username):
        try:
            resp = self.connection.search(
                searchFilter=f"(sAMAccountName={username})",
                attributes=["distinguishedName"],
            )
            parsed = parse_result_attributes(resp)
            if not parsed:
                self.context.log.fail(f"User '{username}' not found in LDAP")
                return None
            return parsed[0]["distinguishedName"]
        except Exception as e:
            self.context.log.fail(f"LDAP search failed for '{username}': {e}")
            return None

    def ldap_self_change(self, dn):
        old_encoded = f'"{self.connection.password}"'.encode("utf-16-le")
        new_encoded = f'"{self.newpass}"'.encode("utf-16-le")
        try:
            self.connection.ldap_connection.modify(dn, {"unicodePwd": [(MODIFY_DELETE, [old_encoded]), (MODIFY_ADD, [new_encoded]),]},)
            self.context.log.success(f"Successfully changed password for '{self.target_username}'")
            self.db_remove_credential()
            self.db_add_credential()
        except LDAPSessionError as e:
            self.handle_ldap_error(e, action="change")

    def ldap_admin_reset(self, dn):
        new_encoded = f'"{self.newpass}"'.encode("utf-16-le")
        try:
            self.connection.ldap_connection.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [new_encoded])]})
            self.context.log.success(f"Successfully reset password for '{self.target_username}'")
            self.db_remove_credential()
            self.db_add_credential()
        except LDAPSessionError as e:
            self.handle_ldap_error(e, action="reset")

    def handle_ldap_error(self, exc, action):
        err = str(exc)
        if "noSuchObject" in err:
            self.context.log.fail(f"User '{self.target_username}' was not found")
        elif "insufficientAccessRights" in err:
            self.context.log.fail(f"Insufficient rights to {action} password for '{self.target_username}'")
        elif "unwillingToPerform" in err:
            if action == "change":
                self.context.log.fail(f"Server unwilling to perform: wrong current password or policy violation for '{self.target_username}'")
            else:
                self.context.log.fail(f"Server unwilling to perform password reset for '{self.target_username}'")
        elif "constraintViolation" in err:
            self.context.log.fail(f"Constraint violation for '{self.target_username}': new password does not meet the domain policy")
        else:
            self.context.log.fail(f"Failed to {action} password for '{self.target_username}': {exc}")
