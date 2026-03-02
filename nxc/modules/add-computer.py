import sys

from impacket.dcerpc.v5 import samr, transport
from impacket.ldap.ldap import LDAPSessionError, MODIFY_REPLACE
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module by CyberCelt: @Cyb3rC3lt
    Refactored to use impacket LDAP CRUD operations instead of ldap3.

    Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    Thanks to the guys at impacket for the original code
    """

    name = "add-computer"
    description = "Adds or deletes a domain computer via SAMR (SMB) or LDAPS"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        """
        add-computer: Adds, deletes, or changes the password of a domain computer account.
        Uses SAMR when invoked with nxc smb, LDAPS when invoked with nxc ldap.

        NAME        Computer name (required). Trailing '$' is added automatically.
        PASSWORD    Computer password (required for add/changepw).
        DELETE      Set to delete the computer account.
        CHANGEPW    Set to change an existing computer's password.

        Usage:
            nxc smb  $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password1"
            nxc ldap $DC-IP -u Username -p Password --port 636 -M add-computer -o NAME="BADPC" PASSWORD="Password1"
            nxc smb  $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" DELETE=True
            nxc ldap $DC-IP -u Username -p Password --port 636 -M add-computer -o NAME="BADPC" DELETE=True
            nxc smb  $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password2" CHANGEPW=True
            nxc ldap $DC-IP -u Username -p Password --port 636 -M add-computer -o NAME="BADPC" PASSWORD="Password2" CHANGEPW=True
        """
        self.delete = "DELETE" in module_options
        self.no_add = False

        if "CHANGEPW" in module_options:
            if "NAME" not in module_options or "PASSWORD" not in module_options:
                context.log.error("NAME and PASSWORD options are required for CHANGEPW!")
                sys.exit(1)
            self.no_add = True

        if "NAME" not in module_options:
            context.log.error("NAME option is required!")
            sys.exit(1)

        self.computer_name = module_options["NAME"]
        if not self.computer_name.endswith("$"):
            self.computer_name += "$"

        if "PASSWORD" in module_options:
            self.computer_password = module_options["PASSWORD"]
        elif not self.delete:
            context.log.error("PASSWORD option is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        if connection.args.protocol == "smb":
            self._do_samr()
        elif connection.args.protocol == "ldap":
            self._do_ldap()

    def _db_remove_credential(self):
        try:
            db = self.context.db
            domain = self.connection.domain
            rows = db.get_user(domain, self.computer_name) if hasattr(db, "get_user") else db.get_credentials(filter_term=self.computer_name)
            if rows:
                db.remove_credentials([row[0] for row in rows])
        except Exception as e:
            self.context.log.debug(f"Could not remove credentials from DB: {e}")

    def _db_add_credential(self):
        self.context.db.add_credential("plaintext", self.connection.domain, self.computer_name, self.computer_password)

    def _do_samr(self):
        conn = self.connection
        rpc_transport = transport.SMBTransport(
            conn.conn.getRemoteHost(),
            445,
            r"\samr",
            smb_connection=conn.conn,
        )

        try:
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
        except Exception as e:
            self.context.log.fail(f"Failed to connect to SAMR: {e}")
            return

        try:
            self._samr_execute(dce, conn.conn.getRemoteName())
        finally:
            dce.disconnect()

    def _samr_execute(self, dce, target_name):
        domain = self.connection.domain
        username = self.connection.username

        serv_handle = samr.hSamrConnect5(
            dce,
            f"\\\\{target_name}\x00",
            samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN,
        )["ServerHandle"]

        domains = samr.hSamrEnumerateDomainsInSamServer(dce, serv_handle)["Buffer"]["Buffer"]
        non_builtin = [d for d in domains if d["Name"].lower() != "builtin"]

        if len(non_builtin) > 1:
            matched = [d for d in domains if d["Name"].lower() == domain.lower()]
            if len(matched) != 1:
                self.context.log.fail(f"Domain '{domain}' not found. Available: {', '.join(d['Name'] for d in domains)}")
                return
            selected = matched[0]["Name"]
        else:
            selected = non_builtin[0]["Name"]

        domain_sid = samr.hSamrLookupDomainInSamServer(dce, serv_handle, selected)["DomainId"]
        domain_handle = samr.hSamrOpenDomain(
            dce, serv_handle,
            samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER,
            domain_sid,
        )["DomainHandle"]

        user_handle = None
        try:
            user_handle = self._samr_open_existing(dce, domain_handle, selected, username) if self.no_add or self.delete else self._samr_create(dce, domain_handle, username)

            if user_handle is None:
                return

            if self.delete:
                samr.hSamrDeleteUser(dce, user_handle)
                user_handle = None
                self.context.log.highlight(f"Successfully deleted the '{self.computer_name}' Computer account")
                self._db_remove_credential()
            else:
                samr.hSamrSetPasswordInternal4New(dce, user_handle, self.computer_password)
                if self.no_add:
                    self.context.log.highlight(f"Successfully changed password for '{self.computer_name}'")
                else:
                    user_handle = self._samr_set_workstation_trust(dce, domain_handle, user_handle)
                    self.context.log.highlight(f"Successfully added '{self.computer_name}' with password '{self.computer_password}'")
                self._db_add_credential()
        finally:
            if user_handle is not None:
                samr.hSamrCloseHandle(dce, user_handle)
            samr.hSamrCloseHandle(dce, domain_handle)
            samr.hSamrCloseHandle(dce, serv_handle)

    def _samr_set_workstation_trust(self, dce, domain_handle, user_handle):
        user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name])["RelativeIds"]["Element"][0]
        samr.hSamrCloseHandle(dce, user_handle)
        new_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)["UserHandle"]
        req = samr.SAMPR_USER_INFO_BUFFER()
        req["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
        req["Control"]["UserAccountControl"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
        samr.hSamrSetInformationUser2(dce, new_handle, req)
        return new_handle

    def _samr_open_existing(self, dce, domain_handle, selected_domain, username):
        try:
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name])["RelativeIds"]["Element"][0]
        except samr.DCERPCSessionError as e:
            if "STATUS_NONE_MAPPED" in str(e):
                self.context.log.fail(f"'{self.computer_name}' not found in domain {selected_domain}")
            else:
                self.context.log.fail(f"Error looking up {self.computer_name}: {e}")
            return None

        access = samr.DELETE if self.delete else samr.USER_FORCE_PASSWORD_CHANGE
        action = "delete" if self.delete else "change password for"
        try:
            return samr.hSamrOpenUser(dce, domain_handle, access, user_rid)["UserHandle"]
        except samr.DCERPCSessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                self.context.log.fail(f"{username} does not have the right to {action} '{self.computer_name}'")
            else:
                self.context.log.fail(f"Error opening {self.computer_name}: {e}")
            return None

    def _samr_create(self, dce, domain_handle, username):
        try:
            samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.computer_name])
            self.context.log.fail(f"Computer '{self.computer_name}' already exists")
            return None
        except samr.DCERPCSessionError as e:
            if "STATUS_NONE_MAPPED" not in str(e):
                self.context.log.fail(f"Error looking up {self.computer_name}: {e}")
                return None

        try:
            return samr.hSamrCreateUser2InDomain(
                dce, domain_handle, self.computer_name,
                samr.USER_WORKSTATION_TRUST_ACCOUNT,
                samr.USER_FORCE_PASSWORD_CHANGE,
            )["UserHandle"]
        except samr.DCERPCSessionError as e:
            err = str(e)
            if "STATUS_USER_EXISTS" in err:
                self.context.log.fail(f"Computer '{self.computer_name}' already exists")
            elif "STATUS_ACCESS_DENIED" in err:
                self.context.log.fail(f"{username} does not have the right to create a computer account")
            elif "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED" in err:
                self.context.log.fail(f"{username} exceeded the machine account quota")
            else:
                self.context.log.fail(f"Error creating computer: {e}")
            return None

    def _do_ldap(self):
        conn = self.connection
        ldap_connection = conn.ldap_connection

        if not ldap_connection:
            self.context.log.fail("No LDAP connection available")
            return

        if conn.port != 636:
            self.context.log.fail("LDAP module requires LDAPS. Use --port 636.")
            return

        name = self.computer_name.rstrip("$")
        computer_dn = f"CN={name},CN=Computers,{conn.baseDN}"

        if self.delete:
            self._ldap_delete(ldap_connection, computer_dn)
        elif self.no_add:
            self._ldap_change_password(ldap_connection, computer_dn)
        else:
            self._ldap_add(ldap_connection, computer_dn, name)

    def _ldap_delete(self, ldap_conn, dn):
        try:
            ldap_conn.delete(dn)
            self.context.log.highlight(f'Successfully deleted the "{self.computer_name}" Computer account')
            self._db_remove_credential()
        except LDAPSessionError as e:
            err = str(e)
            if "noSuchObject" in err:
                self.context.log.fail(f'Computer "{self.computer_name}" was not found')
            elif "insufficientAccessRights" in err:
                self.context.log.fail(f'Insufficient rights to delete "{self.computer_name}"')
            else:
                self.context.log.fail(f'Failed to delete "{self.computer_name}": {e}')

    def _ldap_change_password(self, ldap_conn, dn):
        try:
            encoded_pw = f'"{self.computer_password}"'.encode("utf-16-le")
            ldap_conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, encoded_pw)]})
            self.context.log.highlight(f"Successfully changed password for '{self.computer_name}'")
            self._db_add_credential()
        except LDAPSessionError as e:
            err = str(e)
            if "noSuchObject" in err:
                self.context.log.fail(f'Computer "{self.computer_name}" was not found')
            elif "insufficientAccessRights" in err:
                self.context.log.fail(f'Insufficient rights to change password for "{self.computer_name}"')
            elif "unwillingToPerform" in err:
                self.context.log.fail(f'Server unwilling to change password for "{self.computer_name}". Verify LDAPS.')
            else:
                self.context.log.fail(f'Failed to change password for "{self.computer_name}": {e}')

    def _ldap_add(self, ldap_conn, dn, name):
        domain = self.connection.domain
        fqdn = f"{name}.{domain}"
        spns = [
            f"HOST/{name}",
            f"HOST/{fqdn}",
            f"RestrictedKrbHost/{name}",
            f"RestrictedKrbHost/{fqdn}",
        ]

        try:
            ldap_conn.add(
                dn,
                ["top", "person", "organizationalPerson", "user", "computer"],
                {
                    "dnsHostName": fqdn,
                    "userAccountControl": 0x1000,
                    "servicePrincipalName": spns,
                    "sAMAccountName": self.computer_name,
                    "unicodePwd": f'"{self.computer_password}"'.encode("utf-16-le"),
                },
            )
            self.context.log.highlight(f'Successfully added "{self.computer_name}" with password "{self.computer_password}"')
            self._db_add_credential()
        except LDAPSessionError as e:
            err = str(e)
            if "entryAlreadyExists" in err:
                self.context.log.fail(f"Computer '{self.computer_name}' already exists")
            elif "insufficientAccessRights" in err:
                self.context.log.fail(f"Insufficient rights to add '{self.computer_name}'")
            elif "unwillingToPerform" in err:
                self.context.log.fail("Server unwilling to perform. Verify LDAPS is active.")
            elif "constraintViolation" in err:
                self.context.log.fail(f"Constraint violation for '{self.computer_name}'. Quota exceeded or password policy.")
            else:
                self.context.log.fail(f"Failed to add '{self.computer_name}': {e}")
