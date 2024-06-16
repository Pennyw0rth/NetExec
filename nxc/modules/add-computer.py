import ssl
import ldap3
import sys
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

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
    opsec_safe = True
    multiple_hosts = False

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
        self.__baseDN = None
        self.__computerGroup = None
        self.__method = "SAMR"
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
        self.__domain = connection.domain
        self.__domainNetbios = connection.domain
        self.__kdcHost = connection.kdcHost
        self.__username = connection.username
        self.__password = connection.password
        self.__host = connection.host
        self.__port = context.smb_server_port
        self.__aesKey = context.aesKey
        self.__hashes = context.hash
        self.__doKerberos = connection.kerberos
        self.__nthash = ""
        self.__lmhash = ""

        if context.hash and ":" in context.hash[0]:
            hashList = context.hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif context.hash and ":" not in context.hash[0]:
            self.__nthash = context.hash[0]
            self.__lmhash = "00000000000000000000000000000000"

        # First try to add via SAMR over SMB
        self.do_samr_add(context)

        # If SAMR fails now try over LDAPS
        if not self.noLDAPRequired:
            self.do_ldaps_add(connection, context)
            

    def do_samr_add(self, context):
        """
        Connects to a target server and performs various operations related to adding or deleting machine accounts.

        Args:
        ----
            context (object): The context object.

        Returns:
        -------
            None
        """
        string_binding = epm.hept_map(self.__host, samr.MSRPC_UUID_SAMR, protocol="ncacn_np")

        rpc_transport = transport.DCERPCTransportFactory(string_binding.replace(self.__host, self.__kdcHost))
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

        samr_enum_response = samr.hSamrEnumerateDomainsInSamServer(dce, serv_handle)
        domains = samr_enum_response["Buffer"]["Buffer"]
        domains_without_builtin = [domain for domain in domains if domain["Name"].lower() != "builtin"]
        if len(domains_without_builtin) > 1:
            domain = list(filter(lambda x: x["Name"].lower() == self.__domainNetbios, domains))
            if len(domain) != 1:
                context.log.highlight("{}".format('This domain does not exist: "' + self.__domainNetbios + '"'))
                context.log.highlight("Available domain(s):")
                for domain in domains:
                    context.log.highlight(f" * {domain['Name']}")
                raise Exception
            else:
                selected_domain = domain[0]["Name"]
        else:
            selected_domain = domains_without_builtin[0]["Name"]

        samr_lookup_domain_response = samr.hSamrLookupDomainInSamServer(dce, serv_handle, selected_domain)
        domain_sid = samr_lookup_domain_response["DomainId"]

        context.log.debug(f"Opening domain {selected_domain}...")
        samr_open_domain_response = samr.hSamrOpenDomain(dce, serv_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER, domain_sid)
        domain_handle = samr_open_domain_response["DomainHandle"]

        if self.__noAdd or self.__delete:
            try:
                check_for_user = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])
            except samr.DCERPCSessionError as e:
                if e.error_code == 0xC0000073:
                    context.log.highlight(f"{self.__computerName} not found in domain {selected_domain}")
                    self.noLDAPRequired = True
                context.log.exception(e)

            user_rid = check_for_user["RelativeIds"]["Element"][0]
            if self.__delete:
                access = samr.DELETE
                message = "delete"
            else:
                access = samr.USER_FORCE_PASSWORD_CHANGE
                message = "set the password for"
            try:
                open_user = samr.hSamrOpenUser(dce, domain_handle, access, user_rid)
                user_handle = open_user["UserHandle"]
            except samr.DCERPCSessionError as e:
                if e.error_code == 0xC0000022:
                    context.log.highlight(f"{self.__username + ' does not have the right to ' + message + ' ' + self.__computerName}")
                    self.noLDAPRequired = True
                context.log.exception(e)
        else:
            if self.__computerName is not None:
                try:
                    samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])
                    self.noLDAPRequired = True
                    context.log.highlight("{}".format('Computer account already exists with the name: "' + self.__computerName + '"'))
                except samr.DCERPCSessionError as e:
                    if e.error_code != 0xC0000073:
                        raise
            else:
                found_unused = False
                while not found_unused:
                    self.__computerName = self.generateComputerName()
                    try:
                        samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])
                    except samr.DCERPCSessionError as e:
                        if e.error_code == 0xC0000073:
                            found_unused = True
                        else:
                            raise
            try:
                create_user = samr.hSamrCreateUser2InDomain(
                    dce,
                    domain_handle,
                    self.__computerName,
                    samr.USER_WORKSTATION_TRUST_ACCOUNT,
                    samr.USER_FORCE_PASSWORD_CHANGE,
                )
                self.noLDAPRequired = True
                context.log.highlight('Successfully added the machine account: "' + self.__computerName + '" with Password: "' + self.__computerPassword + '"')
            except samr.DCERPCSessionError as e:
                if e.error_code == 0xC0000022:
                    context.log.highlight("{}".format('The following user does not have the right to create a computer account: "' + self.__username + '"'))
                elif e.error_code == 0xC00002E7:
                    context.log.highlight("{}".format('The following user exceeded their machine account quota: "' + self.__username + '"'))
                context.log.exception(e)
            user_handle = create_user["UserHandle"]

        if self.__delete:
            samr.hSamrDeleteUser(dce, user_handle)
            context.log.highlight("{}".format('Successfully deleted the "' + self.__computerName + '" Computer account'))
            self.noLDAPRequired = True
            user_handle = None
        else:
            samr.hSamrSetPasswordInternal4New(dce, user_handle, self.__computerPassword)
            if self.__noAdd:
                context.log.highlight("{}".format('Successfully set the password of machine "' + self.__computerName + '" with password "' + self.__computerPassword + '"'))
                self.noLDAPRequired = True
            else:
                check_for_user = samr.hSamrLookupNamesInDomain(dce, domain_handle, [self.__computerName])
                user_rid = check_for_user["RelativeIds"]["Element"][0]
                open_user = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)
                user_handle = open_user["UserHandle"]
                req = samr.SAMPR_USER_INFO_BUFFER()
                req["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
                req["Control"]["UserAccountControl"] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                samr.hSamrSetInformationUser2(dce, user_handle, req)
                if not self.noLDAPRequired:
                    context.log.highlight("{}".format('Successfully added the machine account "' + self.__computerName + '" with Password: "' + self.__computerPassword + '"'))
                self.noLDAPRequired = True

            if user_handle is not None:
                samr.hSamrCloseHandle(dce, user_handle)
            if domain_handle is not None:
                samr.hSamrCloseHandle(dce, domain_handle)
            if serv_handle is not None:
                samr.hSamrCloseHandle(dce, serv_handle)
            dce.disconnect()

    def do_ldaps_add(self, connection, context):
        """
        Performs an LDAPS add operation.

        Args:
        ----
            connection (Connection): The LDAP connection object.
            context (Context): The context object.

        Returns:
        -------
            None

        Raises:
        ------
            None
        """
        ldap_domain = connection.domain.replace(".", ",dc=")
        spns = [
            f"HOST/{self.__computerName}",
            f"HOST/{self.__computerName}.{connection.domain}",
            f"RestrictedKrbHost/{self.__computerName}",
            f"RestrictedKrbHost/{self.__computerName}.{connection.domain}",
        ]
        ucd = {
            "dnsHostName": f"{self.__computerName}.{connection.domain}",
            "userAccountControl": 0x1000,
            "servicePrincipalName": spns,
            "sAMAccountName": self.__computerName,
            "unicodePwd": f"{self.__computerPassword}".encode("utf-16-le")
        }
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL:@SECLEVEL=0")
        ldap_server = ldap3.Server(connection.host, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        c = ldap3.Connection(ldap_server, f"{connection.username}@{connection.domain}", connection.password)
        c.bind()

        if self.__delete:
            result = c.delete(f"cn={self.__computerName},cn=Computers,dc={ldap_domain}")
            if result:
                context.log.highlight(f'Successfully deleted the "{self.__computerName}" Computer account')
            elif result is False and c.last_error == "noSuchObject":
                context.log.highlight(f'Computer named "{self.__computerName}" was not found')
            elif result is False and c.last_error == "insufficientAccessRights":
                context.log.highlight(f'Insufficient Access Rights to delete the Computer "{self.__computerName}"')
            else:
                context.log.highlight(f'Unable to delete the "{self.__computerName}" Computer account. The error was: {c.last_error}')
        else:
            result = c.add(
                f"cn={self.__computerName},cn=Computers,dc={ldap_domain}",
                ["top", "person", "organizationalPerson", "user", "computer"],
                ucd
            )
            if result:
                context.log.highlight(f'Successfully added the machine account: "{self.__computerName}" with Password: "{self.__computerPassword}"')
                context.log.highlight("You can try to verify this with the nxc command:")
                context.log.highlight(f"nxc ldap {connection.host} -u {connection.username} -p {connection.password} -M group-mem -o GROUP='Domain Computers'")
            elif result is False and c.last_error == "entryAlreadyExists":
                context.log.highlight(f"The Computer account '{self.__computerName}' already exists")
            elif not result:
                context.log.highlight(f"Unable to add the '{self.__computerName}' Computer account. The error was: {c.last_error}")
            c.unbind()
