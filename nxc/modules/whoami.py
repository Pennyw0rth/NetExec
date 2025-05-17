class NXCModule:
    """
    Basic enumeration of provided user information and privileges
    Module by spyr0 (@spyr0-sec)
    """

    name = "whoami"
    description = "Get details of provided user"
    supported_protocols = ["ldap"]
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        """USER  Enumerate information about a different SamAccountName"""
        self.username = None
        if "USER" in module_options:
            self.username = module_options["USER"]

    def on_login(self, context, connection):
        searchBase = connection.ldap_connection._baseDN
        searchFilter = f"(sAMAccountName={connection.username})" if self.username is None else f"(sAMAccountName={format(self.username)})"

        context.log.debug(f"Using naming context: {searchBase} and {searchFilter} as search filter")

        # Get attributes of provided user
        r = connection.ldap_connection.search(
            searchBase=searchBase,
            searchFilter=searchFilter,
            attributes=[
                "name",
                "sAMAccountName",
                "description",
                "distinguishedName",
                "pwdLastSet",
                "logonCount",
                "lastLogon",
                "userAccountControl",
                "servicePrincipalName",
                "userPrincipalName",
                "mail",
                "memberOf",
            ],
            sizeLimit=9999,
        )
        for response in r[0]["attributes"]:
            if "userAccountControl" in str(response["type"]):
               uac_raw = response["vals"][0]
    
               # Ensure it's a string, then integer
               uac = int(uac_raw.decode() if isinstance(uac_raw, bytes) else str(uac_raw))

               # Flags
               ACCOUNTDISABLE = 0x0002
               DONT_EXPIRE_PASSWORD = 0x10000

               is_disabled = (uac & ACCOUNTDISABLE) != 0
               password_never_expires = (uac & DONT_EXPIRE_PASSWORD) != 0

               context.log.highlight(f"Enabled: {'No' if is_disabled else 'Yes'}")
               context.log.highlight(f"Password Never Expires: {'Yes' if password_never_expires else 'No'}")
            elif "lastLogon" in str(response["type"]):
               raw = response["vals"][0]
               # Convert from bytes if needed
               filetime_str = raw.decode() if isinstance(raw, bytes) else str(raw)
               filetime_int = int(filetime_str)

               if filetime_int == 1601:
                 context.log.highlight("Last logon: Never")
               else:
                  # Convert FILETIME to datetime
                  dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime_int / 10)
                  context.log.highlight(f"Last logon: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            elif "memberOf" in str(response["type"]):
                for group in response["vals"]:
                    context.log.highlight(f"Member of: {group}")
            elif "servicePrincipalName" in str(response["type"]):
                context.log.highlight("Service Account Name(s) found - Potentially Kerberoastable user!")
                for spn in response["vals"]:
                    context.log.highlight(f"Service Account Name: {spn}")
            elif "pwdLastSet" in str(response["type"]):
                raw = response["vals"][0]
                # Convert from bytes if needed
                filetime_str = raw.decode() if isinstance(raw, bytes) else str(raw)
                filetime_int = int(filetime_str)

                if filetime_int == 0:
                    context.log.highlight("Password Last Set: Never")
                else:
                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime_int / 10)
                    context.log.highlight(f"Password Last Set: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            else:
                context.log.highlight(response["type"] + ": " + response["vals"][0])
