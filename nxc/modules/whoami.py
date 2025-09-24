import datetime
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Basic enumeration of provided user information and privileges
    Module by spyr0 (@spyr0-sec)
    """

    name = "whoami"
    description = "Get details of provided user"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @staticmethod
    def register_module_options(subparsers):
        subparsers.add_argument("--user-to-query", help="Username to query LDAP for", required=True)
        return subparsers

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.username = module_options.user_to_query

    def on_login(self, connection):
        searchBase = connection.ldap_connection._baseDN
        searchFilter = f"(sAMAccountName={connection.username})" if self.username is None else f"(sAMAccountName={format(self.username)})"

        self.context.log.debug(f"Using naming context: {searchBase} and {searchFilter} as search filter")

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
                "objectSid",
                "mail",
                "badPwdCount",
                "memberOf",
            ],
            sizeLimit=999,
        )
        resp_parsed = parse_result_attributes(r)

        for response in resp_parsed:

            # Process name
            if "name" in response:
                self.context.log.highlight(f"Name: {response['name']}")

            # Process Description
            if "description" in response:
                self.context.log.highlight(f"Description: {response['description']}")

            # Process sAMAccountName
            if "sAMAccountName" in response:
                self.context.log.highlight(f"sAMAccountName: {response['sAMAccountName']}")

            # Process userAccountControl
            if "userAccountControl" in response:
                uac = int(response["userAccountControl"])
                ACCOUNTDISABLE = 0x0002
                DONT_EXPIRE_PASSWORD = 0x10000
                is_disabled = (uac & ACCOUNTDISABLE) != 0
                password_never_expires = (uac & DONT_EXPIRE_PASSWORD) != 0
                self.context.log.highlight(f"Enabled: {'No' if is_disabled else 'Yes'}")
                self.context.log.highlight(f"Password Never Expires: {'Yes' if password_never_expires else 'No'}")

            # Process User PrincipalName
            if "userPrincipalName" in response:
                self.context.log.highlight(f"User Principal Name: {response['userPrincipalName']}")

            # Process mail
            if "mail" in response:
                self.context.log.highlight(f"Email: {response['mail']}")

            # Process lastLogon
            if "lastLogon" in response:
                filetime_str = response["lastLogon"]
                filetime_int = int(filetime_str)
                if filetime_int == 0:
                    self.context.log.highlight("Last logon: Never")
                else:
                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime_int / 10)
                    self.context.log.highlight(f"Last logon: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")

            # Process pwdLastSet
            if "pwdLastSet" in response:
                filetime_str = response["pwdLastSet"]
                filetime_int = int(filetime_str)
                if filetime_int == 0:
                    self.context.log.highlight("Password Last Set: Never")
                else:
                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime_int / 10)
                    self.context.log.highlight(f"Password Last Set: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")

            # Process Bad Password Count
            if "badPwdCount" in response:
                self.context.log.highlight(f"Bad Password Count: {response['badPwdCount']}")

            # Process servicePrincipalName
            if "servicePrincipalName" in response:
                self.context.log.highlight("Service Account Name(s) found - Potentially Kerberoastable user!")
                spns = response["servicePrincipalName"]
                if isinstance(spns, list):
                    for spn in spns:
                        self.context.log.highlight(f"Service Account Name: {spn}")
                else:
                    self.context.log.highlight(f"Service Account Name: {spns}")

            # Process DistinguishedName
            if "distinguishedName" in response:
                self.context.log.highlight(f"Distinguished Name: {response['distinguishedName']}")

            # Process memberOf
            if "memberOf" in response:
                groups = response["memberOf"]
                if isinstance(groups, list):
                    for group in groups:
                        self.context.log.highlight(f"Member of: {group}")
                else:
                    self.context.log.highlight(f"Member of: {groups}")

            # Process User Sid
            if "objectSid" in response:
                self.context.log.highlight(f"User SID: {response['objectSid']}")
