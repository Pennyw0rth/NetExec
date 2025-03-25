from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
import sys


class NXCModule:
    """
    Created as a contributtion from HackTheBox Academy team for CrackMapExec
    Reference: https://academy.hackthebox.com/module/details/84

    Module by @juliourena
    Based on: https://github.com/juliourena/CrackMapExec/blob/master/cme/modules/get_description.py
    """

    name = "groupmembership"
    description = "Query the groups to which a user belongs."
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """USER	Choose a username to query group membership"""
        self.user = ""
        if "USER" in module_options:
            if module_options["USER"] == "":
                context.log.fail("Invalid value for USER option!")
                sys.exit(1)
            self.user = module_options["USER"]
        else:
            context.log.fail("Missing USER option, use --options to list available parameters")
            sys.exit(1)

    def on_login(self, context, connection):
        """Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection"""
        # Building the search filter
        searchFilter = f"(&(objectClass=user)(sAMAccountName={self.user}))"

        try:
            context.log.debug(f"Search Filter={searchFilter}")
            resp = connection.ldap_connection.search(
                searchFilter=searchFilter,
                attributes=["memberOf", "primaryGroupID"],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                context.log.debug(e)
                return False

        memberOf = []
        primaryGroupID = ""

        context.log.debug(f"Total of records returned {len(resp)}")
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "primaryGroupID":
                        primaryGroupID = attribute["vals"][0]
                        # Hardcode value for Domain Users primary Group ID 513
                        # For future improvement maybe we can query the primary ID value
                        # Reference: https://social.technet.microsoft.com/Forums/Azure/en-US/373febac-665c-494d-91f7-834541c74bee/cant-get-all-member-objects-from-domain-users-in-ldap?forum=winserverDS
                        if str(primaryGroupID) == "513":
                            memberOf.append("CN=Domain Users,CN=Users,DC=XXXXX,DC=XXX")
                    elif str(attribute["type"]) == "memberOf":
                        memberOf += [str(group) for group in attribute["vals"] if isinstance(group._value, bytes)]
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e!s}")
        if len(memberOf) > 0:
            context.log.success(f"User: {self.user} is member of following groups: ")
            for group in memberOf:
                # Split the string on the "," character to get a list of the group name and parent group names
                group_parts = group.split(",")

                # The group name is the first element in the list, so we can extract it by taking the first element of the list
                # and splitting it on the "=" character to get a list of the group name and its prefix (e.g., "CN")
                group_name = group_parts[0].split("=")[1]

                context.log.highlight(f"{group_name}")
