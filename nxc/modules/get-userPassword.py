from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
from nxc.logger import nxc_logger


class NXCModule:
    """
    Get userPassword attribute from all users in ldap
    Module by @SyzikSecu
    """

    name = "get-userPassword"
    description = "Get userPassword attribute from all users in ldap"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        """

    def on_login(self, context, connection):
        searchFilter = "(objectclass=user)"

        try:
            context.log.debug(f"Search Filter={searchFilter}")
            resp = connection.ldap_connection.search(
                searchFilter=searchFilter,
                attributes=["sAMAccountName", "userPassword"],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        answers = []
        context.log.debug(f"Total of records returned {len(resp)}")
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            sAMAccountName = ""
            userPassword = []
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "userPassword":
                        userPassword = [str(i) for i in attribute["vals"]]
                if sAMAccountName != "" and len(userPassword) > 0:
                    answers.append([sAMAccountName, userPassword])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e!s}")
        if len(answers) > 0:
            context.log.success("Found following users: ")
            for answer in answers:
                context.log.highlight(f"User: {answer[0]} userPassword: {answer[1]}")
        else:
            context.log.fail("No userPassword Found")
