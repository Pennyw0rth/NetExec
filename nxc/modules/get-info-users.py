from impacket.ldap import ldap as ldap_impacket
from nxc.logger import nxc_logger
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get the info field of users
    Module by @sepauli
    """

    name = "get-info-users"
    description = "Get the info field of the users. May contained password"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """FILTER    Apply the FILTER (grep-like) (default: '')"""
        self.FILTER = ""
        if "FILTER" in module_options:
            self.FILTER = module_options["FILTER"]

    def on_login(self, context, connection):
        # Building the search filter
        searchFilter = "(objectclass=user)"

        try:
            context.log.debug(f"Search Filter={searchFilter}")
            resp = connection.ldap_connection.search(
                searchFilter=searchFilter,
                attributes=["sAMAccountName", "info"],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        context.log.debug(f"Total of records returned {len(resp)}")
        resp_parsed = parse_result_attributes(resp)
        answers = [[x["sAMAccountName"], x.get("info")] for x in resp_parsed if x.get("info")]

        answers = self.filter_answer(context, answers)
        if len(answers) > 0:
            context.log.success("Found following users: ")
            for answer in answers:
                context.log.highlight(f"User: {answer[0]} Info: {answer[1]}")

    def filter_answer(self, context, answers):
        # No option to filter
        if self.FILTER == "":
            context.log.debug("No filter option enabled")
            return answers
        
        answersFiltered = []
        context.log.debug("Prepare to filter")
        if len(answers) > 0:
            for answer in answers:
                conditionFilter = False
                info = str(answer[1])
                # Filter
                if self.FILTER != "":
                    conditionFilter = False
                    if self.FILTER in info:
                        conditionFilter = True

                if conditionFilter:
                    context.log.highlight(f"'{self.FILTER}' found in Info: '{info}'")
                elif self.FILTER == "":
                    answersFiltered.append([answer[0], info])

        return answersFiltered