from impacket.ldap import ldap as ldap_impacket
import re
from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get description of users
    Module by @nodauf
    """

    name = "get-desc-users"
    description = "Get description of the users. May contain password"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        FILTER    Apply the FILTER (grep-like) (default: '')
        PASSWORDPOLICY    Is the windows password policy enabled ? (default: False)
        MINLENGTH    Minimum password length to match, only used if PASSWORDPOLICY is True (default: 6)
        """
        self.FILTER = ""
        self.MINLENGTH = "6"
        self.PASSWORDPOLICY = False
        if "FILTER" in module_options:
            self.FILTER = module_options["FILTER"]
        if "MINLENGTH" in module_options:
            self.MINLENGTH = module_options["MINLENGTH"]
        if "PASSWORDPOLICY" in module_options:
            self.PASSWORDPOLICY = True
            self.regex = re.compile(r"((?=[^ ]*[A-Z])(?=[^ ]*[a-z])(?=[^ ]*\d)|(?=[^ ]*[a-z])(?=[^ ]*\d)(?=[^ ]*[^\w \n])|(?=[^ ]*[A-Z])(?=[^ ]*\d)(?=[^ ]*[^\w \n])|(?=[^ ]*[A-Z])(?=[^ ]*[a-z])(?=[^ ]*[^\w \n]))[^ \n]{" + self.MINLENGTH + ",}$")  # Credit : https://stackoverflow.com/questions/31191248/regex-password-must-have-at-least-3-of-the-4-of-the-following

    def on_login(self, context, connection):
        """Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection"""
        # Building the search filter
        searchFilter = "(objectclass=user)"

        try:
            context.log.debug(f"Search Filter={searchFilter}")
            resp = connection.ldap_connection.search(
                searchFilter=searchFilter,
                attributes=["sAMAccountName", "description"],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        context.log.debug(f"Total of records returned {len(resp)}")
        resp_parsed = parse_result_attributes(resp)
        answers = [[x["sAMAccountName"], x.get("description")] for x in resp_parsed if x.get("description")]

        answers = self.filter_answer(context, answers)
        if len(answers) > 0:
            context.log.success("Found following users: ")
            for answer in answers:
                context.log.highlight(f"User: {answer[0]} description: {answer[1]}")

    def filter_answer(self, context, answers):
        # No option to filter
        if self.FILTER == "" and not self.PASSWORDPOLICY:
            context.log.debug("No filter option enabled")
            return answers
        answersFiltered = []
        context.log.debug("Prepare to filter")
        if len(answers) > 0:
            for answer in answers:
                conditionFilter = False
                description = str(answer[1])
                # Filter
                if self.FILTER != "":
                    conditionFilter = False
                    if self.FILTER in description:
                        conditionFilter = True

                # Password policy
                if self.PASSWORDPOLICY:
                    conditionPasswordPolicy = False
                    if self.regex.search(description):
                        conditionPasswordPolicy = True

                if conditionFilter and not self.PASSWORDPOLICY:
                    context.log.highlight(f"'{self.FILTER}' found in description: '{description}'")
                elif (self.FILTER == "" and (conditionPasswordPolicy == self.PASSWORDPOLICY)):
                    answersFiltered.append([answer[0], description])
                elif (self.FILTER != "" and conditionFilter) and (conditionPasswordPolicy == self.PASSWORDPOLICY):
                    context.log.highlight(f"'{self.FILTER}' found in user: '{answer[0]}' description: '{description}'")

        return answersFiltered
