from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get the info field of users
    Module by @sepauli
    """
    name = "get-info-users"
    description = "Get the info field of all users. May contain password"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """FILTER    Apply the FILTER (grep-like) (default: '')"""
        self.FILTER = ""
        if "FILTER" in module_options:
            self.FILTER = module_options["FILTER"]

    def on_login(self, context, connection):
        # Building the search filter
        resp = connection.search(
            searchFilter="(info=*)",
            attributes=["sAMAccountName", "info"]
        )

        context.log.debug(f"Total of records returned {len(resp)}")
        resp_parsed = parse_result_attributes(resp)
        answers = [[x["sAMAccountName"], x["info"]] for x in resp_parsed]

        answers = self.filter_answer(context, answers)
        if answers:
            context.log.success("Found following users: ")
            for answer in answers:
                context.log.highlight(f"User: {answer[0]:<20} Info: {answer[1]}")

    def filter_answer(self, context, answers):
        # No option to filter
        if not self.FILTER:
            context.log.debug("No filter option enabled")
            return answers
        # Filter
        context.log.debug(f"Filter info field with: {self.FILTER}")
        return [answer for answer in answers if self.FILTER in answer[1]]
