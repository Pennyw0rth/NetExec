import json
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get the scriptPath attribute of users

    Module by @wyndoo
    """
    name = "get-scriptpath"
    description = "Get the scriptPath attribute of all users."
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        FILTER        Apply the FILTER (grep-like) (default: '')
        OUTPUTFILE    Path to a file to save the results (default: None)
        """
        self.filter = ""
        self.outputfile = None

        if "FILTER" in module_options:
            self.filter = module_options["FILTER"]

        if "OUTPUTFILE" in module_options:
            self.outputfile = module_options["OUTPUTFILE"]

    def on_login(self, context, connection):
        # Building the search filter
        resp = connection.search(
            searchFilter="(scriptPath=*)",
            attributes=["sAMAccountName", "scriptPath"]
        )

        context.log.debug(f"Total of records returned {len(resp)}")
        answers = parse_result_attributes(resp)
        context.log.debug(f"Filtering for scriptPath containing: {self.filter}")
        filtered_answers = list(filter(lambda x: self.filter in x["scriptPath"], answers))

        if filtered_answers:
            context.log.success("Found the following attributes: ")
            for answer in filtered_answers:
                context.log.highlight(f"User: {answer['sAMAccountName']:<20} ScriptPath: {answer['scriptPath']}")

            # Save the results to a file
            if self.outputfile:
                self.save_to_file(context, filtered_answers)
        else:
            context.log.fail("No results found after filtering.")

    def save_to_file(self, context, answers):
        """Save the results to a JSON file."""
        try:
            # Format answers as a list of dictionaries for JSON output
            json_data = [{"sAMAccountName": answer["sAMAccountName"], "scriptPath": answer["scriptPath"]} for answer in answers]

            # Save the JSON data to the specified file
            with open(self.outputfile, "w") as f:
                json.dump(json_data, f, indent=4)
            context.log.success(f"Results successfully saved to {self.outputfile}")

        except Exception as e:
            context.log.error(f"Failed to save results to file: {e}")
