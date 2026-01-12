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
        FILTER    Apply the FILTER (grep-like) (default: '')
        OUTPUTFILE    Path to a file to save the results (default: None)
        """
        self.FILTER = ""
        self.OUTPUTFILE = None
        
        if "FILTER" in module_options:
            self.FILTER = module_options["FILTER"]
        
        if "OUTPUTFILE" in module_options:
            self.OUTPUTFILE = module_options["OUTPUTFILE"]

    def on_login(self, context, connection):
        # Building the search filter
        resp = connection.search(
            searchFilter="(scriptPath=*)",
            attributes=["sAMAccountName", "scriptPath"]
        )

        context.log.debug(f"Total of records returned {len(resp)}")
        resp_parsed = parse_result_attributes(resp)
        answers = [[x["sAMAccountName"], x["scriptPath"]] for x in resp_parsed]

        answers = self.filter_answer(context, answers)

        if answers:
            context.log.success("Found the following attributes: ")
            for answer in answers:
                context.log.highlight(f"User: {answer[0]:<20} ScriptPath: {answer[1]}")

            # Save the results to a file
            if self.OUTPUTFILE:
                self.save_to_file(context, answers)
        else:
            context.log.warning("No results found after filtering.")

    def filter_answer(self, context, answers):
       # No filter
        if not self.FILTER:
            context.log.debug("No filter option enabled")
            return answers
        # Filter
        context.log.debug(f"Filter info field with: {self.FILTER}")
        return [answer for answer in answers if self.FILTER in answer[0]] 

    def save_to_file(self, context, answers):
        """Save the results to a JSON file."""
        try:
            # Format answers as a list of dictionaries for JSON output
            json_data = [{"sAMAccountName": answer[0], "scriptPath": answer[1]} for answer in answers]

            # Save the JSON data to the specified file
            with open(self.OUTPUTFILE, "w") as f:
                json.dump(json_data, f, indent=4)
            context.log.success(f"Results successfully saved to {self.OUTPUTFILE}")
        
        except Exception as e:
            context.log.error(f"Failed to save results to file: {e}")
