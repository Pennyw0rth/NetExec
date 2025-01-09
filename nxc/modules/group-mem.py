from impacket.ldap import ldapasn1 as ldapasn1_impacket
import sys


class NXCModule:
    """
    Module by CyberCelt: @Cyb3rC3lt

    Initial module:
      https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    """

    name = "group-mem"
    description = "Retrieves all the members within a Group"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    primaryGroupID = ""
    answers = []

    def options(self, context, module_options):
        """
        group-mem: Specify group-mem to call the module
        GROUP: Specify the GROUP option to query for that group's members
        Usage: nxc ldap $DC-IP -u Username -p Password -M group-mem -o GROUP="domain admins"
               nxc ldap $DC-IP -u Username -p Password -M group-mem -o GROUP="domain controllers"
        """
        self.GROUP = ""

        if "GROUP" in module_options:
            self.GROUP = module_options["GROUP"]
        else:
            context.log.error("GROUP option is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        # First look up the SID of the group passed in
        search_filter = "(&(objectCategory=group)(cn=" + self.GROUP + "))"
        attribute = "objectSid"

        search_result = do_search(self, context, connection, search_filter, attribute)
        # If no SID for the Group is returned exit the program
        if search_result is None:
            context.log.success('Unable to find any members of the "' + self.GROUP + '" group')
            return True

        # Convert the binary SID to a primaryGroupID string to be used further
        sid_string = connection.sid_to_str(search_result).split("-")
        self.primaryGroupID = sid_string[-1]

        # Look up the groups DN
        search_filter = "(&(objectCategory=group)(cn=" + self.GROUP + "))"
        attribute = "distinguishedName"
        distinguished_name = (do_search(self, context, connection, search_filter, attribute)).decode("utf-8")

        # Carry out the search
        search_filter = "(|(memberOf=" + distinguished_name + ")(primaryGroupID=" + self.primaryGroupID + "))"
        attribute = "sAMAccountName"
        search_result = do_search(self, context, connection, search_filter, attribute)

        if len(self.answers) > 0:
            context.log.success("Found the following members of the " + self.GROUP + " group:")
            for answer in self.answers:
                context.log.highlight(f"{answer[0]}")


# Carry out an LDAP search for the Group with the supplied Group name
def do_search(self, context, connection, searchFilter, attributeName):
    try:
        context.log.debug(f"Search Filter={searchFilter}")
        resp = connection.ldap_connection.search(searchFilter=searchFilter, attributes=[attributeName], sizeLimit=0)
        context.log.debug(f"Total number of records returned {len(resp)}")
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            attribute_value = ""
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == attributeName:
                        if attributeName in ["objectSid", "distinguishedName"]:
                            return bytes(attribute["vals"][0])
                        else:
                            attribute_value = str(attribute["vals"][0])
                    if attribute_value is not None:
                        self.answers.append([attribute_value])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e}")
    except Exception as e:
        context.log.debug(f"Exception: {e}")
        return False
