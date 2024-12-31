import socket
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry
import sys


class NXCModule:
    """
    Module by CyberCelt: @Cyb3rC3lt

    Initial module:
      https://github.com/Cyb3rC3lt/CrackMapExec-Modules
    """

    name = "find-computer"
    description = "Finds computers in the domain via the provided text"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        find-computer: Specify find-computer to call the module
        TEXT: Specify the TEXT option to enter your text to search for
        Usage: nxc ldap $DC-IP -u Username -p Password -M find-computer -o TEXT="server"
               nxc ldap $DC-IP -u Username -p Password -M find-computer -o TEXT="SQL"
        """
        self.TEXT = ""

        if "TEXT" in module_options:
            self.TEXT = module_options["TEXT"]
        else:
            context.log.error("TEXT option is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        search_filter = f"(&(objectCategory=computer)(&(|(operatingSystem=*{self.TEXT}*))(name=*{self.TEXT}*)))"

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=["dNSHostName", "operatingSystem"], sizeLimit=0)
        except LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        answers = []
        context.log.debug(f"Total no. of records returned: {len(resp)}")
        for item in resp:
            if isinstance(item, SearchResultEntry) is not True:
                continue
            dns_host_name = ""
            operating_system = ""
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "dNSHostName":
                        dns_host_name = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "operatingSystem":
                        operating_system = attribute["vals"][0]
                if dns_host_name != "" and operating_system != "":
                    answers.append([dns_host_name, operating_system])
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e}")
        if len(answers) > 0:
            context.log.success("Found the following computers: ")
            for answer in answers:
                try:
                    ip = socket.gethostbyname(answer[0])
                    context.log.highlight(f"{answer[0]} ({answer[1]}) ({ip})")
                    context.log.debug("IP found")
                except socket.gaierror:
                    context.log.debug("Missing IP")
                    context.log.highlight(f"{answer[0]} ({answer[1]}) (No IP Found)")
        else:
            context.log.success(f"Unable to find any computers with the text {self.TEXT}")
