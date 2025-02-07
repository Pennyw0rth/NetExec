from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry

class NXCModule:

    name = "dump-computers"
    description = "Dumps all computers in the domain"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        dump-computers: Specify dump-computers to call the module
        Usage:
        
        >prints fqdn and version
        nxc ldap $DC-IP -u Username -p Password -M dump-computers
        
        >prints only netbios name
        nxc ldap $DC-IP -u Username -p Password -M dump-computers -o NETBIOS=True
        
        >prints fqdn and version, output to file
        nxc ldap $DC-IP -u Username -p Password -M dump-computers -o OUTPUT=<location>
        
        >prints only netbios name, output to file
        nxc ldap $DC-IP -u Username -p Password -M dump-computers -o OUTPUT=<location> -o NETBIOS=True
        
        """
        self.output_file = None
        self.netbios_only = False
        
        if "OUTPUT" in module_options:
            self.output_file = module_options["OUTPUT"]
        if "NETBIOS" in module_options and module_options["NETBIOS"].lower() == "true":
            self.netbios_only = True

    def on_login(self, context, connection):
        search_filter = "(objectCategory=computer)"
        
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
                if dns_host_name:
                    netbios_name = dns_host_name.split(".")[0]
                    answer = netbios_name if self.netbios_only else f"{dns_host_name} ({operating_system})"
                    answers.append(answer)
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e}")
        
        if len(answers) > 0:
            context.log.success("Found the following computers: ")
            for answer in answers:
                context.log.highlight(answer)
            
            if self.output_file:
                try:
                    with open(self.output_file, "w") as f:
                        f.write("\n".join(answers) + "\n")
                    context.log.success(f"Results saved to {self.output_file}")
                except Exception as e:
                    context.log.error(f"Failed to write to file {self.output_file}: {e}")
        else:
            context.log.success("No computers found in the domain.")
