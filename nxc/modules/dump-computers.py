from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    name = "dump-computers"
    description = "Dumps FQDN and OS of all computers in the domain"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        TYPE        Only dump NETBIOS or FQDN instead of 'FQDN (OS Version)'
        OUTPUT      Output to file in addition to printing to console

        Examples
        --------
        netexec ldap $DC-IP -u $username -p $password -M dump-computers
        netexec ldap $DC-IP -u $username -p $password -M dump-computers -o TYPE=netbios
        netexec ldap $DC-IP -u $username -p $password -M dump-computers -o TYPE=fqdn
        netexec ldap $DC-IP -u $username -p $password -M dump-computers -o TYPE=netbios OUTPUT=<location>
        """
        self.output_file = None
        self.netbios_only = False
        self.fqdn_only = False

        if "OUTPUT" in module_options:
            self.output_file = module_options["OUTPUT"]
        if "TYPE" in module_options:
            if module_options["TYPE"].lower() == "netbios":
                self.netbios_only = True
            elif module_options["TYPE"].lower() == "fqdn":
                self.fqdn_only = True

    def on_login(self, context, connection):
        resp = connection.search(
            searchFilter="(objectCategory=computer)",
            attributes=["dNSHostName", "operatingSystem"]
        )
        resp_parsed = parse_result_attributes(resp)

        answers = []
        context.log.debug(f"Total number of records returned: {len(resp_parsed)}")

        for item in resp_parsed:
            dns_host_name = item.get("dNSHostName")
            operating_system = item.get("operatingSystem", "Unknown OS")
            if not dns_host_name:
                context.log.debug(f"Skipping computer without dNSHostName: {item.get('cn', '<unknown>')}")
                continue

            if self.netbios_only:
                netbios_name = dns_host_name.split(".")[0]
                answer = netbios_name
            elif self.fqdn_only:
                answer = dns_host_name
            else:
                answer = f"{dns_host_name} ({operating_system})"
            answers.append(answer)

        context.log.success("Found the following computers:")
        for answer in answers:
            context.log.highlight(answer)

        if self.output_file:
            try:
                with open(self.output_file, "w") as f:
                    f.write("\n".join(answers) + "\n")
                context.log.success(f"Results saved to {self.output_file}")
            except Exception as e:
                context.log.error(f"Failed to write to file {self.output_file}: {e}")
