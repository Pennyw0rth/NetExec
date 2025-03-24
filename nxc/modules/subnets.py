from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPSearchError
import sys


def search_res_entry_to_dict(results):
    data = {}
    for attr in results["attributes"]:
        key = str(attr["type"])
        value = str(attr["vals"][0])
        data[key] = value
    return data


class NXCModule:
    """
    Retrieves the different Sites and Subnets of an Active Directory

    Authors:
      Podalirius: @podalirius_
    """

    def options(self, context, module_options):
        """Showservers    Toggle printing of servers (default: true)"""
        self.showservers = True
        self.base_dn = None

        if module_options and "SHOWSERVERS" in module_options:
            if module_options["SHOWSERVERS"].lower() == "true" or module_options["SHOWSERVERS"] == "1":
                self.showservers = True
            elif module_options["SHOWSERVERS"].lower() == "false" or module_options["SHOWSERVERS"] == "0":
                self.showservers = False
            else:
                print("Could not parse showservers option.")
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]

    name = "subnets"
    description = "Retrieves the different Sites and Subnets of an Active Directory"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def on_login(self, context, connection):
        dn = connection.ldap_connection._baseDN if self.base_dn is None else self.base_dn

        context.log.display("Getting the Sites and Subnets from domain")

        try:
            list_sites = connection.ldap_connection.search(
                searchBase=f"CN=Configuration,{dn}",
                searchFilter="(objectClass=site)",
                attributes=["distinguishedName", "name", "description"],
                sizeLimit=999,
            )
        except LDAPSearchError as e:
            context.log.fail(str(e))
            sys.exit()

        for site in list_sites:
            if isinstance(site, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            site = search_res_entry_to_dict(site)
            site_dn = site["distinguishedName"]
            site_name = site["name"]
            site_description = ""
            if "description" in site:
                site_description = site["description"]

            # Getting subnets of this site
            list_subnets = connection.ldap_connection.search(
                searchBase=f"CN=Sites,CN=Configuration,{dn}",
                searchFilter=f"(siteObject={site_dn})",
                attributes=["distinguishedName", "name"],
                sizeLimit=999,
            )
            if len([subnet for subnet in list_subnets if isinstance(subnet, ldapasn1_impacket.SearchResultEntry)]) == 0:
                context.log.highlight(f'Site "{site_name}"')
            else:
                for subnet in list_subnets:
                    if isinstance(subnet, ldapasn1_impacket.SearchResultEntry) is not True:
                        continue
                    subnet = search_res_entry_to_dict(subnet)
                    subnet["distinguishedName"]
                    subnet_name = subnet["name"]

                    if self.showservers:
                        # Getting machines in these subnets
                        list_servers = connection.ldap_connection.search(
                            searchBase=site_dn,
                            searchFilter="(objectClass=server)",
                            attributes=["cn"],
                            sizeLimit=999,
                        )
                        if len([server for server in list_servers if isinstance(server, ldapasn1_impacket.SearchResultEntry)]) == 0:
                            if len(site_description) != 0:
                                context.log.highlight(f'Site "{site_name}" (Subnet:{subnet_name}) (description:"{site_description}")')
                            else:
                                context.log.highlight(f'Site "{site_name}" (Subnet:{subnet_name})')
                        else:
                            for server in list_servers:
                                if isinstance(server, ldapasn1_impacket.SearchResultEntry) is not True:
                                    continue
                                server = search_res_entry_to_dict(server)["cn"]
                                if len(site_description) != 0:
                                    context.log.highlight(f"Site: '{site_name}' (Subnet:{subnet_name}) (description:'{site_description}') (Server:'{server}')")
                                else:
                                    context.log.highlight(f'Site "{site_name}" (Subnet:{subnet_name}) (Server:{server})')
                    else:
                        if len(site_description) != 0:
                            context.log.highlight(f'Site "{site_name}" (Subnet:{subnet_name}) (description:"{site_description}")')
                        else:
                            context.log.highlight(f'Site "{site_name}" (Subnet:{subnet_name})')
