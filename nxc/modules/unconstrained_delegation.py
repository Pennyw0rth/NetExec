from nxc.parsers.ldap_results import parse_result_attributes
from impacket.dcerpc.v5.samr import UF_TRUSTED_FOR_DELEGATION

class NXCModule:
    """
    Module by Bernardo Rodrigues
    """
    name = "unconstrained_delegation"
    description = "Enumerate machines with Unconstrained Delegation (enabled for delegation but lacking services, suggesting a security risk)"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        context.log.display("Searching for machines with Unconstrained Delegation...")

        search_filter = f"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_FOR_DELEGATION})(!(msDS-AllowedToDelegateTo=*))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"

        try:

            results_raw = connection.ldap_connection.search(
                searchBase=connection.baseDN,
                searchFilter=search_filter,
                attributes=["sAMAccountName", "dNSHostName"],
                sizeLimit=0
            )


            results_parsed = parse_result_attributes(results_raw)

            context.log.display(f"Search Finished. {len(results_parsed)} results found and processed.")


            found_machines = []
            for entry in results_parsed:

                sam_account_name = entry.get('sAMAccountName', 'N/A')
                dns_hostname = entry.get('dNSHostName', 'N/A')

                if sam_account_name != 'N/A':
                    found_machines.append(f"{sam_account_name} ({dns_hostname})")


            if found_machines:
                context.log.success("Machines with Unconstrained Delegation found:")
                for machine in found_machines:
                    context.log.highlight(f"  - {machine}")
            else:
                context.log.display("Machines with Unconstrained Delegation not found")

        except Exception as e:
            context.log.error(f"Error ({type(e).__name__}): {e}")
