from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Module by Shutdown and Podalirius
    Modified by @azoxlpf to handle null session errors and avoid IndexError when no LDAP results are returned.

    Initial module:
      https://github.com/ShutdownRepo/CrackMapExec-MachineAccountQuota

    Authors:
      Shutdown: @_nwodtuhs
      Podalirius: @podalirius_
    """

    def options(self, context, module_options):
        """No options available"""

    name = "maq"
    description = "Retrieves the MachineAccountQuota domain-level attribute"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota")

        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        context.log.highlight(f"MachineAccountQuota: {entries[0]['ms-DS-MachineAccountQuota']}")
