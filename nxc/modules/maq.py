from pyasn1.error import PyAsn1Error
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module by Shutdown and Podalirius

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
        result = connection.search("(objectClass=*)", ["ms-DS-MachineAccountQuota"])
        try:
            maq = result[0]["attributes"][0]["vals"][0]
            context.log.highlight(f"MachineAccountQuota: {maq}")
        except PyAsn1Error:
            context.log.highlight("MachineAccountQuota: <not set>")
