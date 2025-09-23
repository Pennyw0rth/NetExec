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

    @staticmethod
    def register_module_options(subparsers):
        return subparsers

    name = "maq"
    description = "Retrieves the MachineAccountQuota domain-level attribute"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context

    def on_login(self, connection):
        self.context.log.display("Getting the MachineAccountQuota")
        result = connection.search("(objectClass=*)", ["ms-DS-MachineAccountQuota"])
        try:
            maq = result[0]["attributes"][0]["vals"][0]
            self.context.log.highlight(f"MachineAccountQuota: {maq}")
        except PyAsn1Error:
            self.context.log.highlight("MachineAccountQuota: <not set>")
