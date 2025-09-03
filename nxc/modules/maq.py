from pyasn1.error import PyAsn1Error
from nxc.helpers.misc import CATEGORY


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
         try:
             result = connection.search("(objectClass=*)", ["ms-DS-MachineAccountQuota"])
         except Exception as e:
             context.log.fail(f"LDAP search failed: {e}")
             return

         if not result:
             context.log.fail("No LDAP entries returned.")
             return

         try:
             maq = result[0]["attributes"][0]["vals"][0]
             context.log.highlight(f"MachineAccountQuota: {maq}")
         except (IndexError, KeyError, PyAsn1Error):
             context.log.highlight("MachineAccountQuota: <not set>")
