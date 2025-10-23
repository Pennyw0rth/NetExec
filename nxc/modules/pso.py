from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Initial FGPP/PSO script written by @n00py: https://github.com/n00py/GetFGPP

    Module by @_sandw1ch
    """
    name = "pso"
    description = "Module to get the Fine Grained Password Policy/PSOs"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """No options available."""

    def on_login(self, context, connection):
        context.log.fail("[REMOVED] This module moved to the core option --pso")
