class NXCModule:
    name = "coerce_plus"
    description = "[REMOVED] Module to check if the Target is vulnerable to any coerce vulns. Set LISTENER IP for coercion."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.listener = None

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        context.log.fail('[REMOVED] This module moved to the new module "coerce_plus"')
        return