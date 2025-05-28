

class NXCModule:
    """
    Extract all Trust Relationships, Trusting Direction, and Trust Transitivity
    Module by Brandon Fisher @shad0wcntr0ller
    """

    name = "enum_trusts"
    description = "[REMOVED] Extract all Trust Relationships, Trusting Direction, and Trust Transitivity"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        context.log.fail("[REMOVED] This module moved to the --dc-list LDAP flag.")
