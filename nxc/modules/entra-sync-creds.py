
class NXCModule:
    """
    Example:
    -------
    Module by @yomama
    """

    name = "entra-sync-creds"
    description = "Extract Entra ID sync credentials from the target host"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """Required.
        Module options get parsed here. Additionally, put the modules usage here as well
        """

    def on_admin_login(self, context, connection):
        self.context = context
