
class NXCModule:
    name = "runasppl"
    description = "Check if the registry value RunAsPPL is set or not"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """"""

    def on_admin_login(self, context, connection):
        command = r"reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ /v RunAsPPL"
        context.log.debug(f"Executing command: {command}")
        p = connection.execute(command, True)
        if "The system was unable to find the specified registry key or value" in p:
            context.log.debug("Unable to find RunAsPPL Registry Key")
        else:
            context.log.highlight(p)
