from nxc.helpers.misc import CATEGORY
from nxc.helpers.bash import get_script


class NXCModule:
    name = "linux_session_enum"
    description = (
        "Enumerate interactive users currently logged into the remote Linux system"
    )
    supported_protocols = ["ssh"]
    category = CATEGORY.ENUMERATION
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No module options required."""

    def __init__(self):
        try:
            self.script = get_script("linux_session_enum/linux_session_enum.sh")
        except Exception:
            self.script = None
            return

    def on_login(self, context, connection):
        # Execute script
        output = connection.execute(self.script)
        # Display results
        if output is None:
            context.log.error("Command failed or returned no output.")
            return

        if not output.strip():
            context.log.display("No active session found.")
            return

        context.log.success("Active sessions:")
        for line in output.splitlines():
            context.log.highlight(line.strip())
