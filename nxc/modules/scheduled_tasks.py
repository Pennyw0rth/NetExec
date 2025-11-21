from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enumerate Windows scheduled tasks on remote system
    Module by NetExec Community
    """

    name = "scheduled_tasks"
    description = "Enumerate Windows scheduled tasks and their configurations"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ENABLED     Only show enabled tasks (default: False)
        USER        Filter tasks by username
        """
        self.enabled_only = "ENABLED" in module_options
        self.filter_user = module_options.get("USER", None)

    def on_admin_login(self, context, connection):
        """Enumerate scheduled tasks via PowerShell or WMI"""
        try:
            if hasattr(connection, 'wmi'):
                self._enumerate_via_wmi(context, connection)
            else:
                self._enumerate_via_powershell(context, connection)
                
        except Exception as e:
            context.log.fail(f"Error enumerating scheduled tasks: {e}")
            context.log.debug(f"Exception: {e}")

    def _enumerate_via_powershell(self, context, connection):
        """Enumerate using PowerShell"""
        context.log.display("Enumerating scheduled tasks via PowerShell...")
        
        # PowerShell command to get scheduled tasks
        ps_command = """
        Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object {
            $task = $_
            $info = Get-ScheduledTaskInfo $task.TaskName -ErrorAction SilentlyContinue
            if ($info) {
                "$($task.TaskName)|$($task.State)|$($info.LastRunTime)|$($info.NextRunTime)|$($task.Principal.UserId)"
            }
        }
        """
        
        if self.enabled_only:
            ps_command = ps_command.replace("$_.State -ne 'Disabled'", "$_.State -eq 'Ready'")
        
        try:
            output = connection.ps_execute(ps_command, get_output=True)
            
            if output:
                context.log.success("Found scheduled tasks:")
                task_count = 0
                
                for line in output:
                    if not line or line.strip() == "":
                        continue
                    
                    try:
                        parts = line.split("|")
                        if len(parts) >= 5:
                            task_name, state, last_run, next_run, user = parts[0], parts[1], parts[2], parts[3], parts[4]
                            
                            # Filter by user if specified
                            if self.filter_user and self.filter_user.lower() not in user.lower():
                                continue
                            
                            context.log.highlight(f"Task: {task_name}")
                            context.log.display(f"  State: {state}")
                            context.log.display(f"  User: {user}")
                            context.log.display(f"  Last Run: {last_run}")
                            context.log.display(f"  Next Run: {next_run}")
                            task_count += 1
                    except Exception as e:
                        context.log.debug(f"Error parsing task line: {e}")
                
                context.log.success(f"Total tasks found: {task_count}")
            else:
                context.log.display("No scheduled tasks found or access denied")
                
        except Exception as e:
            context.log.fail(f"Error executing PowerShell command: {e}")

    def _enumerate_via_wmi(self, context, connection):
        """Enumerate using WMI (Windows Management Instrumentation)"""
        context.log.display("Enumerating scheduled tasks via WMI...")
        
        try:
            # Note: WMI doesn't have a direct scheduled tasks class in older Windows
            # We'll use a PowerShell approach through WMI execution
            ps_script = "Get-ScheduledTask | Select-Object TaskName, State | ConvertTo-Json"
            
            output = connection.wmi(
                f'SELECT * FROM Win32_Process WHERE Name="powershell.exe"',
                "root\\cimv2"
            )
            
            context.log.display("WMI enumeration requires PowerShell execution capability")
            # Fallback to PowerShell method
            self._enumerate_via_powershell(context, connection)
            
        except Exception as e:
            context.log.fail(f"Error with WMI enumeration: {e}")
            # Fallback to PowerShell
            self._enumerate_via_powershell(context, connection)
