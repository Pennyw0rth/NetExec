from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enumerate Windows startup items and autorun entries
    Module by NetExec Community
    """

    name = "startup_items"
    description = "Enumerate startup programs, services, and autorun registry entries"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        REGISTRY    Include registry autorun entries (default: True)
        STARTUP     Include startup folder items (default: True)
        SERVICES    Include services set to auto-start (default: False)
        """
        self.check_registry = "REGISTRY" not in module_options or module_options["REGISTRY"].lower() != "false"
        self.check_startup = "STARTUP" not in module_options or module_options["STARTUP"].lower() != "false"
        self.check_services = "SERVICES" in module_options and module_options["SERVICES"].lower() == "true"

    def on_admin_login(self, context, connection):
        """Enumerate startup items"""
        try:
            context.log.display("Enumerating startup items and autorun entries...")
            
            if self.check_registry:
                self._enumerate_registry_autoruns(context, connection)
            
            if self.check_startup:
                self._enumerate_startup_folders(context, connection)
            
            if self.check_services:
                self._enumerate_autostart_services(context, connection)
                
        except Exception as e:
            context.log.fail(f"Error enumerating startup items: {e}")
            context.log.debug(f"Exception: {e}")

    def _enumerate_registry_autoruns(self, context, connection):
        """Enumerate common autorun registry keys"""
        context.log.display("Checking registry autorun entries...")
        
        ps_command = """
        $keys = @(
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        )
        
        foreach ($key in $keys) {
            if (Test-Path $key) {
                $items = Get-ItemProperty $key -ErrorAction SilentlyContinue
                if ($items) {
                    Write-Output "KEY:$key"
                    $items.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object {
                        Write-Output "  $($_.Name) = $($_.Value)"
                    }
                }
            }
        }
        """
        
        try:
            output = connection.ps_execute(ps_command, get_output=True)
            
            if output:
                current_key = None
                found_items = 0
                
                for line in output:
                    if not line or line.strip() == "":
                        continue
                    
                    if line.startswith("KEY:"):
                        current_key = line[4:]
                        context.log.highlight(f"Registry: {current_key}")
                    elif line.strip().startswith("  "):
                        context.log.success(line.strip())
                        found_items += 1
                
                if found_items > 0:
                    context.log.success(f"Found {found_items} registry autorun entries")
                else:
                    context.log.display("No registry autorun entries found")
            else:
                context.log.display("No registry autorun entries found or access denied")
                
        except Exception as e:
            context.log.fail(f"Error checking registry autoruns: {e}")

    def _enumerate_startup_folders(self, context, connection):
        """Enumerate startup folder contents"""
        context.log.display("Checking startup folders...")
        
        ps_command = """
        $startupPaths = @(
            "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        )
        
        foreach ($path in $startupPaths) {
            if (Test-Path $path) {
                $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                if ($items) {
                    Write-Output "FOLDER:$path"
                    foreach ($item in $items) {
                        Write-Output "  $($item.Name)"
                    }
                }
            }
        }
        """
        
        try:
            output = connection.ps_execute(ps_command, get_output=True)
            
            if output:
                current_folder = None
                found_items = 0
                
                for line in output:
                    if not line or line.strip() == "":
                        continue
                    
                    if line.startswith("FOLDER:"):
                        current_folder = line[7:]
                        context.log.highlight(f"Startup Folder: {current_folder}")
                    elif line.strip().startswith("  "):
                        context.log.success(line.strip())
                        found_items += 1
                
                if found_items > 0:
                    context.log.success(f"Found {found_items} startup folder items")
                else:
                    context.log.display("No startup folder items found")
            else:
                context.log.display("No startup folder items found")
                
        except Exception as e:
            context.log.fail(f"Error checking startup folders: {e}")

    def _enumerate_autostart_services(self, context, connection):
        """Enumerate services set to automatically start"""
        context.log.display("Checking auto-start services...")
        
        ps_command = """
        Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | 
        Select-Object Name, DisplayName, Status | 
        ForEach-Object {
            "$($_.Name)|$($_.DisplayName)|$($_.Status)"
        }
        """
        
        try:
            output = connection.ps_execute(ps_command, get_output=True)
            
            if output:
                context.log.highlight("Auto-start Services:")
                service_count = 0
                
                for line in output:
                    if not line or line.strip() == "" or "|" not in line:
                        continue
                    
                    try:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            name, display_name, status = parts[0], parts[1], parts[2]
                            context.log.display(f"  {name:<30} {display_name:<40} [{status}]")
                            service_count += 1
                    except Exception as e:
                        context.log.debug(f"Error parsing service line: {e}")
                
                context.log.success(f"Found {service_count} auto-start services")
            else:
                context.log.display("No auto-start services found or access denied")
                
        except Exception as e:
            context.log.fail(f"Error checking auto-start services: {e}")
