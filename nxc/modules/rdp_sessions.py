from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enumerate active and disconnected RDP sessions
    Module by NetExec Community
    """

    name = "rdp_sessions"
    description = "Enumerate active and disconnected RDP sessions on target system"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ACTIVE      Show only active sessions (default: False)
        """
        self.active_only = "ACTIVE" in module_options

    def on_admin_login(self, context, connection):
        """Enumerate RDP sessions"""
        try:
            context.log.display("Enumerating RDP sessions...")
            self._enumerate_rdp_sessions(context, connection)
                
        except Exception as e:
            context.log.fail(f"Error enumerating RDP sessions: {e}")
            context.log.debug(f"Exception: {e}")

    def _enumerate_rdp_sessions(self, context, connection):
        """Enumerate RDP sessions using PowerShell/qwinsta"""
        
        # Try using qwinsta (query session) command
        ps_command = """
        $sessions = quser 2>&1
        if ($LASTEXITCODE -eq 0) {
            $sessions
        } else {
            # Fallback to query session
            query session 2>&1
        }
        """
        
        try:
            output = connection.ps_execute(ps_command, get_output=True)
            
            if output:
                context.log.success("RDP Sessions found:")
                session_count = 0
                active_count = 0
                disconnected_count = 0
                
                for line in output:
                    if not line or line.strip() == "":
                        continue
                    
                    # Skip header lines
                    if "USERNAME" in line.upper() or "SESSIONNAME" in line.upper():
                        context.log.display(line)
                        continue
                    
                    # Parse session information
                    # Format varies but typically: USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME
                    parts = line.split()
                    
                    if len(parts) >= 3:
                        # Determine if session is active or disconnected
                        is_active = "Active" in line or "Activo" in line
                        is_disconnected = "Disc" in line or "Desconectado" in line
                        
                        # Filter if only active sessions requested
                        if self.active_only and not is_active:
                            continue
                        
                        # Highlight based on session state
                        if is_active:
                            context.log.highlight(line)
                            active_count += 1
                        elif is_disconnected:
                            context.log.success(line)
                            disconnected_count += 1
                        else:
                            context.log.display(line)
                        
                        session_count += 1
                
                # Summary
                context.log.display("")
                context.log.success(f"Total sessions: {session_count}")
                if active_count > 0:
                    context.log.highlight(f"Active sessions: {active_count}")
                if disconnected_count > 0:
                    context.log.success(f"Disconnected sessions: {disconnected_count}")
                    
            else:
                context.log.display("No RDP sessions found or access denied")
                
        except Exception as e:
            context.log.fail(f"Error querying sessions: {e}")
            # Try alternative method using WMI if available
            self._enumerate_rdp_sessions_wmi(context, connection)

    def _enumerate_rdp_sessions_wmi(self, context, connection):
        """Enumerate RDP sessions using WMI Win32_LogonSession"""
        context.log.display("Trying WMI enumeration method...")
        
        ps_command = """
        Get-WmiObject -Class Win32_LogonSession | Where-Object {$_.LogonType -eq 10} | ForEach-Object {
            $logonId = $_.LogonId
            $user = Get-WmiObject -Class Win32_LoggedOnUser | Where-Object {
                $_.Dependent -like "*LogonId=`"$logonId`"*"
            } | Select-Object -First 1
            
            if ($user) {
                $username = $user.Antecedent -replace '.*Name="([^"]+)".*','$1'
                $domain = $user.Antecedent -replace '.*Domain="([^"]+)".*','$1'
                $startTime = [Management.ManagementDateTimeConverter]::ToDateTime($_.StartTime)
                
                "$domain\\$username|RDP|$startTime|$logonId"
            }
        }
        """
        
        try:
            output = connection.ps_execute(ps_command, get_output=True)
            
            if output:
                context.log.success("RDP Logon Sessions (via WMI):")
                
                for line in output:
                    if not line or line.strip() == "" or "|" not in line:
                        continue
                    
                    try:
                        parts = line.split("|")
                        if len(parts) >= 4:
                            user, logon_type, start_time, logon_id = parts[0], parts[1], parts[2], parts[3]
                            context.log.highlight(f"User: {user}")
                            context.log.display(f"  Type: {logon_type}")
                            context.log.display(f"  Start Time: {start_time}")
                            context.log.display(f"  Logon ID: {logon_id}")
                    except Exception as e:
                        context.log.debug(f"Error parsing session line: {e}")
            else:
                context.log.display("No RDP sessions found via WMI")
                
        except Exception as e:
            context.log.fail(f"Error with WMI enumeration: {e}")
