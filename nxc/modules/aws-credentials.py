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
                                Default: "'/home/' '/tmp/'"

        SEARCH_PATH_WIN		Windows locations where to search for aws credentials related files
                                Default: "'C:\\Users\\', 'C:\\ProgramData\\AWSCLI\\', 'C:\\Temp\\'"
        """
        if "SEARCH_PATH_LINUX" in module_options:
            self.search_path_linux = module_options["SEARCH_PATH_LINUX"]

        if "SEARCH_PATH_WIN" in module_options:
            self.search_path_win = module_options["SEARCH_PATH_WIN"]

    def on_login(self, context, connection):
        # search for aws_credentials-related files on linux systems
        if "ssh" in context.protocol:
            search_aws_creds_files_payload = f"find {self.search_path_linux} -type f  -name credentials -exec grep -l 'aws_' {{}} \\; 2>&1 | grep -v 'Permission denied$'"
            search_aws_creds_files_cmd = f'/bin/bash -c "{search_aws_creds_files_payload}"'
            output = connection.execute(search_aws_creds_files_cmd)
        else:
            # search for aws_credentials-related files on windows systems
            # we have to exclude "Application Data" as this creates an infinite recursion, see: https://www.reddit.com/r/PowerShell/comments/17pctnv/symbolic_link_application_data_in_appdatalocal/
            search_aws_creds_files_payload_win = f"Get-ChildItem -Path {self.search_path_win} -Recurse -Force -Include 'credentials' -ErrorAction SilentlyContinue | Where-Object {{ Select-String -Path $_.FullName -Pattern 'aws' -Quiet }} | Select-Object -ExpandProperty FullName"
            search_aws_creds_files_cmd_win = f'powershell.exe "{search_aws_creds_files_payload_win}"'
            output = connection.execute(search_aws_creds_files_cmd_win, True)

        if output:
            context.log.success("The following files were found:")
            for line in output.splitlines():
                context.log.highlight(line.rstrip())
