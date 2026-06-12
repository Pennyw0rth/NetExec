class MSSQLEXEC:
    def __init__(self, mssql):
        self.mssql = mssql
        self.mssql_conn = mssql.conn
        self.logger = mssql.logger

    def execute(self, command, get_output, clr_assembly=None):
        result = ""

        self.mssql.backup_and_enable("advanced options")
        self.mssql.backup_and_enable("xp_cmdshell")

        try:
            cmd = f"exec master..xp_cmdshell '{command}'"
            self.logger.debug(f"Attempting to execute query: {cmd}")
            raw = self.mssql_conn.sql_query(cmd)
            self.logger.debug(f"Raw results from query: {raw}")
            if raw:
                result = "\n".join(line["output"] for line in raw if line["output"] != "NULL")
                self.logger.debug(f"Concatenated result together for easier parsing: {result}")
                # if you prepend SilentlyContinue it will still output the error, but it will still continue on (so it's not silent...)
                if "Preparing modules for first use" in result and "Completed" not in result:
                    self.logger.error("Error when executing PowerShell (received 'preparing modules for first use'), try prepending $ProgressPreference = 'SilentlyContinue'; to your command")
        except Exception as e:
            self.logger.error(f"Error when attempting to execute command via xp_cmdshell: {e}")

        self.mssql.restore("xp_cmdshell")
        self.mssql.restore("advanced options")

        return result
