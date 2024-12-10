import binascii


class MSSQLEXEC:
    def __init__(self, connection, logger):
        self.mssql_conn = connection
        self.logger = logger

        # Store the original state of options that have to be enabled/disabled in order to restore them later
        self.backuped_options = {}

    def execute(self, command):
        result = None

        self.backup_and_enable("advanced options")
        self.backup_and_enable("xp_cmdshell")

        try:
            cmd = f"exec master..xp_cmdshell '{command}'"
            self.logger.debug(f"Attempting to execute query: {cmd}")
            result = self.mssql_conn.sql_query(cmd)
            self.logger.debug(f"Raw results from query: {result}")
            if result:
                result = "\n".join(line["output"] for line in result if line["output"] != "NULL")
                self.logger.debug(f"Concatenated result together for easier parsing: {result}")
                # if you prepend SilentlyContinue it will still output the error, but it will still continue on (so it's not silent...)
                if "Preparing modules for first use" in result and "Completed" not in result:
                    self.logger.error("Error when executing PowerShell (received 'preparing modules for first use'), try prepending $ProgressPreference = 'SilentlyContinue'; to your command")
        except Exception as e:
            self.logger.error(f"Error when attempting to execute command via xp_cmdshell: {e}")

        self.restore("xp_cmdshell")
        self.restore("advanced options")

        return result

    def restore(self, option):
        try:
            if not self.backuped_options[option]:
                self.logger.debug(f"Option '{option}' was not enabled originally, attempting to disable it.")
                query = f"EXEC master.dbo.sp_configure '{option}', 0;RECONFIGURE;"
                self.logger.debug(f"Executing query: {query}")
                self.mssql_conn.sql_query(query)
            else:
                self.logger.debug(f"Option '{option}' was originally enabled, leaving it enabled.")
        except Exception as e:
            self.logger.error(f"[OPSEC] Error when attempting to restore option '{option}': {e}")

    def backup_and_enable(self, option):
        try:
            self.backuped_options[option] = self.is_option_enabled("show advanced options")
            if not self.backuped_options[option]:
                self.logger.debug(f"Option '{option}' is disabled, attempting to enable it.")
                query = f"EXEC master.dbo.sp_configure '{option}', 1;RECONFIGURE;"
                self.logger.debug(f"Executing query: {query}")
                self.mssql_conn.sql_query(query)
            else:
                self.logger.debug(f"Option '{option}' is already enabled.")
        except Exception as e:
            self.logger.error(f"Error when checking/enabling option '{option}': {e}")

    def is_option_enabled(self, option):
        query = f"EXEC master.dbo.sp_configure '{option}';"
        self.logger.debug(f"Checking if {option} is enabled: {query}")
        result = self.mssql_conn.sql_query(query)
        # Assuming the query returns a list of dictionaries with 'config_value' as the key
        self.logger.debug(f"{option} check result: {result}")
        if result and result[0]["config_value"] == 1:
            return True
        return False

    def put_file(self, data, remote):
        try:
            self.backup_and_enable("advanced options")
            self.backup_and_enable("Ole Automation Procedures")
            hexdata = data.hex()
            self.logger.debug(f"Hex data to write to file: {hexdata}")
            query = f"DECLARE @ob INT;EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT;EXEC sp_OASetProperty @ob, 'Type', 1;EXEC sp_OAMethod @ob, 'Open';EXEC sp_OAMethod @ob, 'Write', NULL, 0x{hexdata};EXEC sp_OAMethod @ob, 'SaveToFile', NULL, '{remote}', 2;EXEC sp_OAMethod @ob, 'Close';EXEC sp_OADestroy @ob;"
            self.logger.debug(f"Executing query: {query}")
            self.mssql_conn.sql_query(query)
            self.restore("Ole Automation Procedures")
            self.restore("advanced options")
        except Exception as e:
            self.logger.debug(f"Error uploading via mssqlexec: {e}")

    def file_exists(self, remote):
        try:
            query = f"DECLARE @r INT; EXEC master.dbo.xp_fileexist '{remote}', @r OUTPUT; SELECT @r as n"
            self.logger.debug(f"Executing query: {query}")
            res = self.mssql_conn.batch(query)
            self.logger.debug(f"File check response: {res}")
            return res[0]["n"] == 1
        except Exception:
            return False

    def get_file(self, remote, local):
        try:
            query = f"SELECT * FROM OPENROWSET(BULK N'{remote}', SINGLE_BLOB) rs"
            self.logger.debug(f"Executing query: {query}")
            self.mssql_conn.sql_query(query)
            data = self.mssql_conn.rows
            self.logger.debug(f"Get file returned: {data}")
            with open(local, "wb+") as f:
                f.write(binascii.unhexlify(data[0]["BulkColumn"]))
        except Exception as e:
            self.logger.debug(f"Error downloading via mssqlexec: {e}")
