import binascii


class MSSQLEXEC:
    def __init__(self, connection, logger):
        self.mssql_conn = connection
        self.logger = logger

    def execute(self, command):
        result = None
        xp_cmdshell_was_enabled = False

        try:
            xp_cmdshell_was_enabled = self.is_xp_cmdshell_enabled()
            if not xp_cmdshell_was_enabled:
                self.logger.debug("xp_cmdshell is disabled, attempting to enable it.")
                self.enable_xp_cmdshell()
            else:
                self.logger.debug("xp_cmdshell is already enabled.")

        except Exception as e:
            self.logger.error(f"Error when checking/enabling xp_cmdshell: {e}")

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

        try:
            if not xp_cmdshell_was_enabled:
                self.logger.debug("xp_cmdshell was not enabled originally, attempting to disable it.")
                self.disable_xp_cmdshell()
            else:
                self.logger.debug("xp_cmdshell was originally enabled, leaving it enabled.")
        except Exception as e:
            self.logger.error(f"[OPSEC] Error when attempting to disable xp_cmdshell: {e}")
        
        return result

    def is_xp_cmdshell_enabled(self):
        query = "EXEC sp_configure 'xp_cmdshell';"
        self.logger.debug(f"Checking if xp_cmdshell is enabled: {query}")
        result = self.mssql_conn.sql_query(query)
        # Assuming the query returns a list of dictionaries with 'config_value' as the key
        self.logger.debug(f"xp_cmdshell check result: {result}")
        if result and result[0]["config_value"] == 1:
            return True
        return False

    def enable_xp_cmdshell(self):
        query = "exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;"
        self.logger.debug(f"Executing query: {query}")
        self.mssql_conn.sql_query(query)

    def disable_xp_cmdshell(self):
        query = "exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;"
        self.logger.debug(f"Executing query: {query}")
        self.mssql_conn.sql_query(query)

    def enable_ole(self):
        query = "exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'Ole Automation Procedures', 1;RECONFIGURE;"
        self.logger.debug(f"Executing query: {query}")
        self.mssql_conn.sql_query(query)

    def disable_ole(self):
        query = "exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'Ole Automation Procedures', 0;RECONFIGURE;"
        self.logger.debug(f"Executing query: {query}")
        self.mssql_conn.sql_query(query)

    def put_file(self, data, remote):
        try:
            self.enable_ole()
            hexdata = data.hex()
            self.logger.debug(f"Hex data to write to file: {hexdata}")
            query = f"DECLARE @ob INT;EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT;EXEC sp_OASetProperty @ob, 'Type', 1;EXEC sp_OAMethod @ob, 'Open';EXEC sp_OAMethod @ob, 'Write', NULL, 0x{hexdata};EXEC sp_OAMethod @ob, 'SaveToFile', NULL, '{remote}', 2;EXEC sp_OAMethod @ob, 'Close';EXEC sp_OADestroy @ob;"
            self.logger.debug(f"Executing query: {query}")
            self.mssql_conn.sql_query(query)
            self.disable_ole()
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
