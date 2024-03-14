import binascii


class MSSQLEXEC:
    def __init__(self, connection, logger):
        self.mssql_conn = connection
        self.logger = logger
        self.outputBuffer = []

    def execute(self, command, output=False):
        try:
            self.enable_xp_cmdshell()
        except Exception as e:
            self.logger.error(f"Error when attempting to enable x_cmdshell: {e}")

        try:
            result = self.mssql_conn.sql_query(f"exec master..xp_cmdshell '{command}'")
        except Exception as e:
            self.logger.error(f"Error when attempting to execute command via xp_cmdshell: {e}")

        try:
            self.disable_xp_cmdshell()
        except Exception as e:
            self.logger.error(f"[OPSEC] Error when attempting to disable xp_cmdshell: {e}")

        if output:
            self.logger.debug(f"SQL Query Result: {result}")
            for row in result:
                if row["output"] == "NULL":
                    continue
                self.outputBuffer.append(row["output"])
        else:
            self.logger.info("Output set to disabled")

        return self.outputBuffer

    def enable_xp_cmdshell(self):
        self.mssql_conn.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")

    def disable_xp_cmdshell(self):
        self.mssql_conn.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;")

    def enable_ole(self):
        self.mssql_conn.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'Ole Automation Procedures', 1;RECONFIGURE;")

    def disable_ole(self):
        self.mssql_conn.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'Ole Automation Procedures', 0;RECONFIGURE;")

    def put_file(self, data, remote):
        try:
            self.enable_ole()
            hexdata = data.hex()
            self.mssql_conn.sql_query(f"DECLARE @ob INT;EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT;EXEC sp_OASetProperty @ob, 'Type', 1;EXEC sp_OAMethod @ob, 'Open';EXEC sp_OAMethod @ob, 'Write', NULL, 0x{hexdata};EXEC sp_OAMethod @ob, 'SaveToFile', NULL, '{remote}', 2;EXEC sp_OAMethod @ob, 'Close';EXEC sp_OADestroy @ob;")
            self.disable_ole()
        except Exception as e:
            self.logger.debug(f"Error uploading via mssqlexec: {e}")

    def file_exists(self, remote):
        try:
            res = self.mssql_conn.batch(f"DECLARE @r INT; EXEC master.dbo.xp_fileexist '{remote}', @r OUTPUT; SELECT @r as n")[0]["n"]
            return res == 1
        except Exception:
            return False

    def get_file(self, remote, local):
        try:
            self.mssql_conn.sql_query(f"SELECT * FROM OPENROWSET(BULK N'{remote}', SINGLE_BLOB) rs")
            data = self.mssql_conn.rows[0]["BulkColumn"]

            with open(local, "wb+") as f:
                f.write(binascii.unhexlify(data))

        except Exception as e:
            self.logger.debug(f"Error downloading via mssqlexec: {e}")
