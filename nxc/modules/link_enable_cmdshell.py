class NXCModule:
    """
    Enable or disable xp_cmdshell on a linked MSSQL server
    Module by deathflamingo
    """

    name = "link_enable_cmdshell"
    description = "Enable or disable xp_cmdshell on a linked MSSQL server"
    supported_protocols = ["mssql"]
    opsec_safe = False
    multiple_hosts = False

    def __init__(self):
        self.action = None
        self.linked_server = None

    def options(self, context, module_options):
        """
        Defines the options for enabling or disabling xp_cmdshell on the linked server.
        ACTION           Specifies whether to enable or disable:
                          - enable (default)
                          - disable
        LINKED_SERVER    The name of the linked SQL server to target.
        """
        self.action = module_options.get("ACTION", "enable")
        self.linked_server = module_options.get("LINKED_SERVER")

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn

        # Store the original state of options that have to be enabled/disabled in order to restore them later
        self.backuped_options = {}

        if not self.linked_server:
            self.context.log.fail("Please provide a linked server name using the LINKED_SERVER option.")
            return

        # Enable or disable xp_cmdshell based on action
        if self.action == "enable":
            self.enable_xp_cmdshell()
        elif self.action == "disable":
            self.disable_xp_cmdshell()
        else:
            self.context.log.fail(f"Unknown action: {self.action}")

    def enable_xp_cmdshell(self):
        """Enable xp_cmdshell on the linked server."""
        self.backup_and_enable("advanced options")

        current_value = self.is_option_enabled("xp_cmdshell")
        self.context.log.display(f"Enabling xp_cmdshell on {self.linked_server}. Current value: {current_value}")
        self.mssql_conn.sql_query(f"EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{self.linked_server}]")
        self.context.log.success(f"xp_cmdshell enabled on {self.linked_server}")

        self.restore("advanced options")

    def disable_xp_cmdshell(self):
        """Disable xp_cmdshell on the linked server."""
        self.backup_and_enable("advanced options")

        current_value = self.is_option_enabled("xp_cmdshell")
        self.context.log.display(f"Disabling xp_cmdshell on {self.linked_server}. Current value: {current_value}")
        self.mssql_conn.sql_query(f"EXEC ('sp_configure xp_cmdshell, 0; RECONFIGURE;') AT [{self.linked_server}]")
        self.context.log.success(f"xp_cmdshell disabled on {self.linked_server}")

        self.restore("advanced options")

    # Adapting methods from MSSQLEXEC for backup and restore functionality
    def restore(self, option):
        try:
            if not self.backuped_options[option]:
                self.context.log.debug(f"Option '{option}' was not enabled on {self.linked_server} originally, attempting to disable it.")
                query = f"EXEC ('EXEC master.dbo.sp_configure \"{option}\", 0;RECONFIGURE;') AT [{self.linked_server}]"
                self.context.log.debug(f"Executing query: {query}")
                self.mssql_conn.sql_query(query)
            else:
                self.context.log.debug(f"Option '{option}' was originally enabled on {self.linked_server}, leaving it enabled.")
        except Exception as e:
            self.context.log.error(f"[OPSEC] Error when attempting to restore option '{option}' on {self.linked_server}: {e}")

    def backup_and_enable(self, option):
        try:
            self.backuped_options[option] = self.is_option_enabled(option)
            if not self.backuped_options[option]:
                self.context.log.debug(f"Option '{option}' is disabled on {self.linked_server}, attempting to enable it.")
                query = f"EXEC ('EXEC master.dbo.sp_configure \"{option}\", 1;RECONFIGURE;') AT [{self.linked_server}]"
                self.context.log.debug(f"Executing query: {query}")
                self.mssql_conn.sql_query(query)
            else:
                self.context.log.debug(f"Option '{option}' is already enabled on {self.linked_server}.")
        except Exception as e:
            self.context.log.error(f"Error when checking/enabling option '{option}' on {self.linked_server}: {e}")

    def is_option_enabled(self, option):
        query = f"EXEC ('EXEC master.dbo.sp_configure \"{option}\";') AT [{self.linked_server}]"
        self.context.log.debug(f"Checking if {option} is enabled on {self.linked_server}: {query}")
        result = self.mssql_conn.sql_query(query)
        # Assuming the query returns a list of dictionaries with 'config_value' as the key
        self.context.log.debug(f"{option} check result: {result}")
        return bool(result and result[0]["config_value"] == 1)
