class NXCModule:
    """
    Enables or disables xp_cmdshell in MSSQL Server.
    Module by crosscutsaw
    """

    name = "enable_cmdshell"
    description = "Enable or disable xp_cmdshell in MSSQL Server"
    supported_protocols = ["mssql"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None
        self.action = None
        self.advanced_options_backup = None  # Stores original value of 'show advanced options'

    def options(self, context, module_options):
        """
        ACTION      enable or disable xp_cmdshell

        Examples
        --------
        netexec mssql $TARGET -u $username -p $password -M enable_cmdshell -o ACTION=enable
        netexec mssql $TARGET -u $username -p $password -M enable_cmdshell -o ACTION=disable
        """
        if "ACTION" in module_options:
            self.action = module_options["ACTION"].lower()
        else:
            context.log.fail("Missing required option: ACTION (enable/disable)")
            exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn

        if self.action == "enable":
            self.toggle_xp_cmdshell(enable=True)
        elif self.action == "disable":
            self.toggle_xp_cmdshell(enable=False)
        else:
            self.context.log.fail("Invalid ACTION. Use 'enable' or 'disable'.")

    def backup_show_advanced_options(self):
        """Backs up the current state of 'show advanced options'."""
        query = "SELECT CAST(value AS INT) AS value FROM sys.configurations WHERE name = 'show advanced options'"
        res = self.mssql_conn.sql_query(query)
        if res:
            self.advanced_options_backup = int(res[0]["value"])  # Convert to integer

    def restore_show_advanced_options(self):
        """Restores the original state of 'show advanced options' if needed."""
        if self.advanced_options_backup is not None and self.advanced_options_backup == 0:
            self.mssql_conn.sql_query("EXEC sp_configure 'show advanced options', '0'; RECONFIGURE;")

    def toggle_xp_cmdshell(self, enable: bool):
        """Enables or disables xp_cmdshell while preserving 'show advanced options' state."""
        state = "1" if enable else "0"

        # Backup 'show advanced options' state
        self.backup_show_advanced_options()

        # Enable 'show advanced options' if it was disabled
        self.mssql_conn.sql_query("EXEC sp_configure 'show advanced options', '1'; RECONFIGURE;")

        try:
            # Enable or disable xp_cmdshell
            self.mssql_conn.sql_query(f"EXEC sp_configure 'xp_cmdshell', '{state}'; RECONFIGURE;")
            action_text = "enabled" if enable else "disabled"
            self.context.log.success(f"xp_cmdshell successfully {action_text}.")
        except Exception as e:
            self.context.log.fail(f"Failed to execute command: {e}")

        # Restore 'show advanced options' to its original state if needed
        self.restore_show_advanced_options()
