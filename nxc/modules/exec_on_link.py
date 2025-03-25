class NXCModule:
    """
    Execute commands on linked servers
    Module by deathflamingo
    """

    name = "exec_on_link"
    description = "Execute commands on a SQL Server linked server"
    supported_protocols = ["mssql"]
    opsec_safe = False
    multiple_hosts = False

    def __init__(self):
        self.mssql_conn = None
        self.context = None
        self.linked_server = None
        self.command = None

    def options(self, context, module_options):
        """
        LINKED_SERVER: The name of the linked server to execute the command on.
        COMMAND: The command to execute on the linked server.
        """
        if "LINKED_SERVER" in module_options:
            self.linked_server = module_options["LINKED_SERVER"]
        if "COMMAND" in module_options:
            self.command = module_options["COMMAND"]

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
        if not self.linked_server or not self.command:
            self.context.log.fail("Please specify both LINKED_SERVER and COMMAND options.")
            return

        self.execute_on_link()

    def execute_on_link(self):
        """Executes the specified command on the linked server."""
        query = f"EXEC ('{self.command}') AT [{self.linked_server}];"
        result = self.mssql_conn.sql_query(query)
        self.context.log.display(f"Command output: {result}")
