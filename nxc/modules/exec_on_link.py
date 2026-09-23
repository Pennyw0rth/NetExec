from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Execute commands on linked servers
    Module by deathflamingo
    """

    name = "exec_on_link"
    description = "Execute commands on a SQL Server linked server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.mssql_conn = None
        self.context = None
        self.linked_server = None
        self.command = None
        self.as_login = None
        self.admin_privs = False

    def options(self, context, module_options):
        """
        LINKED_SERVER: The name of the linked server to execute the command on.
        COMMAND: The command to execute on the linked server.
        AS_LOGIN: Execute the command as this local SQL Server login.
        """
        self.linked_server = module_options.get("LINKED_SERVER")
        self.command = module_options.get("COMMAND")
        self.as_login = module_options.get("AS_LOGIN")

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
        self.admin_privs = connection.admin_privs
        if not self.linked_server or not self.command:
            self.context.log.fail("Please specify both LINKED_SERVER and COMMAND options.")
            return

        self.execute_on_link()

    def execute_on_link(self):
        """Executes the specified command on the linked server."""
        command = self.escape_sql_literal(self.command)
        linked_server = self.escape_sql_identifier(self.linked_server)
        query = f"EXEC (N'{command}')"
        if self.as_login:
            query += f" AS LOGIN = N'{self.escape_sql_literal(self.as_login)}'"
        query += f" AT [{linked_server}];"
        result = self.mssql_conn.sql_query(query)
        if self.mssql_conn.lastError:
            self.handle_execution_error(self.mssql_conn.lastError)
        elif result:
            self.context.log.display("Command output:")
            for row in result:
                for key, value in row.items():
                    self.context.log.highlight(f"{key}:{value}" if key else str(value))
        else:
            self.context.log.display("Command executed but returned no output")

    def handle_execution_error(self, error):
        error_text = str(error)
        if self.is_impersonation_error(error_text):
            self.context.log.fail(f"Unable to execute as login '{self.as_login}': {error_text}")
            self.context.log.display("The login may not exist, may not be impersonatable, or the current login lacks IMPERSONATE permission")
            return

        if self.is_no_login_mapping_error(error_text):
            current_login = f"'{self.as_login}'" if self.as_login else "the current login"
            self.context.log.fail(f"No login mapping exists for {current_login} on linked server {self.linked_server}")
            self.log_linked_login_mappings()
            return

        self.context.log.fail(f"Linked-server execution failed: {error_text}")

    def log_linked_login_mappings(self):
        if not self.admin_privs:
            self.context.log.display("Unable to enumerate mappings with the current privileges")
            self.context.log.display("Run the enum_links module with sufficient privileges, then retry with AS_LOGIN=<login>")
            return

        query = f"EXEC sp_helplinkedsrvlogin @rmtsrvname = N'{self.escape_sql_literal(self.linked_server)}';"
        mappings = self.mssql_conn.sql_query(query)
        if self.mssql_conn.lastError:
            self.context.log.display("Unable to enumerate linked-server login mappings")
            return
        mappings = [mapping for mapping in mappings if mapping["Local Login"] is not None]
        if not mappings:
            self.context.log.display("No explicit local-login mappings were found for this linked server")
            return

        for mapping in mappings:
            remote_login = mapping["Remote Login"] or "<self>"
            self.context.log.display(f"Mapped local login: {mapping['Local Login']} -> {remote_login}")
            if mapping["Local Login"] != self.as_login:
                self.context.log.display(f"Retry with AS_LOGIN={mapping['Local Login']}")

    def escape_sql_literal(self, value):
        return value.replace("'", "''")

    def escape_sql_identifier(self, value):
        return value.replace("]", "]]")

    def is_impersonation_error(self, error):
        return self.as_login and "cannot execute as the login" in error.lower()

    def is_no_login_mapping_error(self, error):
        return "no login-mapping exists" in error.lower()
