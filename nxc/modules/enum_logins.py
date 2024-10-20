#Author: 
# deathflamingo
class NXCModule:
    """Enumerate SQL Server logins"""

    name = "enum_logins"
    description = "Enumerate SQL Server logins"
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
        logins = self.get_logins()
        if logins:
            self.context.log.success("Logins found:")
            for login in logins:
                self.context.log.display(f"  - {login}")
        else:
            self.context.log.fail("No logins found.")

    def get_logins(self) -> list:
        """
        Fetches a list of SQL Server logins.

        Returns:
        -------
        list: List of login names.
        """
        query = "SELECT name FROM sys.server_principals WHERE type_desc = 'SQL_LOGIN';"
        res = self.mssql_conn.sql_query(query)
        return [login["name"] for login in res] if res else []
    def options(self, context, module_options):
        pass
