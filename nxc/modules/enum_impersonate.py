#Author: 
# deathflamingo
class NXCModule:
    """Enumerate SQL Server users with impersonation rights"""

    name = "enum_impersonate"
    description = "Enumerate users with impersonation privileges"
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
        impersonate_users = self.get_impersonate_users()
        if impersonate_users:
            self.context.log.success("Users with impersonation rights:")
            for user in impersonate_users:
                self.context.log.display(f"  - {user}")
        else:
            self.context.log.fail("No users with impersonation rights found.")

    def get_impersonate_users(self) -> list:
        """
        Fetches a list of users with impersonation rights.

        Returns:
        -------
        list: List of user names.
        """
        query = """
        SELECT DISTINCT b.name
        FROM sys.server_permissions a
        INNER JOIN sys.server_principals b
        ON a.grantor_principal_id = b.principal_id
        WHERE a.permission_name LIKE 'IMPERSONATE%'
        """
        res = self.mssql_conn.sql_query(query)
        return [user["name"] for user in res] if res else []
    def options(self, context, module_options):
        pass
