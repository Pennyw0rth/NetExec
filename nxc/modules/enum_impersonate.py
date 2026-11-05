from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enumerate SQL Server users with impersonation rights
    Module by deathflamingo
    """

    name = "enum_impersonate"
    description = "Enumerate users with impersonation privileges"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

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
                self.context.log.display(f"  - {user['grantee']} can impersonate: {user['target']}")
        else:
            self.context.log.fail("No users with impersonation rights found.")

    def get_impersonate_users(self) -> list:
        """
        Fetches the IMPERSONATE grants on logins that the current user can see (all of them as sysadmin).

        Returns
        -------
        list: List of rows with the grantee and the target login.
        """
        query = """
        SELECT ge.name AS grantee, tg.name AS target
        FROM sys.server_permissions p
        INNER JOIN sys.server_principals ge ON ge.principal_id = p.grantee_principal_id
        INNER JOIN sys.server_principals tg ON tg.principal_id = p.major_id
        WHERE p.class_desc = 'SERVER_PRINCIPAL' AND p.permission_name = 'IMPERSONATE' AND p.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION')
        """
        return self.mssql_conn.sql_query(query) or []

    def options(self, context, module_options):
        pass
