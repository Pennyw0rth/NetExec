class NXCModule:
    """
    Enumerate SQL Server logins (SQL, Domain, Local users)
    Module by deathflamingo, modified by mpgn
    """

    name = "enum_logins"
    description = "Enumerate SQL Server logins (SQL, Domain, Local users)"
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
            self.context.log.display("Enumerated logins")
            self.context.log.highlight(f"{'Login Name':<35} {'Type':<15} {'Status'}")
            self.context.log.highlight(f"{'----------':<35} {'----':<15} {'------'}")
            for login_name, login_type, status in logins:
                self.context.log.highlight(f"{login_name:<35} {login_type:<15} {status}")
        else:
            self.context.log.fail("No logins found.")

    def get_logins(self) -> list:
        """
        Fetches a list of SQL Server logins with their types.

        Returns
        -------
        list: List of tuples containing (login_name, login_type, status).
        """
        query = """
        SELECT 
            name,
            type,
            type_desc,
            CASE type_desc 
                WHEN 'SQL_LOGIN' THEN 'SQL User'
                WHEN 'WINDOWS_LOGIN' THEN 
                    CASE 
                        WHEN name LIKE '%\\%' THEN 'Domain User'
                        ELSE 'Local User'
                    END
                WHEN 'WINDOWS_GROUP' THEN 'Windows Group'
                WHEN 'CERTIFICATE_MAPPED_LOGIN' THEN 'Certificate Login'
                WHEN 'ASYMMETRIC_KEY_MAPPED_LOGIN' THEN 'Asymmetric Key Login'
                ELSE type_desc
            END as login_type,
            is_disabled,
            create_date
        FROM sys.server_principals 
        WHERE type IN ('S', 'U', 'G', 'C', 'K')
        AND name NOT LIKE '##%'
        AND name NOT IN ('sa') OR name = 'sa'
        ORDER BY login_type, name;
        """
        try:
            res = self.mssql_conn.sql_query(query)
            if res:
                logins = []
                for login in res:
                    status = "DISABLED" if login.get("is_disabled") else "ENABLED"
                    logins.append((login["name"], login["login_type"], status))
                return logins
            return []
        except Exception as e:
            self.context.log.fail(f"Error querying logins: {e}")
            return []

    def options(self, context, module_options):
        pass
