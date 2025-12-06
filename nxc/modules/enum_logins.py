from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enumerate SQL Server logins (SQL, Domain, Local users)
    Module by deathflamingo, modified by mpgn
    """

    name = "enum_logins"
    description = "Enumerate SQL Server logins (SQL, Domain, Local users)"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

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

    def get_domain_name(self) -> str:
        query = "SELECT DEFAULT_DOMAIN() as domain_name;"
        try:
            res = self.mssql_conn.sql_query(query)
            if res and res[0].get("domain_name"):
                return res[0]["domain_name"].upper()
            return ""
        except Exception as e:
            self.context.log.debug(f"Error querying domain name: {e}")
            return ""

    def get_logins(self) -> list:
        domain_name = self.get_domain_name()
        domain_prefix = f"{domain_name}\\" if domain_name else ""

        query = f"""
        SELECT
            name,
            type,
            type_desc,
            CASE type_desc
                WHEN 'SQL_LOGIN' THEN 'SQL User'
                WHEN 'WINDOWS_LOGIN' THEN
                    CASE
                        WHEN name LIKE '{domain_prefix}%' THEN 'Domain User'
                        WHEN name LIKE '%\\%' THEN 'Local User'
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
