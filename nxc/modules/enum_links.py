#Author: 
# deathflamingo
class NXCModule:
    """Enumerate SQL Server linked servers"""

    name = "enum_links"
    description = "Enumerate linked SQL Servers"
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn
        linked_servers = self.get_linked_servers()
        if linked_servers:
            self.context.log.success("Linked servers found:")
            for server in linked_servers:
                self.context.log.display(f"  - {server}")
        else:
            self.context.log.fail("No linked servers found.")

    def get_linked_servers(self) -> list:
        """
        Fetches a list of linked servers.

        Returns:
        -------
        list: List of linked server names.
        """
        query = "EXEC sp_linkedservers;"
        res = self.mssql_conn.sql_query(query)
        return [server["SRV_NAME"] for server in res] if res else []
    def options(self, context, module_options):
        pass
