class NXCModule:
    """
    Enumerate SQL Server linked servers
    Module by deathflamingo, NeffIsBack
    """

    name = "enum_links"
    description = "Enumerate linked SQL Servers and their login configurations."
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None

    def options(self, context, module_options):
        pass

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

    def on_admin_login(self, context, connection):
        res = self.mssql_conn.sql_query("EXEC sp_helplinkedsrvlogin")
        srvs = [srv for srv in res if srv["Local Login"] != "NULL"]
        if not srvs:
            self.context.log.fail("No linked servers found.")
            return
        self.context.log.success("Linked servers found:")
        for srv in srvs:
            self.context.log.display(f"Linked server: {srv['Linked Server']}")
            self.context.log.display(f"  - Local login: {srv['Local Login']}")
            self.context.log.display(f"  - Remote login: {srv['Remote Login']}")

    def get_linked_servers(self) -> list:
        """
        Fetches a list of linked servers.

        Returns
        -------
        list: List of linked server names.
        """
        query = "EXEC sp_linkedservers;"
        res = self.mssql_conn.sql_query(query)
        return [server["SRV_NAME"] for server in res] if res else []
