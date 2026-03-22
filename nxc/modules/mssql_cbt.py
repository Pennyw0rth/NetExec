from impacket import tds
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module written by @Defte_"""
    name = "mssql_cbt"
    description = "Checks whether Channel Binding is enabled on the MSSQL database"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        self.logger = context.log

        if not connection.encryption:
            self.logger.highlight("TLS not required: Channel Binding Token NOT REQUIRED")
            return

        if connection.args.local_auth:
            self.logger.highlight("Local auth: CANNOT check Channel Binding Token configuration")
            return

        new_conn = tds.MSSQL(connection.host, connection.port, connection.conn.remoteName)
        new_conn.connect(connection.args.mssql_timeout)

        if connection.kerberos:
            success = new_conn.kerberosLogin(
                None,
                connection.username,
                connection.password,
                connection.targetDomain,
                f"{connection.lmhash}:{connection.nthash}" if connection.lmhash or connection.nthash else None,
                connection.aesKey,
                connection.kdcHost,
                None,
                None,
                connection.use_kcache,
                cbt_fake_value=b""
            )
        else:
            success = new_conn.login(
                None,
                connection.username,
                connection.password,
                connection.targetDomain,
                f"{connection.lmhash}:{connection.nthash}" if connection.lmhash or connection.nthash else None,
                not connection.args.local_auth,
                cbt_fake_value=b""
            )

        if success:
            self.logger.highlight("Connection successful: Channel Binding Token NOT REQUIRED")
        else:
            self.logger.highlight("Connection failed: Channel Binding Token REQUIRED")
        new_conn.disconnect()
