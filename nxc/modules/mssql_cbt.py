from impacket import tds
from nxc.helpers.misc import CATEGORY


# Module writtent by @Defte_
class NXCModule:
    name = "mssql_cbt"
    description = "Checks whether Channel Binding is enabled on the MSSQL database"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        self.logger = context.log

    def on_login(self, context, connection):

        if not connection.encryption:
            self.logger.highlight("TLS not required: Channel Binding Token NOT REQUIRED")
            return

        if connection.args.local_auth:
            self.logger.highlight("Local auth: CANNOT check Channel Binding Token configuration")
            return

        ntlm_hash = f":{connection.nthash}" if connection.nthash else None

        new_conn = tds.MSSQL(connection.host, connection.port, connection.conn.remoteName)
        new_conn.connect(connection.args.mssql_timeout)

        def log_result(success):
            self.logger.highlight(
                "Connection successful: Channel Binding Token NOT REQUIRED"
                if success else
                "Connection failed: Channel Binding Token REQUIRED"
            )

        if connection.kerberos:
            success = new_conn.kerberosLogin(
                None, connection.username, connection.password, connection.targetDomain,
                ntlm_hash, connection.aesKey, connection.kdcHost,
                None, None, connection.use_kcache,
                cbt_fake_value=b""
            )
        else:
            success = new_conn.login(
                None, connection.username, connection.password, connection.targetDomain,
                ntlm_hash, not connection.args.local_auth,
                cbt_fake_value=b""
            )

        log_result(success)
        new_conn.disconnect()