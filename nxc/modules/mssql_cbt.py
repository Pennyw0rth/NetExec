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

        domain = connection.targetDomain
        host = connection.host
        remote_name = connection.conn.remoteName
        port = connection.port
        timeout = connection.args.mssql_timeout
        username = connection.username
        password = connection.password
        nthash = connection.nthash
        kerberos = connection.kerberos
        use_cache = connection.use_kcache
        aes_key = connection.aesKey
        kdc_host = connection.kdcHost
        local_auth = connection.args.local_auth

        ntlm_hash = f":{nthash}" if nthash else None

        new_conn = tds.MSSQL(host, port, remote_name)
        new_conn.connect(timeout)

        def log_result(success):
            self.logger.highlight(
                "Connection successful: Channel Binding Token NOT REQUIRED"
                if success else
                "Connection failed: Channel Binding Token REQUIRED"
            )

        if kerberos:
            success = new_conn.kerberosLogin(
                None, username, password, domain,
                ntlm_hash, aes_key, kdc_host,
                None, None, use_cache,
                cbt_fake_value=b""
            )
        else:
            success = new_conn.login(
                None, username, password, domain,
                ntlm_hash, not local_auth,
                cbt_fake_value=b""
            )

        log_result(success)
        new_conn.disconnect()