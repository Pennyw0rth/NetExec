import os
from impacket import tds
from nxc.helpers.misc import CATEGORY
from impacket.krb5.ccache import CCache


class NXCModule:
    name = "mssql_cbt"
    description = "Checks whether Channel Binding is enabled on the MSSQL database"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        self.logger = context.log

    def _check(self, connect_func):
        return connect_func(cbt_fake_value=b"")

    def on_login(self, context, connection):
        if not connection.encryption:
            self.logger.highlight("TLS not required: Channel Binding Token NOT REQUIRED")
            return

        if connection.args.local_auth:
            self.logger.highlight("Local auth: CANNOT check Channel Binding Token configuration")
            return

        # Force authentication to fail if CBT is required
        connection.tls_unique = b""

        domain = connection.targetDomain
        host = connection.host
        remoteName = connection.conn.remoteName
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

        new_conn = tds.MSSQL(host, port, remoteName)
        new_conn.connect(timeout)

        def ok_or_fail(res):
            if res: 
                self.logger.highlight("Connection successful:  Channel Binding Token NOT REQUIRED")
            else: 
                self.logger.highlight("Connection failed: Channel Binding Token REQUIRED")

        # Password auth (NTLM or Kerberos)
        if username and password and not kerberos:
            self.logger.debug("User/password (NTLM)")
            ok_or_fail(self._check(lambda **k: new_conn.login(
                None, username, password, domain, None, not local_auth, **k
            )))

        if username and password and kerberos:
            self.logger.debug("User/password (Kerberos)")
            ok_or_fail(self._check(lambda **k: new_conn.kerberosLogin(
                None, username, password, domain, None, "", kdc_host, None, None, False, **k
            )))

        # NT hash auth
        if username and nthash and not kerberos:
            self.logger.debug("NT hash (NTLM)")
            ntlm_hash = f":{nthash}"
            ok_or_fail(self._check(lambda **k: new_conn.login(
                None, username, None, domain, ntlm_hash, not local_auth, **k
            )))

        if username and nthash and kerberos:
            self.logger.debug("NT hash (Kerberos RC4)")
            ntlm_hash = f":{nthash}"
            ok_or_fail(self._check(lambda **k: new_conn.kerberosLogin(
                None, username, None, domain, ntlm_hash, "", kdc_host, None, None, False, **k
            )))

        # AES key auth
        if username and aes_key:
            self.logger.debug("AES key (Kerberos)")
            ok_or_fail(self._check(lambda **k: new_conn.kerberosLogin(
                None, username, None, domain, None, aes_key, kdc_host, None, None, False, **k
            )))

        # Kerberos cache auth
        if use_cache and kerberos and not any([nthash, password, aes_key]):
            ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            username = ccache.credentials[0].header["client"].prettyPrint().decode().split("@")[0]
            self.logger.debug("Kerberos cache")
            ok_or_fail(self._check(lambda **k: new_conn.kerberosLogin(
                None, username, None, domain, None, None, kdc_host, None, None, True, **k
            )))

        new_conn.disconnect()
