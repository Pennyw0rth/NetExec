import binascii
import contextlib
import random
import string

from termcolor import colored

from impacket import tds, ntlm
from nxc.config import host_info_colors
from nxc.helpers.misc import CATEGORY


EPA_LABELS = {
    "off": colored(
        "Extended Protection: Off - NTLM relay POSSIBLE (Vulnerable)",
        host_info_colors[1],
        attrs=["bold"],
    ),
    "allowed": colored(
        "Extended Protection: Allowed - NTLM relay may succeed with NTLMv1 clients (Partially Vulnerable)",
        host_info_colors[2],
        attrs=["bold"],
    ),
    "required_cb": colored(
        "Extended Protection: Required - CBT enforced, NTLM relay NOT possible (Secure)",
        host_info_colors[0],
        attrs=["bold"],
    ),
    "required_sb": colored(
        "Extended Protection: Required - SPN enforced, NTLM relay NOT possible (Secure)",
        host_info_colors[0],
        attrs=["bold"],
    ),
}


class MSSQLEpaTest(tds.MSSQL):
    def get_error_messages(self):
        if not hasattr(self, "replies") or not self.replies:
            return ""
        messages = [
            key["MsgText"].decode("utf-16le")
            for keys in self.replies
            for key in self.replies[keys]
            if key["TokenType"] == tds.TDS_ERROR_TOKEN
        ]
        return " ".join(messages)

    def epa_login(self, username, password="", domain="", hashes=None,
                  channel_binding_value=None, service="MSSQLSvc", strip_target_service=False):
        if hashes:
            lmhash, nthash = hashes.split(":")
            lmhash = binascii.a2b_hex(lmhash)
            nthash = binascii.a2b_hex(nthash)
        else:
            lmhash = ""
            nthash = ""

        resp = self.preLogin()

        if resp["Encryption"] in (tds.TDS_ENCRYPT_REQ, tds.TDS_ENCRYPT_OFF):
            self.set_tls_context()
        else:
            raise Exception(f"Unsupported encryption: {resp['Encryption']}")

        login = tds.TDS_LOGIN()
        login["HostName"] = "".join(random.choices(string.ascii_letters, k=8)).encode("utf-16le")
        login["AppName"] = "".join(random.choices(string.ascii_letters, k=8)).encode("utf-16le")
        login["ServerName"] = self.remoteName.encode("utf-16le")
        login["CltIntName"] = login["AppName"]
        login["ClientPID"] = random.randint(0, 1024)
        login["PacketSize"] = self.packetSize
        login["OptionFlags2"] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON

        self.version = ntlm.VERSION()
        self.version["ProductMajorVersion"] = 10
        self.version["ProductMinorVersion"] = 0
        self.version["ProductBuild"] = 20348
        auth = ntlm.getNTLMSSPType1("", "", use_ntlmv2=True, version=self.version)
        login["SSPI"] = auth.getData()
        login["Length"] = len(login.getData())

        self.sendTDS(tds.TDS_LOGIN7, login.getData())

        # Per spec, when encryption is OFF, only the LOGIN7 packet is encrypted; tear down TLS afterwards
        if resp["Encryption"] == tds.TDS_ENCRYPT_OFF:
            self.tlsSocket = None

        tds_resp = self.recvTDS()
        serverChallenge = tds_resp["Data"][3:]

        effective_cb = channel_binding_value
        if effective_cb is None:
            if hasattr(self, "tlsSocket") and self.tlsSocket:
                effective_cb = self.generate_cbt_from_tls_unique()
            else:
                effective_cb = b""

        original_test_case = ntlm.TEST_CASE
        if strip_target_service:
            # impacket honors TEST_CASE to strip MsvAvTargetName from AV_PAIRS
            ntlm.TEST_CASE = True

        try:
            type3, exportedSessionKey = ntlm.getNTLMSSPType3(
                auth, serverChallenge, username, password, domain,
                lmhash, nthash,
                service=service, use_ntlmv2=True,
                channel_binding_value=effective_cb,
                version=self.version,
            )
            type3["MIC"] = b"\x00" * 16
            new_mic = ntlm.hmac_md5(
                exportedSessionKey,
                auth.getData() + ntlm.NTLMAuthChallenge(serverChallenge).getData() + type3.getData(),
            )
            type3["MIC"] = new_mic
        finally:
            ntlm.TEST_CASE = original_test_case

        self.sendTDS(tds.TDS_SSPI, type3.getData())
        tds_resp = self.recvTDS()

        self.replies = self.parseReply(tds_resp["Data"])
        return tds.TDS_LOGINACK_TOKEN in self.replies


class NXCModule:
    """Module by @NoahDSJP - replaces mssql_cbt by @Dfte"""

    name = "mssql_epa"
    description = "Check Extended Protection for Authentication (EPA) enforcement on MSSQL"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def _test_connection(self, host, port, remote_name, timeout, username, password, domain, hashes,
                         channel_binding_value=None, service="MSSQLSvc", strip_target_service=False):
        conn = MSSQLEpaTest(host, port, remote_name)
        conn.connect(timeout)
        try:
            res = conn.epa_login(
                username=username, password=password, domain=domain, hashes=hashes,
                channel_binding_value=channel_binding_value,
                service=service, strip_target_service=strip_target_service,
            )
            if res:
                return "success"
            errors = conn.get_error_messages()
            if "untrusted domain" in errors:
                return "untrusted_domain"
            if "Login failed" in errors:
                return "login_failed"
            return "other"
        except Exception as e:
            return f"error: {e}"
        finally:
            with contextlib.suppress(Exception):
                conn.disconnect()

    def on_login(self, context, connection):
        self.logger = context.log

        if connection.args.local_auth:
            self.logger.fail("Local auth: cannot check EPA configuration (requires domain auth)")
            return

        if connection.kerberos:
            self.logger.fail("Kerberos auth: EPA check requires NTLM authentication")
            return

        if getattr(connection, "no_ntlm", False):
            self.logger.fail("Server does not support NTLM, EPA check not applicable")
            return

        test_args = {
            "host": connection.host,
            "port": connection.port,
            "remote_name": connection.conn.remoteName,
            "timeout": connection.args.mssql_timeout,
            "username": connection.username,
            "password": connection.password,
            "domain": connection.targetDomain,
            "hashes": f"{connection.lmhash}:{connection.nthash}" if connection.nthash else None,
        }

        if connection.encryption:
            bogus = self._test_connection(**test_args, channel_binding_value=b"\xde\xad" * 8)
            self.logger.info(f"Bogus CBT: {bogus}")

            if bogus == "untrusted_domain":
                missing = self._test_connection(**test_args, channel_binding_value=b"")
                self.logger.info(f"Missing CBT: {missing}")
                result = "required_cb" if missing == "untrusted_domain" else "allowed"
            else:
                result = "off"
        else:
            bogus = self._test_connection(**test_args, service="cifs")
            self.logger.info(f"Bogus SPN: {bogus}")

            if bogus == "untrusted_domain":
                missing = self._test_connection(**test_args, service="", strip_target_service=True)
                self.logger.info(f"Missing SPN: {missing}")
                result = "required_sb" if missing == "untrusted_domain" else "allowed"
            else:
                result = "off"

        self.logger.highlight(EPA_LABELS[result])
