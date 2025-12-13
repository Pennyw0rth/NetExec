import os
from datetime import datetime, timezone

import ldap3
import ldap3.operation.bind

from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.asn1 import TGS_REP, AP_REQ, Authenticator, seq_set
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

from pyasn1.codec.ber import decoder as der_decoder, encoder as ber_encoder
from pyasn1.type.univ import noValue


class Ldap3Connection:
    """
    Wrapper class for creating ldap3.Connection instances.

    Supports:
    - NTLM authentication (plaintext password or pass-the-hash)
    - Kerberos authentication (password, hash, aesKey, or ccache)
    - Automatic fallback from LDAP:389 to LDAPS:636 when required
    """

    def __init__(
        self,
        host: str,
        port: int,
        hostname: str,
        domain: str,
        username: str,
        password: str = "",
        lmhash: str = "",
        nthash: str = "",
        aesKey: str = "",
        kdcHost: str | None = None,
        kerberos: bool = False,
        use_kcache: bool = False,
        port_explicitly_set: bool = False,
        logger=None,
    ):
        self.host = host
        self.port = port
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.kdcHost = kdcHost
        self.kerberos = kerberos
        self.use_kcache = use_kcache
        self.port_explicitly_set = port_explicitly_set
        self.logger = logger

        self._connection = None

    def _log_info(self, msg):
        if self.logger:
            self.logger.info(msg)

    def _log_debug(self, msg):
        if self.logger:
            self.logger.debug(msg)

    def _log_fail(self, msg):
        if self.logger:
            self.logger.fail(msg)

    def _log_error(self, msg):
        if self.logger:
            self.logger.error(msg)

    def _log_display(self, msg):
        if self.logger:
            self.logger.display(msg)

    def _set_protocol_info(self, protocol: str, port: str):
        if self.logger and hasattr(self.logger, "extra"):
            self.logger.extra["protocol"] = protocol
            self.logger.extra["port"] = port

    def create_conn(self):
        if self.kerberos or self.use_kcache:
            return self._kerberos_connect()

        return self._ntlm_connect()

    def _do_ntlm_bind(self, ssl: bool, bind_port: int):
        try:
            self._set_protocol_info("LDAPS" if ssl else "LDAP", str(bind_port))
            server = ldap3.Server(
                self.host,
                port=bind_port,
                use_ssl=ssl,
                get_info=ldap3.NONE,
            )
            user_ntlm = f"{self.domain}\\{self.username}" if self.domain else (self.username or "")

            # Determine authentication secret: password or hash
            if self.password:
                auth_secret = self.password
            elif self.nthash:
                # Pass-the-hash: ldap3 NTLM accepts "LMHASH:NTHASH" as password
                lmhash = self.lmhash if self.lmhash else "aad3b435b51404eeaad3b435b51404ee"
                auth_secret = f"{lmhash}:{self.nthash}"
            else:
                auth_secret = ""

            conn = ldap3.Connection(
                server,
                user=user_ntlm,
                password=auth_secret,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )
            return conn, {"result": 0}
        except Exception as e:
            return None, e

    def _ntlm_connect(self):
        # Build list of (port, use_ssl) tuples to try
        ports_to_try = [(self.port, self.port == 636)]
        if not self.port_explicitly_set:
            fallback_port = (636, True) if self.port == 389 else (389, False)
            ports_to_try.append(fallback_port)

        connection = None
        last_error = None

        for bind_port, use_ssl in ports_to_try:
            bound_connection, bind_result = self._do_ntlm_bind(use_ssl, bind_port)
            if bound_connection and getattr(bound_connection, "bound", False):
                connection = bound_connection
                break
            last_error = bind_result
            if self.port_explicitly_set:
                break

        if not connection:
            self._log_fail(f"NTLM bind failed: {last_error}")
            return None

        self._connection = connection
        protocol_info = "LDAPS:636" if connection.server.port == 636 else f"LDAP:{connection.server.port}"
        self._log_info(f"ldap3 NTLM bind over {protocol_info} established")
        return connection

    def _kerberos_connect(self):
        # Build FQDN for SPN
        realm = (self.domain or "").upper()
        host_fqdn = (self.hostname or self.host) or ""
        if "." not in host_fqdn and realm:
            host_fqdn = f"{host_fqdn}.{realm}"

        TGT = None
        TGS = None

        if self.use_kcache:
            result = self._load_from_ccache(realm, host_fqdn)
            if result is None:
                return None
            TGT, TGS, realm = result

        # Prepare creds for TGT acquisition if needed
        user_principal = Principal(self.username or "", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        lmhash_bytes = bytes.fromhex(self.lmhash.zfill(len(self.lmhash) + len(self.lmhash) % 2)) if self.lmhash else b""
        nthash_bytes = bytes.fromhex(self.nthash.zfill(len(self.nthash) + len(self.nthash) % 2)) if self.nthash else b""

        if not TGT and not TGS:
            tgt_blob, cipher, _, session_key = getKerberosTGT(user_principal, self.password, realm, lmhash_bytes, nthash_bytes, self.aesKey, self.kdcHost)
            TGT = {"KDC_REP": tgt_blob, "cipher": cipher, "sessionKey": session_key}
        else:
            cipher = (TGT or TGS)["cipher"]
            session_key = (TGT or TGS)["sessionKey"]

        # Ensure we have a ST for ldap/<FQDN>
        if not TGS:
            service_principal = Principal(f"ldap/{host_fqdn}", type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs_blob, cipher, _, session_key = getKerberosTGS(service_principal, realm, self.kdcHost, TGT["KDC_REP"], TGT["cipher"], TGT["sessionKey"])
            TGS = {"KDC_REP": tgs_blob, "cipher": cipher, "sessionKey": session_key}

        # Build AP_REQ SPNEGO blob
        spnego_blob = self._build_spnego_blob(TGS, user_principal, realm, cipher, session_key)

        return self._gss_spnego_bind(spnego_blob, realm, host_fqdn)

    def _load_from_ccache(self, realm, host_fqdn):
        try:
            ccname = os.getenv("KRB5CCNAME")
            if not ccname:
                self._log_error("KRB5CCNAME environment variable is not set")
                return None
            ccache = CCache.loadFile(ccname)

            if not realm:
                realm = ccache.principal.realm["data"].decode().upper()

            spn_candidates = [
                f"ldap/{host_fqdn.lower()}@{realm}",
                f"ldap/{host_fqdn.upper()}@{realm}",
            ]
            TGS = None
            for spn in spn_candidates:
                creds = ccache.getCredential(spn)
                if creds:
                    TGS = creds.toTGS(spn)
                    break

            TGT = None
            if not TGS:
                krbtgt_credential = ccache.getCredential(f"krbtgt/{realm}@{realm}")
                if krbtgt_credential:
                    TGT = krbtgt_credential.toTGT()

            if not TGS and not TGT:
                self._log_fail("Kerberos cache selected (--use-kcache) but no usable TGT/TGS found in cache.")
                return None

            return TGT, TGS, realm
        except Exception as e:
            self._log_fail(f"Failed to read Kerberos cache (--use-kcache): {e}")
            return None

    def _build_spnego_blob(self, TGS, user_principal, realm, cipher, session_key):
        spnego_token = SPNEGO_NegTokenInit()
        spnego_token["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]

        tgs_rep = der_decoder.decode(TGS["KDC_REP"], asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs_rep["ticket"])

        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        apReq["ap-options"] = constants.encodeFlags([])
        seq_set(apReq, "ticket", ticket.to_asn1)

        auth = Authenticator()
        auth["authenticator-vno"] = 5
        auth["crealm"] = realm
        seq_set(auth, "cname", user_principal.components_to_asn1)
        now = datetime.now(timezone.utc)
        auth["ctime"] = KerberosTime.to_asn1(now)
        auth["cusec"] = now.microsecond

        enc_auth = cipher.encrypt(session_key, 11, ber_encoder.encode(auth), None)
        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = enc_auth
        spnego_token["MechToken"] = ber_encoder.encode(apReq)

        return spnego_token

    def _do_gss_bind(self, use_ssl: bool, bind_port: int, spnego_blob):
        try:
            self._set_protocol_info("LDAPS" if use_ssl else "LDAP", str(bind_port))
            ldap_server = ldap3.Server(
                self.host,
                port=bind_port,
                use_ssl=use_ssl,
                get_info=ldap3.NONE,
            )
            ldap_connection = ldap3.Connection(
                ldap_server,
                authentication=ldap3.SASL,
                sasl_mechanism="GSS-SPNEGO",
                auto_bind=False,
            )
            if ldap_connection.closed:
                ldap_connection.open(read_server_info=False)

            bind_request = ldap3.operation.bind.bind_operation(
                ldap_connection.version, ldap3.SASL, (self.username or ""), None, "GSS-SPNEGO", spnego_blob.getData()
            )
            ldap_connection.sasl_in_progress = True
            bind_response = ldap_connection.post_send_single_response(ldap_connection.send("bindRequest", bind_request, None))
            ldap_connection.sasl_in_progress = False

            return ldap_connection, bind_response
        except Exception as error:
            return None, error

    def _gss_spnego_bind(self, spnego_blob, realm, host_fqdn):
        # Build list of (port, use_ssl) tuples to try
        ports_to_try = [(self.port, self.port == 636)]
        if not self.port_explicitly_set:
            fallback_port = (636, True) if self.port == 389 else (389, False)
            ports_to_try.append(fallback_port)

        connection = None
        last_response = None

        for bind_port, use_ssl in ports_to_try:
            bound_connection, bind_response = self._do_gss_bind(use_ssl, bind_port, spnego_blob)
            connection = bound_connection
            last_response = bind_response

            bind_successful = False
            if isinstance(bind_response, list) and bind_response and isinstance(bind_response[0], dict):
                bind_successful = (bind_response[0].get("result", None) == 0)

            if bind_successful:
                break
            if self.port_explicitly_set:
                break

        # Check if bind was successful
        is_valid_response = isinstance(last_response, list) and last_response and isinstance(last_response[0], dict)
        bind_succeeded = is_valid_response and last_response[0].get("result", 1) == 0

        if not bind_succeeded:
            error_detail = last_response[0] if is_valid_response else last_response
            self._log_fail(f"ldap3 Kerberos bind failed: {error_detail}")
            return None

        connection.bound = True
        self._connection = connection

        # Resolve username from whoami if not set (ccache case)
        self._resolve_username_from_whoami(connection)

        self._log_info("ldap3 Kerberos connection established")
        return connection

    def _resolve_username_from_whoami(self, ldap_connection):
        try:
            if not self.username:
                whoami_response = ldap_connection.extend.standard.who_am_i()
                if isinstance(whoami_response, str) and whoami_response.startswith("u:"):
                    # Response format is "u:DOMAIN\\username" or "u:username"
                    identity_string = whoami_response[2:]
                    if "\\" in identity_string:
                        domain_part, username_part = identity_string.split("\\", 1)
                        self.username = username_part
                        if not self.domain:
                            self.domain = domain_part.upper()
                    else:
                        self.username = identity_string
        except Exception:
            pass

    @property
    def connection(self):
        """Return the current connection."""
        return self._connection