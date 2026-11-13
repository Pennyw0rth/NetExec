
from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3

from nxc.helpers.misc import CATEGORY
import contextlib


class NXCModule:
    """
    Checks whether a target enforces NTLM signing (KB5135557 / ServerRequireNtlmSign)
    by doing two NTLM authentications with the same creds, one negotiating signing
    and one not. Unsigned rejected + signed accepted = enforced.
    """

    name = "ntlmsign"
    description = "Checks NTLM signing enforcement (KB5135557 / ServerRequireNtlmSign)"
    supported_protocols = ["smb", "ldap"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        args = connection.args
        method = "NTLM"

        if getattr(args, "kerberos", False) or getattr(args, "use_kcache", False):
            method = "Kerberos"
        elif any(getattr(args, a, None) for a in ("pfx_cert", "pfx_base64", "pem_cert", "pem_key")):
            method = "Schannel/certificate"
        elif getattr(args, "simple_bind", False):
            method = "LDAP simple bind"

        if method != "NTLM":
            context.log.fail(f"Auth method {method} not valid. NTLM signing check not applicable.")
            return

        username = (connection.username or "").strip()
        password = connection.password or ""
        nthash = getattr(connection, "nthash", "") or ""
        lmhash = getattr(connection, "lmhash", "") or ""

        is_null_session = not username or (not password and not nthash and not lmhash)
        is_guest = username.lower() == "guest"

        if is_null_session or is_guest:
            context.log.fail(f"{connection.host} - null/guest auth is exempt from ServerRequireNtlmSign (KB5135557). Re-run with a non-guest account")
            return

        if connection.args.protocol == "smb":
            signed_ok, signed_msg = self._bind_smb(context, connection, True)
            unsigned_ok, unsigned_msg = self._bind_smb(context, connection, False)
            label = "login"
        elif connection.args.protocol == "ldap":
            signed_ok, signed_msg = self._bind_ldap(context, connection, True)
            unsigned_ok, unsigned_msg = self._bind_ldap(context, connection, False)
            label = "bind"
        else:
            context.log.fail(f"{connection.host} - unsupported protocol {connection.args.protocol!r}")
            return

    def _bind_smb(self, context, c, sign):
        """One full SMB NTLM login. Returns (success, diagnostic_message)."""
        label = "signed" if sign else "unsigned"
        conn = None
        try:
            conn = SMBConnection(c.host, c.host, sess_port=getattr(c, "port", 445), timeout=10)
            server = conn.getSMBServer()
            if not hasattr(server, "_Connection"):
                return False, "SMB1 dialect negotiated, not supported"

            # Controls the NTLM Type1 signing flag (and client-side signing after login)
            server._Connection["RequireSigning"] = sign

            conn.login(
                c.username,
                c.password or "",
                c.domain or "",
                c.lmhash or "",
                c.nthash or "",
            )
            context.log.debug(f"[smb:{label}] login ok")
            return True, "STATUS_SUCCESS"
        except Exception as e:
            context.log.debug(f"[smb:{label}] login error: {e!r}")
            return False, str(e)
        finally:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()

    def _bind_ldap(self, context, c, sign):
        """One full sicily bind. Returns (success, diagnostic_message)."""
        label = "signed" if sign else "unsigned"
        try:
            conn = ldap_impacket.LDAPConnection(f"ldap://{c.host}", dstIp=c.host)

            negotiate = getNTLMSSPType1(signingRequired=sign)
            req = ldapasn1_impacket.BindRequest()
            req["version"] = 3
            req["name"] = ""
            req["authentication"]["sicilyNegotiate"] = negotiate.getData()
            resp = conn.sendReceive(req)[0]["protocolOp"]
            challenge = bytes(resp["bindResponse"]["matchedDN"])

            type3, _ = getNTLMSSPType3(
                negotiate, challenge, c.username, c.password or "", c.domain or "",
                c.lmhash or "", c.nthash or "",
            )
            req = ldapasn1_impacket.BindRequest()
            req["version"] = 3
            req["name"] = c.username
            req["authentication"]["sicilyResponse"] = type3.getData()
            resp = conn.sendReceive(req)[0]["protocolOp"]["bindResponse"]

            code, msg = int(resp["resultCode"]), str(resp["diagnosticMessage"])
            context.log.debug(f"[ldap:{label}] resultCode={code} msg={msg!r}")
            return code == 0, msg
        except Exception as e:
            context.log.debug(f"[ldap:{label}] bind error: {e!r}")
            return False, str(e)
