
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
        if getattr(connection.args, "kerberos", False):
            context.log.fail(f"{connection.host} - Kerberos auth in use, NTLM check not applicable")
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

        host = connection.host

        if signed_ok and not unsigned_ok:
            context.log.success(f"{host} - NTLM signing ENFORCED (unsigned {label} rejected, signed accepted)")
        elif signed_ok and unsigned_ok:
            context.log.highlight(f"{host} - NTLM signing NOT enforced (signed and unsigned {label}s accepted)")
        else:
            state = "inconclusive" if not unsigned_ok else "UNEXPECTED (unsigned ok, signed failed)"
            context.log.fail(f"{host} - {state}: signed={signed_msg!r} unsigned={unsigned_msg!r}")

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
