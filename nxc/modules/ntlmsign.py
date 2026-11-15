from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.smb3structs import SMB2SessionSetup, SMB2SessionSetup_Response, SMB2_SESSION_SETUP

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

        host = connection.host

        if signed_ok and not unsigned_ok:
            context.log.success(f"{host} - NTLM signing ENFORCED (unsigned {label} rejected, signed accepted)")
        elif signed_ok and unsigned_ok:
            context.log.highlight(f"{host} - NTLM signing NOT enforced (signed and unsigned {label}s both accepted)")
        else:
            state = "inconclusive" if not unsigned_ok else "UNEXPECTED (unsigned ok, signed failed)"
            context.log.fail(f"{host} - {state}: signed={signed_msg!r} unsigned={unsigned_msg!r}")

    def _bind_smb(self, context, c, sign):
        """One full NTLM authentication. Returns (success, status_string)."""
        label = "signed" if sign else "unsigned"
        conn = None
        try:
            conn = SMBConnection(remoteName=c.host, remoteHost=c.host, sess_port=getattr(c, "port", 445), timeout=10)
            smb = conn.getSMBServer()
            if not hasattr(smb, "_Connection"):
                return False, "SMB1 dialect negotiated, not supported"
            
            # Type 1
            negotiate = getNTLMSSPType1(signingRequired=sign)
            blob1 = SPNEGO_NegTokenInit()
            blob1["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
            blob1["MechToken"] = negotiate.getData()

            ss1 = SMB2SessionSetup()
            ss1["Flags"] = 0
            ss1["SecurityMode"] = smb._Connection["ClientSecurityMode"]
            ss1["Capabilities"] = smb._Connection["Capabilities"]
            ss1["Channel"] = 0
            ss1["PreviousSessionId"] = 0
            ss1["SecurityBufferOffset"] = 0x58
            ss1["SecurityBufferLength"] = len(blob1)
            ss1["Buffer"] = blob1.getData()

            pkt1 = smb.SMB_PACKET()
            pkt1["Command"] = SMB2_SESSION_SETUP
            pkt1["SessionID"] = 0
            pkt1["Data"] = ss1
            pkt1_id = smb.sendSMB(pkt1)
            resp1 = smb.recvSMB(pkt1_id)

            session_id = resp1["SessionID"]
            resp1_data = SMB2SessionSetup_Response(resp1["Data"])

            spnego_resp = SPNEGO_NegTokenResp(resp1_data["Buffer"])

            # Type 2
            challenge = bytes(spnego_resp["ResponseToken"])

            smb._Session["SessionID"] = session_id

            # Type 3
            type3, _ = getNTLMSSPType3(
                negotiate, challenge,
                c.username or "",
                c.password or "",
                c.domain or "",
                c.lmhash or "",
                c.nthash or "",
            )
            auth_token = SPNEGO_NegTokenResp()
            auth_token["ResponseToken"] = type3.getData()
            blob2 = auth_token.getData()

            ss2 = SMB2SessionSetup()
            ss2["Flags"] = 0
            ss2["SecurityMode"] = smb._Connection["ClientSecurityMode"]
            ss2["Capabilities"] = smb._Connection["Capabilities"]
            ss2["Channel"] = 0
            ss2["PreviousSessionId"] = 0
            ss2["SecurityBufferOffset"] = 0x58
            ss2["SecurityBufferLength"] = len(blob2)
            ss2["Buffer"] = blob2

            pkt2 = smb.SMB_PACKET()
            pkt2["Command"] = SMB2_SESSION_SETUP
            pkt2["SessionID"] = session_id
            pkt2["Data"] = ss2
            pkt2_id = smb.sendSMB(pkt2)
            resp2 = smb.recvSMB(pkt2_id)
            status = resp2["Status"]
            context.log.debug(f"[smb:{label}] status={status:#010x}")
            return status == 0, f"STATUS={status:#010x}"
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
