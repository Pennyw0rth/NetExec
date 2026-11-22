from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from impacket.smb3structs import SMB2SessionSetup, SMB2SessionSetup_Response, SMB2_SESSION_SETUP, SMB2_DIALECT_30
from nxc.helpers.misc import CATEGORY
import contextlib


class NXCModule:
    """
    Checks whether a target enforces NTLM signing (KB5135557 / ServerRequireNtlmSign)
    by doing two NTLM authentications with the same creds, one negotiating signing
    and one not. Unsigned rejected + signed accepted = enforced.

    Module by @SoftAndoWetto
    """

    name = "ntlmsign"
    description = "Actively probes NTLM signing enforcement (KB5135557 / ServerRequireNtlmSign)"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        if (connection.kerberos or connection.args.pfx_cert or connection.args.pfx_base64
                or connection.args.pem_cert or connection.args.pem_key
                or (connection.args.protocol == "ldap" and connection.args.simple_bind)):
            context.log.fail("Non-NTLM auth detected. NTLM signing check not applicable.")
            return

        if not connection.username or not (connection.password or connection.nthash or connection.lmhash):
            self.context.log.fail(f"{connection.host} - requires a username and credential. Re-run with a non-guest account.")
            return

        if connection.args.protocol == "smb":
            signed_ok, signed_msg = self._bind_smb(True)
            unsigned_ok, unsigned_msg = self._bind_smb(False)
            label = "login"

        elif connection.args.protocol == "ldap":
            signed_ok, signed_msg = self._bind_ldap(True)
            unsigned_ok, unsigned_msg = self._bind_ldap(False)
            label = "bind"

        if signed_ok and not unsigned_ok:
            self.context.log.display(f"{connection.host} - NTLM signing ENFORCED (unsigned {label} rejected, signed accepted)")
        elif signed_ok and unsigned_ok:
            self.context.log.highlight(f"{connection.host} - NTLM signing NOT enforced (signed and unsigned {label}s both accepted)")
        else:
            state = "inconclusive" if not unsigned_ok else "UNEXPECTED (unsigned ok, signed failed)"
            self.context.log.fail(f"{connection.host} - {state}: signed={signed_msg!r} unsigned={unsigned_msg!r}")

    def _bind_smb(self, sign):
        """One full NTLM authentication. Returns (success, status_string)."""
        label = "signed" if sign else "unsigned"
        conn = None
        try:
            conn = SMBConnection(
                remoteName=self.connection.host,
                remoteHost=self.connection.host,
                sess_port=445,
                preferredDialect=SMB2_DIALECT_30,
                timeout=10
            )

            smb = conn.getSMBServer()

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
                self.connection.username,
                self.connection.password,
                self.connection.domain,
                self.connection.lmhash,
                self.connection.nthash,
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
            self.context.log.debug(f"[smb:{label}] status={status:#010x}")
            return status == 0, f"STATUS={status:#010x}"
        except Exception as e:
            self.context.log.debug(f"[smb:{label}] login error: {e!r}")
            return False, str(e)
        finally:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()

    def _bind_ldap(self, sign):
        """One full sicily bind. Returns (success, diagnostic_message)."""
        label = "signed" if sign else "unsigned"
        try:
            conn = ldap_impacket.LDAPConnection(f"ldap://{self.connection.host}", dstIp=self.connection.host)

            negotiate = getNTLMSSPType1(signingRequired=sign)
            req = ldapasn1_impacket.BindRequest()
            req["version"] = 3
            req["name"] = ""
            req["authentication"]["sicilyNegotiate"] = negotiate.getData()
            resp = conn.sendReceive(req)[0]["protocolOp"]
            challenge = bytes(resp["bindResponse"]["matchedDN"])

            type3, _ = getNTLMSSPType3(
                negotiate,
                challenge,
                self.connection.username,
                self.connection.password,
                self.connection.domain,
                self.connection.lmhash,
                self.connection.nthash,
            )
            req = ldapasn1_impacket.BindRequest()
            req["version"] = 3
            req["name"] = self.connection.username
            req["authentication"]["sicilyResponse"] = type3.getData()
            resp = conn.sendReceive(req)[0]["protocolOp"]["bindResponse"]

            code, msg = int(resp["resultCode"]), str(resp["diagnosticMessage"])
            self.context.log.debug(f"[ldap:{label}] resultCode={code} msg={msg!r}")
            return code == 0, msg
        except Exception as e:
            self.context.log.debug(f"[ldap:{label}] bind error: {e!r}")
            return False, str(e)
