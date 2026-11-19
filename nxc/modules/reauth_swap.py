import binascii
import contextlib

from impacket import ntlm
from impacket.smb3 import SMB2SessionSetup, SMB2SessionSetup_Response
from impacket.smb3structs import SMB2_SESSION_SETUP
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from nxc.helpers.misc import CATEGORY
from nxc.helpers.smb import get_smb_connection


class NXCModule:
    """
    Module made by: Lyderic Lefebvre (@aas_s3curity) - https://blackfield.ch

    Check if an SMB server still allows a cross-user re-authentication swap on an existing session:
    log in as one account, then re-authenticate as a different one on the same connection. That swap
    is the primitive an auth relay uses to keep a privileged session under a signing key it controls,
    defeating enforced SMB signing. Recent Windows builds allow same-user re-auth only and refuse the
    swap with ACCESS_DENIED. Microsoft fixed this server-side as CVE-2026-69676 (September 2026
    cumulative updates). Not derivable from the build number (feature-flagged: the same build can
    allow or refuse it), so it is probed live.
    https://blackfield.ch/blog/defeating-enforced-smb-signing/
    """
    name = "reauth_swap"
    description = "Check if the server allows a cross-user re-auth swap on an SMB session (used to defeat enforced signing); needs a 2nd account"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    STATUS_SUCCESS = 0x00000000
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234

    def options(self, context, module_options):
        """
        PROBE_USER      second account, must differ from the login account (required)
        PROBE_PASS      second account password
        PROBE_NTHASH    second account NT hash (instead of PROBE_PASS)

        The second account is probed over NTLM; its privileges do not matter.

        Lockout warning: every target triggers one real NTLM logon as PROBE_USER
        (in the login account's domain). A correct password never increments
        badPwdCount, whether the host is patched (ACCESS_DENIED) or not (SUCCESS).
        A wrong PROBE_PASS/PROBE_NTHASH, or a PROBE_USER that does not exist in that
        domain, returns LOGON_FAILURE and raises badPwdCount once per host.
        Validate PROBE_USER on a single host before running wide.
        """
        self.probe_user = module_options.get("PROBE_USER")
        self.probe_pass = module_options.get("PROBE_PASS", "")
        self.probe_nthash = module_options.get("PROBE_NTHASH", "")
        if not self.probe_user:
            context.log.fail("reauth_swap requires a second account: -o PROBE_USER=<user> PROBE_PASS=<pass> (must differ from the account nxc logged in with)")
            return False
        if not self.probe_pass and not self.probe_nthash:
            context.log.fail("reauth_swap requires PROBE_PASS or PROBE_NTHASH for the second account")
            return False

    def on_login(self, context, connection):
        if self.probe_user.lower() == (connection.username or "").lower():
            context.log.fail("PROBE_USER must differ from the account nxc logged in with: only a cross-user swap is refused, so the same account always succeeds and tests nothing")
            return

        # without enforced signing there is nothing to bypass: a relayed auth is accepted directly
        if not connection.signing:
            context.log.info("SMB signing not enforced, nothing to bypass - skipping")
            return

        try:
            # fresh session so nxc's own connection is left untouched
            new_conn = get_smb_connection(context, connection, timeout=connection.args.smb_timeout)
            try:
                status = self.reauth_as(new_conn.getSMBServer(), self.probe_user, self.probe_pass, connection.domain, self.probe_nthash)
            finally:
                with contextlib.suppress(Exception):
                    new_conn.close()
        except Exception as e:
            context.log.fail(f"could not probe this host: {e.__class__.__name__}: {e}")
            return

        if status == self.STATUS_SUCCESS:
            context.log.highlight("VULNERABLE - enforced SMB signing bypassable")
            context.log.highlight("Next step: https://blackfield.ch/blog/defeating-enforced-smb-signing/")
        elif status == self.STATUS_ACCESS_DENIED:
            context.log.display("not vulnerable - cross-user re-auth swap refused (ACCESS_DENIED), same-user re-auth only")
        elif status == self.STATUS_LOGON_FAILURE:
            context.log.fail("PROBE_USER login failed (LOGON_FAILURE) - stop before repeated attempts lock the account out")
        elif status == self.STATUS_ACCOUNT_LOCKED_OUT:
            context.log.fail("PROBE_USER is locked out (ACCOUNT_LOCKED_OUT) - stop and let it reset")
        else:
            context.log.display(f"inconclusive - second session setup returned 0x{status:08X}")

    def reauth_as(self, smb, user, password, domain, nthash):
        """Replay an NTLM (Type1/Type3) session setup as `user` on an EXISTING session; return the NTSTATUS."""
        # Create NTLM Type1 message (challenge)
        type1 = ntlm.getNTLMSSPType1("", domain)
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = type1.getData()

        setup = SMB2SessionSetup()
        setup["Flags"] = 0
        setup["SecurityMode"] = 1
        setup["SecurityBufferLength"] = len(blob.getData())
        setup["Buffer"] = blob.getData()
        pkt = smb.SMB_PACKET()
        pkt["Command"] = SMB2_SESSION_SETUP
        pkt["Data"] = setup

        ans = smb.recvSMB(smb.sendSMB(pkt))
        if ans["Status"] != self.STATUS_MORE_PROCESSING_REQUIRED:
            return ans["Status"]

        resp = SMB2SessionSetup_Response(ans["Data"])
        try:
            type2 = SPNEGO_NegTokenResp(resp["Buffer"])["ResponseToken"]
        except Exception:
            raw = resp["Buffer"]
            type2 = raw[raw.index(b"NTLMSSP"):]

        lm = nt = ""
        if nthash:
            lm = binascii.unhexlify("aad3b435b51404eeaad3b435b51404ee")
            nt = binascii.unhexlify(nthash)

        # Create NTLM Type3 message (authentication)
        type3, _ = ntlm.getNTLMSSPType3(type1, type2, user, password, domain, lmhash=lm, nthash=nt)
        blob2 = SPNEGO_NegTokenResp()
        blob2["ResponseToken"] = type3.getData()

        setup2 = SMB2SessionSetup()
        setup2["Flags"] = 0
        setup2["SecurityMode"] = 1
        setup2["SecurityBufferLength"] = len(blob2.getData())
        setup2["Buffer"] = blob2.getData()

        pkt2 = smb.SMB_PACKET()
        pkt2["Command"] = SMB2_SESSION_SETUP
        pkt2["Data"] = setup2

        ans2 = smb.recvSMB(smb.sendSMB(pkt2))
        return ans2["Status"]
