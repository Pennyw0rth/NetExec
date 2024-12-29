# Original Author:
#  Dirk-jan Mollema (@_dirkjan)
#  dlive (@D1iv3)
#
# Refernece:
#  - https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/
#  - https://github.com/fox-it/cve-2019-1040-scanner
#  - https://github.com/Dliv3/cve-2019-1040-scanner
#
# Modify by:
#  XiaoliChan (@Memory_before)

import calendar
import struct
import time
import random
import string

from impacket import ntlm
from impacket import nt_errors
from impacket.smbconnection import SessionError


class NXCModule:
    name = "remove-mic"
    description = "Check if host vulnerable to CVE-2019-1040"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """PORT    Port to check (defaults to 445)"""
        self.port = 445
        if "PORT" in module_options:
            self.port = int(module_options["PORT"])

    def on_login(self, context, connection):
        ntlm.computeResponseNTLMv2 = Modify_Func.mod_computeResponseNTLMv2
        ntlm.getNTLMSSPType3 = Modify_Func.mod_getNTLMSSPType3
        try:
            connection.conn.reconnect()
        except SessionError as e:
            if e.getErrorCode() == nt_errors.STATUS_INVALID_PARAMETER:
                context.log.info("Target is not vulnerable to CVE-2019-1040 (authentication was rejected)")
            else:
                context.log.info("Unexpected Exception while authentication")
        else:
            context.log.highlight("Potentially vulnerable to CVE-2019-1040, next step: https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/")

class Modify_Func:
    # Slightly modified version of impackets computeResponseNTLMv2
    def mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash="", nthash="",
                    use_ntlmv2=ntlm.USE_NTLMv2, channel_binding_value=b""):

        responseServerVersion = b"\x01"
        hiResponseServerVersion = b"\x01"
        responseKeyNT = ntlm.NTOWFv2(user, password, domain, nthash)

        av_pairs = ntlm.AV_PAIRS(serverName)
        # In order to support SPN target name validation, we have to add this to the serverName av_pairs. Otherwise we will
        # get access denied
        # This is set at Local Security Policy -> Local Policies -> Security Options -> Server SPN target name validation
        # level
        av_pairs[ntlm.NTLMSSP_AV_TARGET_NAME] = "cifs/".encode("utf-16le") + av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1]
        if av_pairs[ntlm.NTLMSSP_AV_TIME] is not None:
            aTime = av_pairs[ntlm.NTLMSSP_AV_TIME][1]
        else:
            aTime = struct.pack("<q", (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))
            av_pairs[ntlm.NTLMSSP_AV_TIME] = aTime
        av_pairs[ntlm.NTLMSSP_AV_FLAGS] = b"\x02" + b"\x00" * 3
        serverName = av_pairs.getData()

        if len(channel_binding_value) > 0:
            av_pairs[ntlm.NTLMSSP_AV_CHANNEL_BINDINGS] = channel_binding_value

        # Format according to:
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b
        temp = responseServerVersion  # RespType 1 byte
        temp += hiResponseServerVersion  # HiRespType 1 byte
        temp += b"\x00" * 2  # Reserved1 2 bytes
        temp += b"\x00" * 4  # Reserved2 4 bytes
        temp += aTime  # TimeStamp 8 bytes
        temp += clientChallenge  # ChallengeFromClient 8 bytes
        temp += b"\x00" * 4  # Reserved 4 bytes
        temp += av_pairs.getData()  # AvPairs variable

        ntProofStr = ntlm.hmac_md5(responseKeyNT, serverChallenge + temp)

        ntChallengeResponse = ntProofStr + temp
        lmChallengeResponse = ntlm.hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
        sessionBaseKey = ntlm.hmac_md5(responseKeyNT, ntProofStr)

        if user == "" and password == "":
            # Special case for anonymous authentication
            ntChallengeResponse = ""
            lmChallengeResponse = ""

        return ntChallengeResponse, lmChallengeResponse, sessionBaseKey
    
    def mod_getNTLMSSPType3(type1, type2, user, password, domain, lmhash="", nthash="", use_ntlmv2=ntlm.USE_NTLMv2, channel_binding_value=b""):
        # Safety check in case somebody sent password = None.. That's not allowed. Setting it to '' and hope for the best.
        if password is None:
            password = ""

        # Let's do some encoding checks before moving on. Kind of dirty, but found effective when dealing with
        # international characters.
        import sys
        encoding = sys.getfilesystemencoding()
        if encoding is not None:
            try:
                user.encode("utf-16le")
            except Exception:
                user = user.decode(encoding)
            try:
                password.encode("utf-16le")
            except Exception:
                password = password.decode(encoding)
            try:
                domain.encode("utf-16le")
            except Exception:
                domain = user.decode(encoding)

        ntlmChallenge = ntlm.NTLMAuthChallenge(type2)

        # Let's start with the original flags sent in the type1 message
        responseFlags = type1["flags"]

        # Token received and parsed. Depending on the authentication 
        # method we will create a valid ChallengeResponse
        ntlmChallengeResponse = ntlm.NTLMAuthChallengeResponse(user, password, ntlmChallenge["challenge"])

        clientChallenge = ntlm.b("".join([random.choice(string.digits + string.ascii_letters) for _ in range(8)]))

        serverName = ntlmChallenge["TargetInfoFields"]

        ntResponse, lmResponse, sessionBaseKey = ntlm.computeResponse(ntlmChallenge["flags"], ntlmChallenge["challenge"],
                                                                clientChallenge, serverName, domain, user, password,
                                                                lmhash, nthash, use_ntlmv2, channel_binding_value=channel_binding_value)

        # Let's check the return flags
        if (ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) == 0:
            # No extended session security, taking it out
            responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        if (ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_128) == 0:
            # No support for 128 key len, taking it out
            responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_128
        if (ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH) == 0:
            # No key exchange supported, taking it out
            responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH

        # drop the mic need to unset these flags
        # https://github.com/fortra/impacket/blob/master/impacket/examples/ntlmrelayx/clients/ldaprelayclient.py#L72
        if ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_SEAL == ntlm.NTLMSSP_NEGOTIATE_SEAL:
            responseFlags ^= ntlm.NTLMSSP_NEGOTIATE_SEAL
        if ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_SIGN == ntlm.NTLMSSP_NEGOTIATE_SIGN:
            responseFlags ^= ntlm.NTLMSSP_NEGOTIATE_SIGN
        if ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN == ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
            responseFlags ^= ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN


        keyExchangeKey = ntlm.KXKEY(ntlmChallenge["flags"], sessionBaseKey, lmResponse, ntlmChallenge["challenge"], password,
                            lmhash, nthash, use_ntlmv2)

        # Special case for anonymous login
        if user == "" and password == "" and lmhash == "" and nthash == "":
            keyExchangeKey = b"\x00" * 16


        if ntlmChallenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
            exportedSessionKey = ntlm.b("".join([random.choice(string.digits + string.ascii_letters) for _ in range(16)]))
            encryptedRandomSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey)
        else:
            encryptedRandomSessionKey = None
            exportedSessionKey = keyExchangeKey

        ntlmChallengeResponse["flags"] = responseFlags
        ntlmChallengeResponse["domain_name"] = domain.encode("utf-16le")
        ntlmChallengeResponse["host_name"] = type1.getWorkstation().encode("utf-16le")
        if lmResponse == "":
            ntlmChallengeResponse["lanman"] = b"\x00"
        else:
            ntlmChallengeResponse["lanman"] = lmResponse
        ntlmChallengeResponse["ntlm"] = ntResponse
        if encryptedRandomSessionKey is not None: 
            ntlmChallengeResponse["session_key"] = encryptedRandomSessionKey

        return ntlmChallengeResponse, exportedSessionKey