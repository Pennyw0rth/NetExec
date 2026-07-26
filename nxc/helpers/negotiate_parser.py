# Parsing helpers for auth negotiation: NTLM challenges and TDS ERROR/INFO on MSSQL LOGIN7.
# Original NTLM parsing from: https://github.com/fortra/impacket/blob/master/examples/DumpNTLMInfo.py#L568

import struct

from impacket import ntlm
from impacket.smb3 import WIN_VERSIONS
from impacket.tds import TDS_ERROR_TOKEN, TDS_INFO_TOKEN, TDS_INFO_ERROR
import contextlib


def parse_challenge(challange):
    target_info = {
        "hostname": None,
        "domain": None,
        "os_version": None
    }
    challange = ntlm.NTLMAuthChallenge(challange)
    av_pairs = ntlm.AV_PAIRS(challange["TargetInfoFields"][:challange["TargetInfoFields_len"]])
    if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
        with contextlib.suppress(Exception):
            target_info["hostname"] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode("utf-16le")
    if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
        with contextlib.suppress(Exception):
            target_info["domain"] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode("utf-16le")
    if "Version" in challange.fields:
        version = challange["Version"]
        if len(version) >= 4:
            major_version = version[0]
            minor_version = version[1]
            product_build = struct.unpack("<H", version[2:4])[0]
            if product_build in WIN_VERSIONS:
                target_info["os_version"] = f"{WIN_VERSIONS[product_build]} Build {product_build}"
            else:
                target_info["os_version"] = f"{major_version}.{minor_version} Build {product_build}"
    return target_info


def decode_tds_info_error_msgtext(data, offset):
    """Extract MsgText from a TDS ERROR (0xAA) or INFO (0xAB) token at *offset*.

    Official spec: [MS-TDS] Tabular Data Stream Protocol (Microsoft Learn).
    Token layout per MS-TDS 2.2.7.9 (INFO) / 2.2.7.10 (ERROR):
        TokenType   BYTE        0xAA | 0xAB
        Length      USHORT LE   byte count of the remaining fields
        Number      LONG LE     error / info number
        State       BYTE
        Class       BYTE        severity
        MsgText     US_VARCHAR  (2-byte LE length prefix + UTF-16LE)
        ...         (ServerName, ProcName, LineNumber follow but are unused here)

    The minimum *Length* value for a valid token is 8: Number(4) + State(1) +
    Class(1) + MsgText length prefix(2, may be zero-length string).

    References (Microsoft Learn, MS-TDS):
        INFO: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/284bb815-d083-4ed5-b33a-bdc2492e322b
        ERROR: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/9805e9fa-1f8b-4cf8-8f78-8d2602228635
        Data packet stream tokens: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/f79bb5b8-5919-439a-a696-48064b78b091
    """
    remaining = len(data) - offset
    if remaining < 3 or data[offset] not in (TDS_ERROR_TOKEN, TDS_INFO_TOKEN):
        return None

    # Length (USHORT LE) after TokenType, see MS-TDS INFO/ERROR links in docstring
    payload_len = int.from_bytes(data[offset + 1 : offset + 3], "little")

    if payload_len < 8 or remaining < 3 + payload_len:
        return None
    try:
        token = TDS_INFO_ERROR(data[offset:])
        text = token["MsgText"].decode("utf-16le").strip()
    except Exception:
        return None
    return text or None


def login7_integrated_auth_error_message(packet_data, data_after_login_header):
    """Scan raw LOGIN7 response buffers for the first ERROR/INFO message.

    When a server does not support Integrated Windows Authentication it replies
    to the LOGIN7 NTLMSSP negotiate with a TDS error token instead of an
    NTLMSSP challenge.  This helper locates the first ERROR (0xAA) or INFO
    (0xAB) token in either the full packet or the payload after the 3-byte
    LOGIN7 response header and returns its MsgText.
    """
    token_markers = (TDS_ERROR_TOKEN, TDS_INFO_TOKEN)
    for buf in filter(None, (packet_data, data_after_login_header)):
        for offset in (i for i in range(len(buf)) if buf[i] in token_markers):
            msg = decode_tds_info_error_msgtext(buf, offset)
            if msg:
                return msg
    return None
