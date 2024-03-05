# Original from here: https://github.com/fortra/impacket/blob/master/examples/DumpNTLMInfo.py#L568

import struct

from impacket import ntlm
from impacket.smb3 import WIN_VERSIONS
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