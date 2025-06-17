from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from nxc.data.coercer_method.DCERPCSessionError import DCERPCSessionError


class IsPathSupported(NDRCALL):
    """Structure to make the RPC call to IsPathSupported() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)"""
    opnum = 8
    structure = (
        ("ShareName", WSTR),  # Type: LPWSTR
    )


class IsPathSupportedResponse(NDRCALL):
    """Structure to parse the response of the RPC call to IsPathSupported() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)"""
    structure = ()


def request(dce, target, listener):
    request = IsPathSupported()
    request["ShareName"] = f"{listener}\x00"
    dce.request(request)