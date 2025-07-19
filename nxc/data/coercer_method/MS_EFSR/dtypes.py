from impacket.dcerpc.v5.ndr import NDRSTRUCT
from impacket.dcerpc.v5.dtypes import DWORD, PCHAR, RPC_SID, LPWSTR


class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_HASH_BLOB),
        ("Display", LPWSTR),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    structure = (
        ("nUsers", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ("Cert", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )