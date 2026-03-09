from impacket.smbconnection import SessionError
from impacket.smb3structs import (
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_SHARE_DELETE,
    GENERIC_WRITE,
    FILE_DIRECTORY_FILE,
    FILE_SYNCHRONOUS_IO_NONALERT,
)
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Non-destructive SMB share permission enumeration.
    Tests READ/WRITE access without writing any files to disk.
    Mirrors SharpShares' ACL-based approach via impacket.

    Module by @e-nzym3
    """

    name = "safe_shares"
    description = "Enumerate SMB share permissions without writing to disk (SharpShares-style)"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.exclude = []
        self.filter_access = "ALL"

    def options(self, context, module_options):
        """
        EXCLUDE      Comma-separated share names to skip (Default: IPC$,print$)
        FILTER       Show only shares with this access: READ, WRITE, NONE, ALL (Default: ALL)
        """
        exclude_str = module_options.get("EXCLUDE", "IPC$,print$")
        self.exclude = [s.strip().upper() for s in exclude_str.split(",") if s.strip()]
        self.filter_access = module_options.get("FILTER", "ALL").upper()

    def on_login(self, context, connection):
        results = []

        try:
            shares = connection.conn.listShares()
        except Exception as e:
            context.log.fail(f"Failed to list shares: {e}")
            return

        for share in shares:
            share_name = share["shi1_netname"][:-1]
            share_remark = share["shi1_remark"][:-1]

            if share_name.upper() in self.exclude:
                context.log.debug(f"Skipping excluded share: {share_name}")
                continue

            access = []

            # READ check — non-destructive (list directory)
            try:
                connection.conn.listPath(share_name, "\\*")
                access.append("READ")
            except SessionError as e:
                context.log.debug(f"No READ on {share_name}: {e}")
            except Exception as e:
                context.log.debug(f"READ check error on {share_name}: {e}")

            # WRITE check — non-destructive (open root dir with GENERIC_WRITE + FILE_OPEN)
            # FILE_OPEN (0x1) opens an existing object — never creates anything on disk
            tid = None
            try:
                tid = connection.conn.connectTree(share_name)
                fid = connection.conn.openFile(
                    tid,
                    "\\",
                    desiredAccess=GENERIC_WRITE,
                    shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    creationDisposition=0x00000001,  # FILE_OPEN
                    fileAttributes=0,
                    creationOption=FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                )
                connection.conn.closeFile(tid, fid)
                access.append("WRITE")
            except SessionError as e:
                context.log.debug(f"No WRITE on {share_name}: {e}")
            except Exception as e:
                context.log.debug(f"WRITE check error on {share_name}: {e}")
            finally:
                if tid:
                    try:
                        connection.conn.disconnectTree(tid)
                    except Exception:
                        pass

            access_str = ",".join(access) if access else "NO ACCESS"

            # Apply filter
            if self.filter_access != "ALL":
                if self.filter_access not in access_str.upper():
                    continue

            results.append((share_name, access_str, share_remark))

        context.log.display("Enumerated shares (no disk writes)")
        context.log.highlight(f"{'Share':<20} {'Access':<15} {'Remark'}")
        context.log.highlight(f"{'-----':<20} {'------':<15} {'------'}")
        for name, access_str, remark in results:
            context.log.highlight(f"{name:<20} {access_str:<15} {remark}")
