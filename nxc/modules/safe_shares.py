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

FILE_OPEN             = 0x00000001
FILE_ADD_FILE         = 0x00000002  # FILE_WRITE_DATA on a directory
FILE_ADD_SUBDIRECTORY = 0x00000004  # FILE_APPEND_DATA on a directory
WRITE_DAC             = 0x00040000
WRITE_OWNER           = 0x00080000

# Ordered list of (access_mask, label) write checks.
# Labels are deduplicated — first match per label wins.
WRITE_CHECKS = [
    (GENERIC_WRITE,          "WRITE"),
    (FILE_ADD_FILE,          "WRITE"),
    (FILE_ADD_SUBDIRECTORY,  "WRITE (SUBDIR)"),
    (WRITE_DAC,              "WRITE (ACL)"),
    (WRITE_OWNER,            "WRITE (ACL)"),
]


class NXCModule:
    """
    Non-destructive SMB share permission enumeration.
    Tests READ/WRITE access without writing any files to disk.
    Mirrors SharpShares' ACL-based approach via impacket.

    Write detection covers:
      WRITE        — GENERIC_WRITE or FILE_ADD_FILE (immediate file placement)
      WRITE (SUBDIR) — FILE_ADD_SUBDIRECTORY (directory creation)
      WRITE (ACL)  — WRITE_DAC or WRITE_OWNER (ACL escalation path to write)

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
                     WRITE matches WRITE, WRITE (SUBDIR), and WRITE (ACL)
        """
        exclude_str = module_options.get("EXCLUDE", "IPC$,print$")
        self.exclude = [s.strip().upper() for s in exclude_str.split(",") if s.strip()]
        self.filter_access = module_options.get("FILTER", "ALL").upper()

    def _check_access(self, conn, share_name, mask):
        """Open share root with FILE_OPEN + given mask. Returns True on success."""
        tid = None
        try:
            tid = conn.connectTree(share_name)
            fid = conn.openFile(
                tid,
                "\\",
                desiredAccess=mask,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationDisposition=FILE_OPEN,
                fileAttributes=0,
                creationOption=FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            )
            conn.closeFile(tid, fid)
            return True
        except (SessionError, Exception):
            return False
        finally:
            if tid:
                try:
                    conn.disconnectTree(tid)
                except Exception:
                    pass

    def on_login(self, context, connection):
        results = []

        try:
            shares = connection.conn.listShares()
        except Exception as e:
            context.log.fail(f"Failed to list shares: {e}")
            return

        for share in shares:
            share_name   = share["shi1_netname"][:-1]
            share_remark = share["shi1_remark"][:-1]

            if share_name.upper() in self.exclude:
                context.log.debug(f"Skipping excluded share: {share_name}")
                continue

            access = []

            # READ — non-destructive directory listing
            try:
                connection.conn.listPath(share_name, "\\*")
                access.append("READ")
            except SessionError as e:
                context.log.debug(f"No READ on {share_name}: {e}")
            except Exception as e:
                context.log.debug(f"READ check error on {share_name}: {e}")

            # WRITE checks — FILE_OPEN only, nothing written to disk
            seen_labels = set()
            write_labels = []
            for mask, label in WRITE_CHECKS:
                if label in seen_labels:
                    continue
                if self._check_access(connection.conn, share_name, mask):
                    write_labels.append(label)
                    seen_labels.add(label)
                    context.log.debug(f"{label} confirmed on {share_name} (mask=0x{mask:08x})")

            # If plain WRITE is achievable, suppress SUBDIR and ACL — they are redundant
            if "WRITE" in write_labels:
                write_labels = ["WRITE"]

            access.extend(write_labels)

            access_str = ",".join(access) if access else ""

            # Apply filter — "WRITE" matches WRITE, WRITE (SUBDIR), WRITE (ACL)
            if self.filter_access != "ALL":
                if self.filter_access not in access_str.upper():
                    continue

            results.append((share_name, access_str, share_remark))

        c_share  = max(len(name) for name, _, _ in results) + 2 if results else 20
        c_access = max(len(acc)  for _, acc, _ in results) + 2 if results else 20

        context.log.display("Enumerated shares (no disk writes)")
        context.log.highlight(f"{'Share':<{c_share}} {'Access':<{c_access}} {'Remark'}")
        context.log.highlight(f"{'-----':<{c_share}} {'------':<{c_access}} {'------'}")
        for name, access_str, remark in results:
            context.log.highlight(f"{name:<{c_share}} {access_str:<{c_access}} {remark}")
