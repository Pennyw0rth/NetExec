import contextlib
import ntpath
import time

from nxc.helpers.misc import CATEGORY, gen_random_string
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout


def human_size(nbytes):
    suffixes = ["B", "KB", "MB", "GB", "TB"]
    for i in range(len(suffixes)):
        if nbytes < 1024 or i == len(suffixes) - 1:
            break
        nbytes /= 1024.0
    return f"{nbytes:.0f}{suffixes[i]}"


class NXCModule:
    name = "shares-plus"
    description = (
        "Recursively enumerate shares with per-directory permissions and file listing"
    )
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        DEPTH       Max recursion depth (default: 3, 0 = unlimited)
        EXCLUDE     Comma-separated shares/folders to exclude (default: print$,ipc$)
        DELTA       Only show dirs where permissions differ from parent (default: True)
        WRITE_CHECK Test write permissions per directory (default: True)
        FILES       Show files in each directory (default: True)
        """
        self.depth = int(module_options.get("DEPTH", 3))
        self.exclude = [
            s.lower()
            for s in module_options.get("EXCLUDE", "print$,ipc$").split(",")
            if s
        ]
        self.delta = module_options.get("DELTA", "True").lower() not in (
            "false",
            "0",
            "no",
        )
        self.write_check = module_options.get("WRITE_CHECK", "True").lower() not in (
            "false",
            "0",
            "no",
        )
        self.show_files = module_options.get("FILES", "True").lower() not in (
            "false",
            "0",
            "no",
        )

    def on_login(self, context, connection):
        crawler = ShareCrawler(
            connection,
            context.log,
            self.depth,
            self.exclude,
            self.delta,
            self.write_check,
            self.show_files,
        )
        crawler.run()


class ShareCrawler:
    def __init__(
        self, smb, logger, max_depth, exclude, delta_only, write_check, show_files
    ):
        self.smb = smb
        self.logger = logger
        self.max_depth = max_depth
        self.exclude = exclude
        self.delta_only = delta_only
        self.write_check = write_check
        self.show_files = show_files
        self.max_reconnect = 3
        self.results = {}

    def reconnect(self):
        for _i in range(self.max_reconnect):
            try:
                time.sleep(2)
                self.smb.create_conn_obj()
                self.smb.login()
                return True
            except Exception:
                continue
        return False

    def list_path(self, share, path):
        """Single listPath call — returns (dirs, files) or None if no access."""
        try:
            entries = self.smb.conn.listPath(share, path + "*")
        except SessionError as e:
            err = str(e)
            if any(
                s in err
                for s in (
                    "STATUS_ACCESS_DENIED",
                    "STATUS_OBJECT_PATH_NOT_FOUND",
                    "STATUS_STOPPED_ON_SYMLINK",
                )
            ):
                return None
            if self.reconnect():
                try:
                    entries = self.smb.conn.listPath(share, path + "*")
                except Exception:
                    return None
            else:
                return None
        except (NetBIOSTimeout, Exception):
            return None

        dirs = []
        files = []
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            if entry.is_directory():
                dirs.append(name)
            else:
                files.append((name, entry.get_filesize()))
        return dirs, files

    def can_write(self, share, path):
        if not self.write_check:
            return False
        temp_name = ntpath.normpath(path + "\\" + gen_random_string(8))
        try:
            self.smb.conn.createDirectory(share, temp_name)
            with contextlib.suppress(Exception):
                self.smb.conn.deleteDirectory(share, temp_name)
            return True
        except (SessionError, NetBIOSTimeout, Exception):
            return False

    def format_perms(self, read, write):
        parts = []
        if read:
            parts.append("READ")
        if write:
            parts.append("WRITE")
        return ",".join(parts) if parts else ""

    def spider_dir(self, share, path, depth, parent_read, parent_write):
        if self.max_depth and depth > self.max_depth:
            return

        result = self.list_path(share, path)
        read = result is not None
        write = self.can_write(share, path) if read else False

        if share not in self.results:
            self.results[share] = {}
        self.results[share][path] = {"read": read, "write": write}

        indent = "  " * depth

        if not read:
            if depth > 0:
                perms = self.format_perms(read, write) or "-"
                display_path = path.rstrip("\\")
                self.logger.highlight(f"{indent}\\_{display_path:<40} {perms}")
            return

        dirs, files = result

        # Show directory line: always if perms changed or has files; skip empty same-perm dirs in delta mode
        if depth > 0:
            perm_changed = read != parent_read or write != parent_write
            show = perm_changed or not self.delta_only or (self.show_files and files)
            if show:
                perms = self.format_perms(read, write) or "-"
                display_path = path.rstrip("\\")
                self.logger.highlight(f"{indent}\\_{display_path:<40} {perms}")

        # Show files
        if self.show_files and files:
            file_indent = "  " * (depth + 1)
            for fname, fsize in sorted(files):
                self.logger.display(f"{file_indent}{fname:<35} {human_size(fsize)}")

        # Recurse into subdirectories
        for dirname in sorted(dirs):
            if dirname.lower() in self.exclude:
                continue
            subpath = path + dirname + "\\"
            self.spider_dir(share, subpath, depth + 1, read, write)

    def run(self):
        self.logger.display("Enumerated shares")
        self.logger.highlight(f"{'Share':<15} {'Permissions':<15} {'Remark'}")
        self.logger.highlight(f"{'-----':<15} {'-----------':<15} {'------'}")

        try:
            shares = self.smb.conn.listShares()
        except Exception as e:
            self.logger.fail(f"Error listing shares: {e}")
            return

        # Sort: NETLOGON/SYSVOL last so custom shares are enumerated first
        deferred = {"netlogon", "sysvol"}
        share_list = []
        for share in shares:
            share_name = share["shi1_netname"][:-1]
            share_remark = share["shi1_remark"][:-1]
            if share_name.lower() in self.exclude:
                continue
            share_list.append((share_name, share_remark))
        share_list.sort(key=lambda s: s[0].lower() in deferred)

        for share_name, share_remark in share_list:
            # Single listPath for root
            result = self.list_path(share_name, "")
            read = result is not None
            write = self.can_write(share_name, "") if read else False
            perms = self.format_perms(read, write)

            if share_name not in self.results:
                self.results[share_name] = {}
            self.results[share_name][""] = {"read": read, "write": write}

            self.logger.highlight(f"{share_name:<15} {perms:<15} {share_remark}")

            if not read:
                continue

            dirs, files = result

            # Show root files
            if self.show_files and files:
                for fname, fsize in sorted(files):
                    self.logger.display(f"  {fname:<35} {human_size(fsize)}")

            # Recurse into subdirectories
            for dirname in sorted(dirs):
                if dirname.lower() in self.exclude:
                    continue
                subpath = dirname + "\\"
                self.spider_dir(share_name, subpath, 1, read, write)

        # Summary
        writable_paths = []
        for share, paths in self.results.items():
            for path, p in paths.items():
                if p.get("write") and path:
                    writable_paths.append(f"\\\\{share}\\{path.rstrip(chr(92))}")

        if writable_paths:
            self.logger.highlight(f"\nWritable subdirectories ({len(writable_paths)}):")
            for wp in writable_paths:
                self.logger.highlight(f"  >> {wp}")
