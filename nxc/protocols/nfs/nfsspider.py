import re
import math
from time import strftime, localtime

from pyNfsClient.const import ACCESS3_READ


class NFSSpider:
    def __init__(self, nfs3, mount, auth, logger):
        self.nfs3 = nfs3
        self.mount = mount
        self.auth = auth
        self.logger = logger
        self.pattern = []
        self.regex = []
        self.exclude_dirs = []
        self.only_files = True
        self.only_readable = True
        self.results = []

    def spider(
        self,
        file_handle,
        start_path="/",
        pattern=None,
        regex=None,
        exclude_dirs=None,
        depth=None,
        only_files=True,
        only_readable=True,
    ):
        self.results = []

        if exclude_dirs is None:
            exclude_dirs = []
        if regex is None:
            regex = []
        if pattern is None:
            pattern = []

        if regex:
            try:
                self.regex = [re.compile(rx, re.IGNORECASE) for rx in regex]
            except Exception as e:
                self.logger.fail(f"Regex compilation error: {e}")
                return self.results

        self.pattern = pattern
        self.exclude_dirs = exclude_dirs
        self.only_files = only_files
        self.only_readable = only_readable

        self.logger.display(f"Started spidering from {start_path}")
        self._spider(file_handle, start_path, depth)
        return self.results

    def _spider(self, dir_handle, path, depth):
        """Recursively traverse directory and collect readable files"""
        try:
            # Update UID/GID to match directory owner for proper access
            self._update_auth(dir_handle)
            dir_listing = self.nfs3.readdirplus(dir_handle, auth=self.auth)

            if "resfail" in dir_listing:
                self.logger.debug(f"Cannot read directory {path}: access denied")
                return

            entries = self._format_directory(dir_listing)

            # Procesing large directories in chunksA
            while not dir_listing["resok"]["reply"]["eof"]:
                if not entries and not dir_listing["resok"]["reply"]["entries"]:
                    self.logger.debug(f"Empty entries but eof not set for {path}")
                    break
                cookie_verf = dir_listing["resok"]["cookieverf"]
                cookie = entries[-1]["cookie"]
                dir_listing = self.nfs3.readdirplus(dir_handle, cookie=cookie, cookie_verf=cookie_verf, auth=self.auth)
                more_entries = self._format_directory(dir_listing)
                if not more_entries:
                    break
                entries.extend(more_entries)

            self._process_entries(entries, path, depth)

        except Exception as e:
            self.logger.debug(f"Error spidering {path}: {e}")

    def _process_entries(self, entries, path, depth):
        for entry in entries:
            name = entry.get("name", b"").decode("utf-8", errors="replace")

            if name in [".", ".."]:
                continue

            if name in self.exclude_dirs:
                self.logger.debug(f"Excluding directory: {name}")
                continue

            item_path = f"{path.rstrip('/')}/{name}"

            if not entry.get("name_attributes", {}).get("present", False):
                continue

            if not entry.get("name_handle", {}).get("present", False):
                continue

            attrs = entry.get("name_attributes", {}).get("attributes")
            if not attrs:
                continue

            file_handle = entry.get("name_handle", {}).get("handle", {}).get("data")
            if not file_handle:
                continue
            file_type = attrs.get("type", 0)
            is_dir = file_type == 2  # NF3DIR
            file_size = attrs.get("size", 0)
            uid = attrs.get("uid", 0)
            mtime = attrs.get("mtime", {}).get("seconds", 0)

            self._update_auth(file_handle)
            read_perm = self._check_read_permission(file_handle)

            if is_dir:
                if not self.only_files:
                    if self._matches_pattern(name):
                        if not self.only_readable or read_perm:
                            self._log_result(item_path, is_dir=True, read_perm=read_perm, size=file_size, uid=uid, mtime=mtime)
                            self.results.append(item_path)

                if depth is None or depth > 0:
                    next_depth = None if depth is None else depth - 1
                    self._spider(file_handle, item_path, next_depth)
            else:
                if self._matches_pattern(name):
                    if not self.only_readable or read_perm:
                        self._log_result(item_path, is_dir=False, read_perm=read_perm, size=file_size, uid=uid, mtime=mtime)
                        self.results.append(item_path)

    def _matches_pattern(self, name):
        if not self.pattern and not self.regex:
            return True

        name_lower = name.lower()
        for pattern in self.pattern:
            if pattern.lower() in name_lower:
                return True

        for regex in self.regex:
            if regex.search(name):
                return True

        return False

    def _check_read_permission(self, file_handle):
        try:
            result = self.nfs3.access(file_handle, ACCESS3_READ, self.auth)
            return (result.get("resok", {}).get("access", 0) & ACCESS3_READ) == ACCESS3_READ
        except Exception:
            return False

    def _update_auth(self, file_handle):
        """Be file owner to bypass permission checks (root squash workaround)"""
        try:
            attrs = self.nfs3.getattr(file_handle, auth=self.auth)
            self.auth["uid"] = attrs["attributes"]["uid"]
            self.auth["gid"] = attrs["attributes"]["gid"]
        except Exception:
            pass

    def _format_directory(self, raw_directory):
        if "resfail" in raw_directory:
            return []
        items = []
        nextentry = raw_directory["resok"]["reply"]["entries"]
        if nextentry and isinstance(nextentry, list) and len(nextentry) > 0:
            nextentry = nextentry[0]
        else:
            nextentry = None
        while nextentry:
            entry = nextentry
            next_list = entry.get("nextentry")
            nextentry = next_list[0] if (next_list and isinstance(next_list, list) and len(next_list) > 0) else None
            entry_copy = dict(entry)
            entry_copy.pop("nextentry", None)
            items.append(entry_copy)
        return items

    def _log_result(self, path, is_dir, read_perm, size, uid, mtime):
        type_indicator = "d" if is_dir else "-"
        perm_str = f"{type_indicator}{'r' if read_perm else '-'}--"
        size_str = self._convert_size(size) if not is_dir else "-"
        mtime_str = strftime("%Y-%m-%d %H:%M", localtime(mtime)) if mtime else "n/a"

        self.logger.highlight(f"{path} [uid:{uid} perms:{perm_str} size:{size_str} mtime:{mtime_str}]")

    def _convert_size(self, size_bytes):
        if size_bytes <= 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 1)
        return f"{s}{size_name[i]}"
