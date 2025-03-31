from io import BytesIO
from os import makedirs
from os.path import join, abspath
from nxc.paths import NXC_PATH
import re
from datetime import datetime, timedelta
import struct

class NXCModule:
    # Finds files in the Recycle Bin
    # Module by @leDryPotato

    name = "recycle_bin"
    description = "Lists (and downloads) files in the Recycle Bin."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    false_positive = [".", "..", "desktop.ini", "S-1-5-18"]
    
    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        DOWNLOAD    Download the files in the Recycle Bin (default: False)
            Example: -o DOWNLOAD=True
        FILTER      Filter what files you want to download (default: all) based on their original location, supports regular expressions
            Examples: -o FILTER=pass
                      -o FILTER=ssh
        """
        self.download = bool(module_options.get("DOWNLOAD", False))
        self.filter = module_options.get("FILTER", "all")

    def read_file(self, connection, context, file_path):
        buf = BytesIO()
        try:
            connection.conn.getFile("C$", file_path, buf.write)
        except Exception as e:
            context.log.debug(f"Cannot read file {file_path}: {e}")

        buf.seek(0)
        return buf.read()

    def convert_filetime_to_datetime(self, filetime):
        """Convert Windows FILETIME to a readable timestamp rounded to the closest minute."""
        try:
            WINDOWS_EPOCH = datetime(1601, 1, 1)  # Windows FILETIME epoch

            timestamp = filetime / 10_000_000  # Convert 100-ns intervals to seconds
            dt = WINDOWS_EPOCH + timedelta(seconds=timestamp)
            return dt.replace(microsecond=0)
        except Exception:
            return "Conversion Error"

    def process_recycle_bin_directory(self, connection, context, sid_dir, metadata_map, depth=0):
        """Recursively process the Recycle Bin directory and its subdirectories."""
        for item in connection.conn.listPath("C$", f"{sid_dir}\\*"):
            try:
                if item.get_longname() in self.false_positive:
                    continue

                item_path = f"{sid_dir}\\{item.get_longname()}"
                if item.is_directory():
                    for _ in range(depth, depth + 1):
                        context.log.highlight(f"{'\t' * (depth + 1)}Found subdirectory: {item_path}")
                    
                    # Recursively process subdirectories
                    self.process_recycle_bin_directory(connection, context, item_path, metadata_map, depth + 1)
                else:
                    # Process files in the directory
                    if item.get_longname().startswith("$I"):
                        # Metadata file
                        data = self.read_file(connection, context, item_path)
                        if len(data) >= 24:
                            deletion_time_raw, = struct.unpack("<Q", data[16:24])
                            deletion_time = self.convert_filetime_to_datetime(deletion_time_raw)
                            original_path = data[24:].decode("utf-16", errors="ignore").strip("\x00")
                            match = re.search(r"([a-z]:\\.+)", original_path, re.IGNORECASE)
                            if match:
                                original_path = match.group(1)
                                metadata_map[item.get_longname().replace("$I", "")] = original_path
                                context.log.highlight(f"\tFile: {item.get_longname()}, Original location: {original_path}, Deletion time: {deletion_time}")
                    else:
                        # Actual file
                        for _ in range(depth, depth + 1):
                            context.log.highlight(f"{'\t' * (depth + 1)}File: {item.get_longname()}, size: {item.get_filesize()}KB")
                        if self.download:
                            # TODO handle reconstructing the original path better when there is no associated metadata file
                            # Would need to access the key in metadata_map that is associated with the current directory we are in
                            original_path = metadata_map.get(item.get_longname().replace("$R", ""), f"{sid_dir}\\{item.get_longname()}")
                            if self.filter and self.filter.lower() != "all":
                                match = re.search(self.filter, original_path, re.IGNORECASE)
                                if not match:
                                    context.log.info(f"\tSkipping file {item.get_longname()} ({original_path})")
                                    continue
                            context.log.info(f"\tDownloading file {item.get_longname()} from {original_path}")
                            data = self.read_file(connection, context, item_path)
                            filename = f"{connection.host}_{original_path}"
                            export_path = join(NXC_PATH, "modules", "recycle_bin")
                            path = abspath(join(export_path, filename))
                            makedirs(export_path, exist_ok=True)
                            try:
                                with open(path, "wb") as f:
                                    f.write(data)
                                context.log.success(f"Recycle Bin file {item.get_longname()} written to: {path}")
                            except Exception as e:
                                context.log.fail(f"Failed to write Recycle Bin file to {filename}: {e}")
            except Exception as e:
                context.log.debug(f"Error processing item {item.get_longname()}: {e}")

    def on_admin_login(self, context, connection):
        metadata_map = {}
        
        for directory in connection.conn.listPath("C$", "$Recycle.Bin\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory():
                # Each directory corresponds to a different user account, the SID identifies the user
                sid_dir = f"$Recycle.Bin\\{directory.get_longname()}"
                if (sid_dir is not None):
                    context.log.highlight(f"Found directory {sid_dir}")

                self.process_recycle_bin_directory(connection, context, sid_dir, metadata_map)