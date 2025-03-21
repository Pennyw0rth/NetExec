from io import BytesIO
from os import makedirs
from os.path import join, abspath
from nxc.paths import NXC_PATH
import re


# TODO implement the display of file deletion time to know when the file was deleted (this information should be in the metadata file but I couldn't parse it correctly)
# TODO handle directories in the Recycle Bin as well as single files
# TODO specify what files you want to download as a filter

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
        '''
        DOWNLOAD    Download the files in the Recycle Bin (default:False), enable by specifying -o DOWNLOAD=True
        '''
        self.download = bool(module_options.get("DOWNLOAD", False))

    def read_file(self, connection, context, file_path):
        buf = BytesIO()
        try:
            connection.conn.getFile("C$", file_path, buf.write)
        except Exception as e:
            context.log.debug(f"Cannot read file {file_path}: {e}")

        buf.seek(0)
        binary_data = buf.read()
        return binary_data

    def on_admin_login(self, context, connection):
        found_dirs = 0
        found_files = 0
        metadata_map = {}
        
        for directory in connection.conn.listPath("C$", "$Recycle.Bin\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory():
                # Each directory corresponds to a different user account, the SID identifies the user
                sid_dir = f"$Recycle.Bin\\{directory.get_longname()}"
                if(sid_dir is not None):
                    context.log.highlight(f"Found directory {sid_dir}")
                    found_dirs += 1

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
                            # Get original location of the deleted file from the associated metadata file, this can help determine if we want to download it or not
                            if len(data) > 16:
                                # Extract and clean path
                                original_path = data[16:].decode("utf-16", errors="ignore").strip("\x00")
                                match = re.search(r"([a-z]:\\.+)", original_path, re.IGNORECASE)
                                if match:
                                    original_path = match.group(1)
                                    metadata_map[file.get_longname().replace("$I", "")] = original_path
                                    context.log.highlight(f"\tFile: {file.get_longname()}, Original location: {original_path}")
                            else:
                                context.log.info(f"\tInvalid metadata file: {file.get_longname()}")
                            found_files += 1
                    except Exception as e:
                        context.log.debug(f"Error parsing metadata file: {e}")
                    try:
                        #Actual files (start with $R)
                        if file.get_longname() not in self.false_positive and file.get_longname().startswith("$R"):
                            file_path = f"{sid_dir}\\{file.get_longname()}"
                            context.log.highlight(f"\tFile: {file.get_longname()}, size: {file.get_filesize()}KB")

                            # Download files if the module option is set
                            if self.download:
                                        context.log.info(f"Downloading {file_path}")
                                        data = self.read_file(connection, context, file_path)
                                        file_content = data.decode("utf-8", errors="ignore")
                                        original_path = metadata_map.get(file.get_longname().replace("$R", ""), "unknown_file")
                                        filename = f"{connection.host}_{original_path}"
                                        export_path = join(NXC_PATH, "modules", "recycle_bin")
                                        path = abspath(join(export_path, filename))
                                        makedirs(export_path, exist_ok=True)
                            try:
                                with open(path, "w+") as f:
                                    f.write(file_content)
                                context.log.success(f"Recycle Bin file {file.get_longname()} written to: {path}")
                            except Exception as e:
                                context.log.fail(f"Failed to write Recycle Bin file to {filename}: {e}")
                                found_files += 1
                    except Exception as e:
                        context.log.debug(f"Error parsing content file: {e}")