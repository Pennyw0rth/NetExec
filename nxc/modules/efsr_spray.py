from nxc.context import Context
from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "efsr_spray"
    description = "[REMOVED] Tries to activate the EFSR service by creating a file with the encryption attribute on some available share."
    supported_protocols = ["smb"]
    excluded_shares = ["SYSVOL"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context: Context, module_options: dict[str, str]):
        """
        FILE_NAME      Name of the file which will be tried to create and afterwards delete
        SHARE_NAME     If set, ONLY this share will be used
        EXCLUDED_SHARES List of share names which will not be used, seperated by comma
        """

    def on_login(self, context: Context, connection):
        context.log.fail('[REMOVED] This module has been made obsolete and EFS will be activated automatically by "coerce_plus"')
