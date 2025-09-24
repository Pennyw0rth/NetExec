from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Example:
    -------
    Module by @yomama
    """

    name = "example module"
    description = "I do something"
    supported_protocols = []  # Example: ['smb', 'mssql']
    category = CATEGORY.ENUMERATION  # Must be one of "Enumeration", "Privilege Escalation" or "Credential Dumping". Use what fits best.

    @staticmethod
    def register_module_options(subparsers):
        subparsers.add_argument("--option1", help="This is the first option")
        subparsers.add_argument("--option2", help="This is the second option")
        subparsers.set_defaults(module="example module")
        return subparsers

    def __init__(self, context=None, connection=None, module_options=None):
        self.context = context
        self.connection = connection
        self.option1 = module_options.option1
        self.option2 = module_options.option2

    def on_login(self):
        """Concurrent.
        Required if on_admin_login is not present. This gets called on each authenticated connection
        """
        # Logging best practice
        # Mostly you should use these functions to display information to the user
        self.context.log.display("I'm doing something")  # Use this for every normal message ([*] I'm doing something)
        self.context.log.success("I'm doing something")  # Use this for when something succeeds ([+] I'm doing something)
        self.context.log.fail("I'm doing something")  # Use this for when something fails ([-] I'm doing something), for example a remote registry entry is missing which is needed to proceed
        self.context.log.highlight("I'm doing something")  # Use this for when something is important and should be highlighted, printing credentials for example

        # These are for debugging purposes
        self.context.log.info("I'm doing something")  # This will only be displayed if the user has specified the --verbose flag, so add additional info that might be useful
        self.context.log.debug("I'm doing something")  # This will only be displayed if the user has specified the --debug flag, so add info that you would might need for debugging errors

        # These are for more critical error handling
        self.context.log.error("I'm doing something")  # This will not be printed in the module context and should only be used for critical errors (e.g. a required python file is missing)
        try:
            raise Exception("Exception that might have occurred")
        except Exception as e:
            self.context.log.exception(f"Exception occurred: {e}")  # This will display an exception traceback screen after an exception was raised and should only be used for critical errors

    def on_admin_login(self):
        """Concurrent.
        Required if on_login is not present
        This gets called on each authenticated connection with  Administrative privileges
        """
