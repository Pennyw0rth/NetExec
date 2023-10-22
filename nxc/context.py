import configparser
import os


class Context:
    def __init__(self, db, logger, args):
        for key, value in vars(args).items():
            setattr(self, key, value)

        self.db = db
        self.log_folder_path = os.path.join(os.path.expanduser("~/.nxc"), "logs")
        self.localip = None

        self.conf = configparser.ConfigParser()
        self.conf.read(os.path.expanduser("~/.nxc/nxc.conf"))

        self.log = logger
