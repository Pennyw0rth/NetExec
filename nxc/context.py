import configparser
import os

from nxc.paths import NXC_PATH, CONFIG_PATH


class Context:
    def __init__(self, db, logger, args):
        for key, value in vars(args).items():
            setattr(self, key, value)

        self.db = db
        self.log_folder_path = os.path.join(NXC_PATH, "logs")
        self.localip = None

        self.conf = configparser.ConfigParser()
        self.conf.read(CONFIG_PATH)

        self.log = logger
