from os import mkdir
from os.path import exists
from os.path import join as path_join
import shutil
from nxc.paths import NXC_PATH, CONFIG_PATH, TMP_PATH, DATA_PATH
from nxc.database import initialize_db
from nxc.logger import nxc_logger


def first_run_setup(logger=nxc_logger):
    if not exists(TMP_PATH):
        mkdir(TMP_PATH)

    if not exists(NXC_PATH):
        logger.display("First time use detected")
        logger.display("Creating home directory structure")
        mkdir(NXC_PATH)

    folders = (
        "logs",
        "modules",
        "protocols",
        "workspaces",
        "obfuscated_scripts",
        "screenshots",
    )
    for folder in folders:
        if not exists(path_join(NXC_PATH, folder)):
            logger.display(f"Creating missing folder {folder}")
            mkdir(path_join(NXC_PATH, folder))

    initialize_db()

    if not exists(CONFIG_PATH):
        logger.display("Copying default configuration file")
        default_path = path_join(DATA_PATH, "nxc.conf")
        shutil.copy(default_path, NXC_PATH)

    # if not exists(CERT_PATH):
    #         if os.name != 'nt':
    #         if e.errno == errno.ENOENT:
