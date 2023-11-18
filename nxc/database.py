import sys
import configparser
import shutil
from sqlalchemy import create_engine
from sqlite3 import connect
from os import mkdir
from os.path import exists
from os.path import join as path_join

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.paths import WORKSPACE_DIR
from nxc.logger import nxc_logger


def create_db_engine(db_path):
    return create_engine(f"sqlite:///{db_path}", isolation_level="AUTOCOMMIT", future=True)


def open_config(config_path):
    try:
        config = configparser.ConfigParser()
        config.read(config_path)
    except Exception as e:
        print(f"[-] Error reading nxc.conf: {e}")
        sys.exit(1)
    return config


def get_workspace(config):
    return config.get("nxc", "workspace")


def get_db(config):
    return config.get("nxc", "last_used_db")


def write_configfile(config, config_path):
    with open(config_path, "w") as configfile:
        config.write(configfile)


def create_workspace(workspace_name, p_loader=None):
    """
    Create a new workspace with the given name.

    Args:
    ----
        workspace_name (str): The name of the workspace.

    Returns:
    -------
        None
    """
    if not exists(path_join(WORKSPACE_DIR, workspace_name)):
        nxc_logger.debug(f"Creating {workspace_name} workspace")
        mkdir(path_join(WORKSPACE_DIR, workspace_name))
    
    if p_loader is None:
        p_loader = ProtocolLoader()
    protocols = p_loader.get_protocols()

    for protocol in protocols:
        protocol_object = p_loader.load_protocol(protocols[protocol]["dbpath"])
        proto_db_path = path_join(WORKSPACE_DIR, workspace_name, f"{protocol}.db")

        if not exists(proto_db_path):
            print(f"[*] Initializing {protocol.upper()} protocol database")
            conn = connect(proto_db_path)
            c = conn.cursor()

            # try to prevent some weird sqlite I/O errors
            c.execute("PRAGMA journal_mode = OFF")
            c.execute("PRAGMA foreign_keys = 1")

            protocol_object.database.db_schema(c)

            # commit the changes and close everything off
            conn.commit()
            conn.close()


def delete_workspace(workspace_name):
    shutil.rmtree(path_join(WORKSPACE_DIR, workspace_name))


def initialize_db():
    create_workspace("default")