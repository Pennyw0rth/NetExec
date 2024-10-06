import configparser
import shutil
import sys
from os import mkdir
from os.path import exists
from os.path import join as path_join
from pathlib import Path
from sqlite3 import connect
from threading import Lock

from sqlalchemy import create_engine, MetaData
from sqlalchemy.exc import IllegalStateChangeError
from sqlalchemy.orm import sessionmaker, scoped_session

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.logger import nxc_logger
from nxc.paths import WORKSPACE_DIR


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


def set_workspace(config_path, workspace_name):
    config = open_config(config_path)
    config.set("nxc", "workspace", workspace_name)
    write_configfile(config, config_path)
    print(f"[*] Workspace set to {workspace_name}")


def get_db(config):
    return config.get("nxc", "last_used_db")


def write_configfile(config, config_path):
    with open(config_path, "w") as configfile:
        config.write(configfile)


def init_protocol_dbs(workspace_name, p_loader=None):
    """Check for each protocol if the database exists, if not create it."""
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
    if exists(path_join(WORKSPACE_DIR, workspace_name)):
        print(f"[-] Workspace {workspace_name} already exists")
    else:
        print(f"[*] Creating {workspace_name} workspace")
        mkdir(path_join(WORKSPACE_DIR, workspace_name))

    init_protocol_dbs(workspace_name, p_loader)


def delete_workspace(workspace_name):
    shutil.rmtree(path_join(WORKSPACE_DIR, workspace_name))
    print(f"[*] Workspace {workspace_name} deleted")


def initialize_db():
    if not exists(path_join(WORKSPACE_DIR, "default")):
        create_workspace("default")

    # Even if the default workspace exists, we still need to check if every protocol has a database (in case of a new protocol)
    init_protocol_dbs("default")


class BaseDB:
    def __init__(self, db_engine):
        self.db_engine = db_engine
        self.db_path = self.db_engine.url.database
        self.protocol = Path(self.db_path).stem.upper()
        self.metadata = MetaData()
        self.reflect_tables()
        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)

        session = scoped_session(session_factory)
        self.sess = session()
        self.lock = Lock()

    def reflect_tables(self):
        raise NotImplementedError("Reflect tables not implemented")

    def shutdown_db(self):
        try:
            self.sess.close()
        # due to the async nature of nxc, sometimes session state is a bit messy and this will throw:
        # Method 'close()' can't be called here; method '_connection_for_bind()' is already in progress and
        # this would cause an unexpected state change to <SessionTransactionState.CLOSED: 5>
        except IllegalStateChangeError as e:
            nxc_logger.debug(f"Error while closing session db object: {e}")

    def clear_database(self):
        for table in self.metadata.sorted_tables:
            self.db_execute(table.delete())

    def db_execute(self, *args):
        self.lock.acquire()
        res = self.sess.execute(*args)
        self.lock.release()
        return res
