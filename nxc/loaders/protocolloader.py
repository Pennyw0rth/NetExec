from types import ModuleType
from importlib.machinery import SourceFileLoader
from os import listdir
from os.path import join as path_join
from os.path import dirname, exists

import nxc


class ProtocolLoader:
    def load_protocol(self, protocol_path):
        loader = SourceFileLoader("protocol", protocol_path)
        protocol = ModuleType(loader.name)
        loader.exec_module(protocol)
        return protocol

    def get_protocols(self):
        protocols = {}

        proto_path = path_join(dirname(nxc.__file__), "protocols")
        for protocol in listdir(proto_path):
            if protocol[-3:] == ".py" and protocol[:-3] != "__init__":
                protocol_path = path_join(proto_path, protocol)
                protocol_name = protocol[:-3]

                protocols[protocol_name] = {"path": protocol_path}

                db_file_path = path_join(proto_path, protocol_name, "database.py")
                db_nav_path = path_join(proto_path, protocol_name, "db_navigator.py")
                protocol_args_path = path_join(proto_path, protocol_name, "proto_args.py")
                if exists(db_file_path):
                    protocols[protocol_name]["dbpath"] = db_file_path
                if exists(db_nav_path):
                    protocols[protocol_name]["nvpath"] = db_nav_path
                if exists(protocol_args_path):
                    protocols[protocol_name]["argspath"] = protocol_args_path
        return protocols
