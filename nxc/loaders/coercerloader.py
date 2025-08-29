import nxc
import importlib
import sys

from os import sep, walk
from os.path import dirname, splitext, relpath
from os.path import join as path_join


class CoercerLoader:
    def __init__(self, args, db, logger):
        self.args = args
        self.db = db
        self.logger = logger

    def load_all_coercer_methods():
        methods = []
        proto_path = path_join(dirname(nxc.__file__), "data", "coercer_method")
        
        # I'm not familiar at importlib stuff, but without this, it will raise "can't find module"
        if proto_path not in sys.path:
            sys.path.insert(0, proto_path)
        
        for root, _, files in walk(proto_path):
            # Avoid DCERPCSessionError.py
            if root == proto_path:
                continue
            for file in files:
                if file[-3:] == ".py" and not file.startswith("dtypes"):
                    method_path = path_join(root, file)
                    rel_met_path = relpath(method_path, proto_path)
                    method_name = splitext(rel_met_path)[0].replace(sep, ".")
                    spec = importlib.util.spec_from_file_location(method_name, method_path)
                    method = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(method)
                    methods.append(method)
        return methods