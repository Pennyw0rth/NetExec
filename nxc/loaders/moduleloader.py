import nxc
import argparse
import importlib
from os import listdir
from os.path import dirname, join


class ModuleLoader:
    def __init__(self):
        self.modules_map = {}        # Stores { module_name: class }
        self.per_proto_modules = {}  # Stores { proto_name: [( module_name, description )]

    def list_modules(self):
        """List modules from nxc/modules directory"""
        modules_paths = [(join(dirname(nxc.__file__), "modules"), "nxc.modules")]

        for path, import_base in modules_paths:
            for module_file in listdir(path):
                if not module_file.endswith(".py") or module_file == "example_module.py":
                    continue

                mod_name = module_file[:-3]
                # Imports the module
                module_pkg = importlib.import_module(f"{import_base}.{mod_name}")
                # Retrieves the module's class
                module_class = getattr(module_pkg, "NXCModule", None)

                # Validate that each module has got the necessary attributes:
                # - A name
                # - A description
                # - The list of supported protocols ["smb", "ldap"]
                # - A __init__ function
                # - The register_module_options function
                # - A NXC category
                required_attrs = ["name", "description", "supported_protocols", "__init__", "register_module_options", "category"]
                if not all(hasattr(module_class, attr) for attr in required_attrs):
                    continue

                self.modules_map[module_class.name] = module_class
                for proto in module_class.supported_protocols:
                    self.per_proto_modules.setdefault(proto, []).append((module_class.name, module_class.description))

        return self.modules_map, self.per_proto_modules

    def print_module_help(self, module_name):
        """Special case: show help for a module directly"""
        module_class = self.modules_map.get(module_name)
        if not module_class:
            print(f"Module '{module_name}' not found")
            return

        parser = argparse.ArgumentParser(
            prog=f"{module_name}",
            description=getattr(module_class, "description", ""),
            formatter_class=nxc.helpers.args.DisplayDefaultsNotNone,
            add_help=True,
            allow_abbrev=False
        )
        try:
            module_class.register_module_options(parser)
        except TypeError:
            module_class.register_module_options(None, parser)

        parser.print_help()
