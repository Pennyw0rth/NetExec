import nxc
import argparse
import importlib
from os import listdir
from os.path import dirname, join


class ModuleLoader:
    def __init__(self):
        self.module_names = []
        self.modules_map = {}
        self.per_proto_modules = {}
        self.modules_dir = join(dirname(nxc.__file__), "modules")
        self.import_base = "nxc.modules"

    def list_modules(self, parse_modules_attributes: bool = False):
        """
        List modules stored in nxc/modules

        Args:
            parse_modules_attributes (bool):
                - False = returns only the list of module filenames ()
                - True  = returns entirely parsed module classes

        Returns:
            - If parse_modules_attributes=False : list[str]
            - If parse_modules_attributes=True  : (dict[str, class], dict[str, list[tuple[str, str]]])
        """
        for module_file in listdir(self.modules_dir):
            if not module_file.endswith(".py") or module_file == "example_module.py":
                continue

            # If parsing modules is not requested, only retrieves the module's name
            mod_name = module_file[:-3]
            if not parse_modules_attributes:
                self.module_names.append(mod_name)
                continue

            # Else, instance the module and retrieve necessary attributes
            try:
                module_pkg = importlib.import_module(f"{self.import_base}.{mod_name}")
                module_class = getattr(module_pkg, "NXCModule", None)
            except Exception:
                continue

            # These are the required attributes we need in every modules so that everything works correctly
            required_attrs = {"name", "description", "supported_protocols", "__init__", "register_module_options", "category", }
            if not all(hasattr(module_class, attr) for attr in required_attrs):
                continue

            self.modules_map[module_class.name] = module_class
            for proto in module_class.supported_protocols:
                self.per_proto_modules.setdefault(proto, []).append((module_class.name, module_class.description))

        return (self.modules_map, self.per_proto_modules) if parse_modules_attributes else sorted(self.module_names, key=str.casefold)

    def print_module_help(self, module_name):
        """Special case: show help for a module directly"""
        # Loads the module's class
        module_class = self.modules_map.get(module_name)

        # Create a parser for that module only
        parser = argparse.ArgumentParser(
            prog=f"{module_name}",
            description=getattr(module_class, "description", ""),
            formatter_class=nxc.helpers.args.DisplayDefaultsNotNone,
            add_help=True,
            allow_abbrev=False
        )

        # Registers module's options
        module_class.register_module_options(parser)
        # return the parser so that cli.py print_help()
        return parser
