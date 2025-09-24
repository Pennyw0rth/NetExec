import nxc
import argparse
import importlib
from os import listdir
from os.path import dirname, join


class ModuleLoader:
    def __init__(self):
        self.modules = {}
        self.modules_dir = join(dirname(nxc.__file__), "modules")
        self.import_base = "nxc.modules"

    def list_modules(self, parse_modules_attributes: bool = False):
        """
        List modules stored in nxc/modules

        Args:
            parse_modules_attributes (bool):
                - False = returns only the list of module filenames
                - True  = returns a dict of parsed modules with metadata

        Returns:
            - If parse_modules_attributes=False : list[str]
            - If parse_modules_attributes=True  : dict[str, dict]
        """
        module_names = []

        for module_file in listdir(self.modules_dir):
            if not module_file.endswith(".py") or module_file == "example_module.py":
                continue

            mod_name = module_file[:-3]

            if not parse_modules_attributes:
                module_names.append(mod_name)
                continue

            try:
                module_pkg = importlib.import_module(f"{self.import_base}.{mod_name}")
                module_class = getattr(module_pkg, "NXCModule", None)
            except Exception:
                continue

            required_attrs = {
                "name", "description", "supported_protocols",
                "__init__", "register_module_options", "category",
            }
            if not all(hasattr(module_class, attr) for attr in required_attrs):
                continue

            self.modules[module_class.name] = {
                "class": module_class,
                "description": module_class.description,
                "supported_protocols": module_class.supported_protocols,
                "category": module_class.category,
                "requires_admin": hasattr(module_class, "on_admin_login"),
            }

        return self.modules if parse_modules_attributes else sorted(module_names, key=str.casefold)

    def print_module_help(self, module_name):
        """Special case: show help for a module directly"""
        module_info = self.modules.get(module_name)
        if not module_info:
            raise ValueError(f"Module {module_name} not found or missing required attributes")

        module_class = module_info["class"]

        parser = argparse.ArgumentParser(
            prog=module_name,
            description=module_info["description"],
            formatter_class=nxc.helpers.args.DisplayDefaultsNotNone,
            add_help=False,
            allow_abbrev=False,
            usage=argparse.SUPPRESS
        )
        module_class.register_module_options(parser)
        return parser
