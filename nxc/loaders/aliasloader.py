import shlex
import sys
from nxc.config import nxc_config
from nxc.logger import nxc_logger


class AliasLoader:
    def __init__(self):
        self.aliases = self.load_aliases()
        self.logger = nxc_logger

    # Map aliases to their equivalent
    def load_aliases(self):
        aliases = {}
        try:
            if nxc_config.has_section("aliases"):
                # configparser returns lowercased option names by default
                for name, value in nxc_config.items("aliases"):
                    aliases[name] = value.strip()
        except Exception as e:
            self.logger.error(f"Error reading aliases from config: {e}")
        return aliases

    # Inject aliases equivalents in sys.argv
    def expand_aliases(self, initial_args):
        if not initial_args.aliases:
            return

        expanded_args = []

        for alias_name in initial_args.aliases:
            alias_name_lc = alias_name.lower()
            expansion = self.aliases.get(alias_name_lc)
            if "-A" in expansion or "--alias" in expansion:
                self.logger.error(f"Alias '{alias_name_lc}' contains '-A/--alias', which is not supported (avoids recursion).")
                sys.exit(1)
            try:
                tokens = shlex.split(expansion)
                self.logger.debug(f"Replaced alias {alias_name} by {expansion}")
            except Exception as e:
                self.logger.error(f"Failed to parse alias '{alias_name_lc}' expansion: {e}")
                sys.exit(1)
            expanded_args.extend(tokens)

        # Rebuild sys.argv
        new_argv = [sys.argv[0]]  # program name
        skip_next = False
        for i, arg in enumerate(sys.argv[1:]):
            if skip_next:
                skip_next = False
                continue
            if arg in ("-A", "--aliases") and i < len(sys.argv[1:]) - 1:
                skip_next = True  # skip the alias argument
                continue
            else:
                new_argv.append(arg)
        # Append the expanded tokens at the end
        new_argv.extend(expanded_args)

        sys.argv[:] = new_argv

    # Alias help (--list-alias)
    def list_aliases(self):
        if not self.aliases:
            self.logger.display("No aliases defined in your config file.")
            return

        self.logger.highlight("AVAILABLE ALIASES")
        for name, expansion in self.aliases.items():
            self.logger.display(f"  {name:<15} →  {expansion}")
