import argparse
import argcomplete
import sys
from argparse import RawTextHelpFormatter
from os.path import dirname, join as path_join
import nxc
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.helpers.logger import highlight
from nxc.helpers.args import DisplayDefaultsNotNone
from nxc.logger import nxc_logger, setup_debug_logging
import importlib.metadata
from importlib import import_module
from pkgutil import iter_modules


def gen_cli_args():
    setup_debug_logging()

    # --- VERSION INFO ---
    try:
        VERSION, COMMIT = importlib.metadata.version("netexec").split("+")
        DISTANCE, COMMIT = COMMIT.split(".")
    except Exception:
        VERSION = importlib.metadata.version("netexec")
        COMMIT = ""
        DISTANCE = ""
    CODENAME = "SmoothOperator"

    # --- GENERIC / OUTPUT / DNS PARSERS ---
    generic_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    ggroup = generic_parser.add_argument_group("Generic", "Generic options for nxc across protocols")
    ggroup.add_argument("--version", action="store_true", help="Display nxc version")
    ggroup.add_argument("-t", "--threads", type=int, default=256, help="number of concurrent threads")
    ggroup.add_argument("--timeout", type=int, default=None, help="max timeout per thread")
    ggroup.add_argument("--jitter", metavar="INTERVAL", help="random delay between each authentication")
    # expose -M here (we will use -M flow)
    ggroup.add_argument("-M", "--module", help="Select module to use", dest="module")

    output_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    ogroup = output_parser.add_argument_group("Output", "Output options")
    ogroup.add_argument("--verbose", action="store_true")
    ogroup.add_argument("--debug", action="store_true")
    ogroup.add_argument("--no-progress", action="store_true")
    ogroup.add_argument("--log", metavar="LOG")

    dns_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    dgroup = dns_parser.add_argument_group("DNS")
    dgroup.add_argument("-6", dest="force_ipv6", action="store_true")
    dgroup.add_argument("--dns-server")
    dgroup.add_argument("--dns-tcp", action="store_true")
    dgroup.add_argument("--dns-timeout", type=int, default=3)

    # --- MAIN PARSER (disable abbreviation to avoid --hello => --help) ---
    parser = argparse.ArgumentParser(
        description=rf"""
 .   .
.|   |.     _   _          _     _____
||   ||    | \ | |   ___  | |_  | ____| __  __   ___    ___
\\( )//    |  \| |  / _ \ | __| |  _|   \ \/ /  / _ \  / __|
.=[ ]=.    | |\  | |  __/ | |_  | |___   >  <  |  __/ | (__
/ /˙-˙\ \   |_| \_|  \___|  \__| |_____| /_/\_\  \___|  \___|
˙ \   / ˙
 ˙   ˙

The network execution tool
Maintained as open source by @NeffIsBack, @MJHallenbeck, @_zblurx

Documentation: https://www.netexec.wiki/

{highlight('Version', 'red')}: {highlight(VERSION)}
{highlight('Codename', 'red')}: {highlight(CODENAME)}
{highlight('Commit', 'red')} : {highlight(COMMIT)}
""",
        formatter_class=RawTextHelpFormatter,
        parents=[generic_parser, output_parser, dns_parser],
        allow_abbrev=False
    )

    # --- SUBPARSERS FOR PROTOCOLS ---
    proto_subparsers = parser.add_subparsers(title="Available Protocols", dest="protocol")

    # Standard shared parser for protocols
    std_parser = argparse.ArgumentParser(add_help=False, parents=[generic_parser, output_parser, dns_parser],
                                        formatter_class=DisplayDefaultsNotNone)
    std_parser.add_argument("target", nargs="+",
                            help="Target IP(s), ranges, CIDR(s), hostnames, files, XML, Nessus")

    # --- Authentication groups ---
    cred_group = std_parser.add_argument_group("Authentication")
    cred_group.add_argument("-u", "--username", nargs="+", default=[])
    cred_group.add_argument("-p", "--password", nargs="+", default=[])
    cred_group.add_argument("-id", nargs="+", default=[], type=str, dest="cred_id")
    cred_group.add_argument("--ignore-pw-decoding", action="store_true")
    cred_group.add_argument("--no-bruteforce", action="store_true")
    cred_group.add_argument("--continue-on-success", action="store_true")
    cred_group.add_argument("--gfail-limit", type=int)
    cred_group.add_argument("--ufail-limit", type=int)
    cred_group.add_argument("--fail-limit", type=int)

    kerberos_group = std_parser.add_argument_group("Kerberos")
    kerberos_group.add_argument("-k", "--kerberos", action="store_true")
    kerberos_group.add_argument("--use-kcache", action="store_true")
    kerberos_group.add_argument("--aesKey", nargs="+")
    kerberos_group.add_argument("--kdcHost")

    cert_group = std_parser.add_argument_group("Certificate")
    cert_group.add_argument("--pfx-cert")
    cert_group.add_argument("--pfx-base64")
    cert_group.add_argument("--pfx-pass")
    cert_group.add_argument("--pem-cert")
    cert_group.add_argument("--pem-key")

    # --- Load protocol arguments dynamically ---
    p_loader = ProtocolLoader()
    try:
        protocols = p_loader.get_protocols()
    except Exception:
        protocols = {}
    try:
        for proto in protocols:
            proto_obj = p_loader.load_protocol(protocols[proto]["argspath"])
            proto_subparsers = proto_obj.proto_args(proto_subparsers, [std_parser])
    except Exception as e:
        nxc_logger.exception(f"Error loading proto_args: {e}")

    # --- LOAD MODULES (collect for listing + for -M) ---
    modules_paths = [(path_join(dirname(nxc.__file__), "modules"), "nxc.modules")]
    modules_map = {}
    per_proto_modules = {}  # proto -> list of (name, desc)
    for path, import_base in modules_paths:
        for module_info in iter_modules(path=[path]):
            try:
                module_pkg = import_module(f"{import_base}.{module_info.name}")
                module_class = getattr(module_pkg, "NXCModule", None)
                if not module_class:
                    continue

                # Validate module minimal interface
                if not all(hasattr(module_class, attr) for attr in ("name", "description", "supported_protocols", "__init__")):
                    continue

                name = getattr(module_class, "name", None)
                description = getattr(module_class, "description", "")
                supported_protocols = getattr(module_class, "supported_protocols", [])

                modules_map[name] = module_class
                for sp in supported_protocols:
                    per_proto_modules.setdefault(sp, []).append((name, description))

            except Exception as e:
                nxc_logger.debug(f"Cannot load module {module_info.name}: {e}")
                continue

    # --- Attach module listing to the protocol help (epilog), without positional subparsers ---
    for proto_name, proto_parser in proto_subparsers.choices.items():
        mods = per_proto_modules.get(proto_name, [])
        if not mods:
            continue

        lines = [f"{proto_name.upper()} modules available:"]
        # Determine the max length of module names to align descriptions
        max_name_len = max((len(n) for n, _ in mods), default=0)

        for n, desc in sorted(mods, key=lambda x: x[0].lower()):
            # Format: module_name (padded) : description
            lines.append(f"  {n.ljust(max_name_len)} : {desc}")

        # Append nicely formatted list to existing description/epilog
        try:
            proto_parser.description = proto_parser.description or ""
            proto_parser.epilog = (proto_parser.epilog or "") + "\n" + "\n".join(lines)
        except Exception:
            pass

    # --- Special-case: module help requested directly (-M <module> -h) ---
    if ("-M" in sys.argv) or ("--module" in " ".join(sys.argv)):
        argv_tail = sys.argv[1:]
        sel_mod = None
        for i, tok in enumerate(argv_tail):
            if tok in ("-M", "--module") and i + 1 < len(argv_tail):
                sel_mod = argv_tail[i + 1]
                break
            if tok.startswith("--module="):
                sel_mod = tok.split("=", 1)[1]
                break
        if sel_mod and (("-h" in argv_tail) or ("--help" in argv_tail)):
            module_class = modules_map.get(sel_mod)
            if not module_class:
                print(f"Module '{sel_mod}' not found")
                sys.exit(1)

            module_only_parser = argparse.ArgumentParser(
                prog=f"{sys.argv[0]} -M {sel_mod}",
                description=getattr(module_class, "description", ""),
                formatter_class=DisplayDefaultsNotNone,
                add_help=True,
                allow_abbrev=False
            )
            try:
                module_class.register_module_options(None, module_only_parser)
            except TypeError:
                module_class.register_module_options(module_only_parser)

            module_only_parser.print_help()
            sys.exit(0)

    # --- FIRST PARSE: detect -M and capture unknown tokens ---
    argcomplete.autocomplete(parser, always_complete_options=False)
    initial_args, unknown = parser.parse_known_args()

    # --- DOUBLE PARSING: if -M present, reconstruct module tokens from argv and parse them ---
    selected_module = getattr(initial_args, "module", None)
    if selected_module:
        module_class = modules_map.get(selected_module)
        if not module_class:
            print(f"Module '{selected_module}' not found")
            sys.exit(1)

        # locate module position in argv (support -M shadow -M=shadow and just 'shadow' fallback)
        argv = sys.argv[1:]
        mod_pos = None
        for i, tok in enumerate(argv):
            if tok in ("-M", "--module") and i + 1 < len(argv):
                if argv[i + 1] == selected_module:
                    mod_pos = i + 1
                    break
            if tok.startswith("--module="):
                val = tok.split("=", 1)[1]
                if val == selected_module:
                    mod_pos = i
                    break
        if mod_pos is None:
            for i, tok in enumerate(argv):
                if tok == selected_module:
                    mod_pos = i
                    break

        module_tokens = argv[mod_pos + 1 :] if mod_pos is not None else []

        # Build set of global option strings to filter out
        global_opts_set = set()
        for action in parser._actions:
            for opt in getattr(action, "option_strings", []):
                global_opts_set.add(opt)
        try:
            for action in std_parser._actions:
                for opt in getattr(action, "option_strings", []):
                    global_opts_set.add(opt)
        except Exception:
            pass

        # Filter tokens to remove known global options (and their single values)
        filtered = []
        skip_next = False
        for t in module_tokens:
            if skip_next:
                filtered.append(t)
                skip_next = False
                continue
            if t.startswith("--") or (t.startswith("-") and len(t) > 1 and not t[1:].isdigit()):
                name = t.split("=", 1)[0]
                if name in global_opts_set:
                    if "=" not in t:
                        skip_next = True
                    continue
                else:
                    filtered.append(t)
            else:
                filtered.append(t)

        module_tokens_filtered = filtered

        # Build module-only parser and register module options
        module_only_parser = argparse.ArgumentParser(
            prog=f"{sys.argv[0]} -M {selected_module}",
            description=getattr(module_class, "description", ""),
            formatter_class=DisplayDefaultsNotNone,
            add_help=True,
            allow_abbrev=False
        )
        try:
            module_class.register_module_options(None, module_only_parser)
        except TypeError:
            module_class.register_module_options(module_only_parser)

        # Parse only module tokens
        module_ns = module_only_parser.parse_args(module_tokens_filtered)

        # Merge namespaces
        merged = vars(initial_args).copy()
        merged.update(vars(module_ns))
        final_ns = argparse.Namespace(**merged)
        return final_ns, [CODENAME, VERSION, COMMIT, DISTANCE]

    # No module selected: return the initial namespace
    return initial_args, [CODENAME, VERSION, COMMIT, DISTANCE]
