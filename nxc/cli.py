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

    generic_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    generic_group = generic_parser.add_argument_group("Generic", "Generic options for nxc across protocols")
    generic_group.add_argument("--version", action="store_true", help="Display nxc version")
    generic_group.add_argument("-t", "--threads", type=int, dest="threads", default=256, help="set how many concurrent threads to use")
    generic_group.add_argument("--timeout", default=None, type=int, help="max timeout in seconds of each thread")
    generic_group.add_argument("--jitter", metavar="INTERVAL", type=str, help="sets a random delay between each authentication")
    generic_group.add_argument("-M", "--module", help="Select module to use", dest="module")

    output_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    output_group = output_parser.add_argument_group("Output", "Options to set verbosity levels and control output")
    output_group.add_argument("--verbose", action="store_true", help="enable verbose output")
    output_group.add_argument("--debug", action="store_true", help="enable debug level information")
    output_group.add_argument("--no-progress", action="store_true", help="do not displaying progress bar during scan")
    output_group.add_argument("--log", metavar="LOG", help="export result into a custom file")

    dns_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    dns_group = dns_parser.add_argument_group("DNS")
    dns_group.add_argument("-6", dest="force_ipv6", action="store_true", help="Enable force IPv6")
    dns_group.add_argument("--dns-server", action="store", help="Specify DNS server (default: Use hosts file & System DNS)")
    dns_group.add_argument("--dns-tcp", action="store_true", help="Use TCP instead of UDP for DNS queries")
    dns_group.add_argument("--dns-timeout", action="store", type=int, default=3, help="DNS query timeout in seconds")

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
    Maintained as an open source project by @NeffIsBack, @MJHallenbeck, @_zblurx

    For documentation and usage examples, visit: https://www.netexec.wiki/

    {highlight('Version', 'red')} : {highlight(VERSION)}
    {highlight('Codename', 'red')}: {highlight(CODENAME)}
    {highlight('Commit', 'red')}  : {highlight(COMMIT)}
    """,
        formatter_class=RawTextHelpFormatter,
        parents=[generic_parser, output_parser, dns_parser]
    )

    subparsers = parser.add_subparsers(title="Available Protocols", dest="protocol")

    std_parser = argparse.ArgumentParser(add_help=False, parents=[generic_parser, output_parser, dns_parser], formatter_class=DisplayDefaultsNotNone)
    std_parser.add_argument("target", nargs="+", help="Target IP(s), ranges, CIDR(s), hostnames, files, XML, Nessus")
    credential_group = std_parser.add_argument_group("Authentication", "Options for authenticating")
    credential_group.add_argument("-u", "--username", metavar="USERNAME", dest="username", nargs="+", default=[], help="username(s) or file(s) containing usernames")
    credential_group.add_argument("-p", "--password", metavar="PASSWORD", dest="password", nargs="+", default=[], help="password(s) or file(s) containing passwords")
    credential_group.add_argument("-id", metavar="CRED_ID", nargs="+", default=[], type=str, dest="cred_id", help="database credential ID(s) to use for authentication")
    credential_group.add_argument("--ignore-pw-decoding", action="store_true", help="Ignore non UTF-8 characters when decoding the password file")
    credential_group.add_argument("--no-bruteforce", action="store_true", help="No spray when using file for username and password (user1 => password1, user2 => password2)")
    credential_group.add_argument("--continue-on-success", action="store_true", help="continues authentication attempts even after successes")
    credential_group.add_argument("--gfail-limit", metavar="LIMIT", type=int, help="max number of global failed login attempts")
    credential_group.add_argument("--ufail-limit", metavar="LIMIT", type=int, help="max number of failed login attempts per username")
    credential_group.add_argument("--fail-limit", metavar="LIMIT", type=int, help="max number of failed login attempts per host")

    kerberos_group = std_parser.add_argument_group("Kerberos", "Options for Kerberos authentication")
    kerberos_group.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    kerberos_group.add_argument("--use-kcache", action="store_true", help="Use Kerberos authentication from ccache file (KRB5CCNAME)")
    kerberos_group.add_argument("--aesKey", metavar="AESKEY", nargs="+", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    kerberos_group.add_argument("--kdcHost", metavar="KDCHOST", help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")

    certificate_group = std_parser.add_argument_group("Certificate", "Options for certificate authentication")
    certificate_group.add_argument("--pfx-cert", metavar="PFXCERT", help="Use certificate authentication from pfx file .pfx")
    certificate_group.add_argument("--pfx-base64", metavar="PFXB64", help="Use certificate authentication from pfx file encoded in base64")
    certificate_group.add_argument("--pfx-pass", metavar="PFXPASS", help="Password of the pfx certificate")
    certificate_group.add_argument("--pem-cert", metavar="PEMCERT", help="Use certificate authentication from PEM file")
    certificate_group.add_argument("--pem-key", metavar="PEMKEY", help="Private key for the PEM format")

    p_loader = ProtocolLoader()
    protocols = p_loader.get_protocols()

    try:
        for protocol in protocols:
            protocol_object = p_loader.load_protocol(protocols[protocol]["argspath"])
            subparsers = protocol_object.proto_args(subparsers, [std_parser])
    except Exception as e:
        nxc_logger.exception(f"Error loading proto_args from proto_args.py file in protocol folder: {protocol} - {e}")

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
    for proto_name, proto_parser in subparsers.choices.items():
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
            if tok in ("-M", "--module") and i + 1 < len(argv) and argv[i + 1] == selected_module:
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
