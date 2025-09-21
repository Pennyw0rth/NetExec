import sys
import argparse
import argcomplete
import importlib.metadata
from argparse import RawTextHelpFormatter

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.helpers.logger import highlight
from nxc.helpers.args import DisplayDefaultsNotNone
from nxc.logger import nxc_logger, setup_debug_logging
from nxc.loaders.moduleloader import ModuleLoader


def build_parent_parsers():
    generic_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    generic_group = generic_parser.add_argument_group("Generic", "Generic options for nxc across protocols")
    generic_group.add_argument("--version", action="store_true", help="Display nxc version")
    generic_group.add_argument("-t", "--threads", type=int, dest="threads", default=256, help="Concurrent threads")
    generic_group.add_argument("--timeout", type=int, help="Max timeout per thread")
    generic_group.add_argument("--jitter", metavar="INTERVAL", type=str, help="Random delay between auths")
    generic_group.add_argument("-M", "--module", help="Select module to use", dest="module")

    output_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    output_group = output_parser.add_argument_group("Output", "Verbosity & output control")
    output_group.add_argument("--verbose", action="store_true")
    output_group.add_argument("--debug", action="store_true")
    output_group.add_argument("--no-progress", action="store_true")
    output_group.add_argument("--log", metavar="LOG")

    dns_parser = argparse.ArgumentParser(add_help=False, formatter_class=DisplayDefaultsNotNone)
    dns_group = dns_parser.add_argument_group("DNS")
    dns_group.add_argument("-6", dest="force_ipv6", action="store_true")
    dns_group.add_argument("--dns-server")
    dns_group.add_argument("--dns-tcp", action="store_true")
    dns_group.add_argument("--dns-timeout", type=int, default=3)

    return generic_parser, output_parser, dns_parser


def attach_modules_epilog(subparsers, per_proto_modules):
    for proto_name, proto_parser in subparsers.choices.items():
        mods = per_proto_modules.get(proto_name, [])
        if not mods:
            continue
        lines = [f"{proto_name.upper()} modules available:"]
        max_name_len = max((len(n) for n, _ in mods), default=0)
        for n, desc in sorted(mods, key=lambda x: x[0].lower()):
            lines.append(f"  {n.ljust(max_name_len)} : {desc}")
        proto_parser.epilog = (proto_parser.epilog or "") + "\n" + "\n".join(lines)


def extract_module_name(argv):
    for i, tok in enumerate(argv):
        if tok in ("-M", "--module") and i + 1 < len(argv):
            return argv[i + 1]
        if tok.startswith("--module="):
            return tok.split("=", 1)[1]
    return None


def filter_module_tokens(argv, mod_name, global_opts_set):
    try:
        mod_pos = argv.index(mod_name)
    except ValueError:
        return []
    tokens = argv[mod_pos + 1 :]
    filtered = []
    skip = False
    for t in tokens:
        if skip:
            skip = False
            continue
        name = t.split("=", 1)[0] if t.startswith("-") else None
        if name in global_opts_set:
            if "=" not in t:
                skip = True
            continue
        filtered.append(t)
    return filtered


def gen_cli_args():
    setup_debug_logging()

    # Parsing NXC version
    try:
        VERSION, COMMIT = importlib.metadata.version("netexec").split("+")
        DISTANCE, COMMIT = COMMIT.split(".")
    except Exception:
        VERSION = importlib.metadata.version("netexec")
        COMMIT = DISTANCE = ""
    CODENAME = "SmoothOperator"

    # Generic parser
    generic_parser, output_parser, dns_parser = build_parent_parsers()

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

    # Standard parsers
    std_parser = argparse.ArgumentParser(add_help=False, parents=[generic_parser, output_parser, dns_parser], formatter_class=DisplayDefaultsNotNone)
    std_parser.add_argument("target", nargs="+", help="Target IP(s), ranges, CIDR(s), hostnames, files, XML, Nessus")

    # Credentials
    credential_group = std_parser.add_argument_group("Authentication", "Options for authenticating")
    credential_group.add_argument("-u", "--username", metavar="USERNAME", dest="username", nargs="+", default=[], help="username(s) or file(s) containing usernames")
    credential_group.add_argument("-p", "--password", metavar="PASSWORD", dest="password", nargs="+", default=[], help="password(s) or file(s) containing passwords")
    credential_group.add_argument("-id", metavar="CRED_ID", nargs="+", default=[], type=str, dest="cred_id", help="database credential ID(s) to use for authentication")
    credential_group.add_argument("--ignore-pw-decoding", action="store_true")
    credential_group.add_argument("--no-bruteforce", action="store_true")
    credential_group.add_argument("--continue-on-success", action="store_true")
    credential_group.add_argument("--gfail-limit", metavar="LIMIT", type=int)
    credential_group.add_argument("--ufail-limit", metavar="LIMIT", type=int)
    credential_group.add_argument("--fail-limit", metavar="LIMIT", type=int)

    # Kerberos
    kerberos_group = std_parser.add_argument_group("Kerberos", "Options for Kerberos authentication")
    kerberos_group.add_argument("-k", "--kerberos", action="store_true")
    kerberos_group.add_argument("--use-kcache", action="store_true")
    kerberos_group.add_argument("--aesKey", metavar="AESKEY", nargs="+")
    kerberos_group.add_argument("--kdcHost", metavar="KDCHOST")

    # Certificate
    certificate_group = std_parser.add_argument_group("Certificate", "Options for certificate authentication")
    certificate_group.add_argument("--pfx-cert", metavar="PFXCERT")
    certificate_group.add_argument("--pfx-base64", metavar="PFXB64")
    certificate_group.add_argument("--pfx-pass", metavar="PFXPASS")
    certificate_group.add_argument("--pem-cert", metavar="PEMCERT")
    certificate_group.add_argument("--pem-key", metavar="PEMKEY")

    # Load protocols
    p_loader = ProtocolLoader()
    for proto, info in p_loader.get_protocols().items():
        try:
            proto_obj = p_loader.load_protocol(info["argspath"])
            proto_obj.proto_args(subparsers, [std_parser])
        except Exception as e:
            nxc_logger.exception(f"Error loading proto_args for {proto}: {e}")

    # Load modules
    module_loader = ModuleLoader()
    modules_map, per_proto_modules = module_loader.list_modules()
    attach_modules_epilog(subparsers, per_proto_modules)

    # --- Module help if requested directly (-M <module> -h) ---
    argv_tail = sys.argv[1:]
    if "-M" in argv_tail or "--module" in " ".join(argv_tail):
        sel_mod = extract_module_name(argv_tail)
        if sel_mod and ("-h" in argv_tail or "--help" in argv_tail):
            module_loader.print_module_help(sel_mod)
            sys.exit(0)

    # First args aprsing
    argcomplete.autocomplete(parser, always_complete_options=False)
    initial_args, _ = parser.parse_known_args()

    # If a module is found, parsing a second time to include module options
    selected_module = getattr(initial_args, "module", None)
    if selected_module:
        module_class = modules_map.get(selected_module)
        if not module_class:
            print(f"Module '{selected_module}' not found")
            sys.exit(1)

        global_opts_set = {opt for a in parser._actions for opt in getattr(a, "option_strings", [])}
        global_opts_set.update(opt for a in std_parser._actions for opt in getattr(a, "option_strings", []))
        module_tokens_filtered = filter_module_tokens(argv_tail, selected_module, global_opts_set)

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

        module_ns = module_only_parser.parse_args(module_tokens_filtered)
        merged = vars(initial_args).copy()
        merged.update(vars(module_ns))
        return argparse.Namespace(**merged), [CODENAME, VERSION, COMMIT, DISTANCE]

    return initial_args, [CODENAME, VERSION, COMMIT, DISTANCE]
