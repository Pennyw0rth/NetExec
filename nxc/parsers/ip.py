import netifaces
from ipaddress import ip_address, ip_network, summarize_address_range, ip_interface
from nxc.helpers.logger import highlight
from nxc.helpers.misc import identify_target_file
from nxc.config import exclude_hosts, skip_self
from nxc.logger import nxc_logger
from nxc.parsers.nmap import parse_nmap_xml
from nxc.parsers.nessus import parse_nessus_file

from os.path import exists, isfile
from pathlib import Path
from sys import exit


def process_targets(args):
    targets = []
    if hasattr(args, "target") and args.target:
        for target in args.target:
            try:
                if exists(target) and isfile(target):
                    target_file_type = identify_target_file(target)
                    if target_file_type == "nmap":
                        targets.extend(parse_nmap_xml(target, args.protocol))
                    elif target_file_type == "nessus":
                        targets.extend(parse_nessus_file(target, args.protocol))
                    else:
                        with open(target) as target_file:
                            for target_entry in target_file:
                                targets.extend(parse_targets(target_entry.strip()))
                else:
                    targets.extend(parse_targets(target))
            except Exception as e:
                nxc_logger.fail(f"Failed to parse target '{target}': {e}")

    # Handle exclusions from config
    excluded_ips = set()

    # Process exclude_hosts from config. Important, we are reusing the parse_targets because it
    # already provides the code necessary for parsing all provided inputs
    if args.exclude_hosts is not None:
        exclude_hosts.extend(args.exclude_hosts)

    for excluded in exclude_hosts:
        if Path(excluded).is_file():
            with open(excluded) as excluded_file:
                for line in excluded_file.readlines():
                    excluded_ips.update(parse_targets(line.strip()))
        else:
            excluded_ips.update(parse_targets(excluded))

    # Process skip_self from config and cli argument
    if skip_self or args.skip_self:
        local_ips = get_local_ips()
        if local_ips:
            nxc_logger.debug(f"Local IP addresses detected: {local_ips}")
            excluded_ips.update(local_ips)
        else:
            nxc_logger.error("Could not determine local IP address for skip_self")

    # Validate that all objects to be excluded are valid IP addresses
    try:
        for ip in excluded_ips:
            ip_address(ip)
    except ValueError as e:
        nxc_logger.error(f"Invalid IP address in excluded hosts: {e}")
        exit(1)

    # Filter out excluded targets
    if excluded_ips:
        ignore_target_warning = False
        for target in targets:
            try:
                ip_address(target)
            except ValueError:
                if not ignore_target_warning:
                    ans = input(highlight("[!] Target is not an IP address, but exclusion list detected. Hostnames will not be filtered. Do you want to continue? [Y/n] ", "red"))
                    if ans.lower() not in ["y", "yes", ""]:
                        exit(1)
                    ignore_target_warning = True

        original_count = len(targets)
        excluded_targets = [target for target in targets if target in excluded_ips]
        targets = [target for target in targets if target not in excluded_ips]
        nxc_logger.debug(f"Excluding {original_count - len(targets)} hosts from scan: {excluded_targets}")
    return targets


def get_local_ips():
    """Get the local IP address using netifaces library."""
    interfaces = netifaces.interfaces()
    ips = set()

    for interface in interfaces:
        # Skip loopback interface
        if interface == "lo" or interface.startswith("lo"):
            continue

        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for addr_info in addresses[netifaces.AF_INET]:
                ip = addr_info.get("addr")
                # Skip localhost and link-local addresses
                if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                    ips.add(ip)
        if netifaces.AF_INET6 in addresses:
            for addr_info in addresses[netifaces.AF_INET6]:
                ip = addr_info.get("addr")
                # Skip localhost and link-local addresses
                if ip and not ip.startswith("::1") and not ip.startswith("fe80::"):
                    ips.add(ip)
    return ips


def parse_targets(target):
    try:
        if "-" in target:
            start_ip, end_ip = target.split("-")
            start = ip_address(start_ip)
            try:
                end = ip_address(end_ip)
            except ValueError:
                sep = ":" if start.version == 6 else "."
                prefix = start_ip.split(sep)[:-1]
                prefix.append(end_ip)
                end = ip_address(sep.join(prefix))

            for ip_range in summarize_address_range(start, end):
                for ip in ip_range:
                    yield str(ip)
        else:
            ip = ip_interface(target).ip
            if ip.version == 6 and ip.is_link_local:
                yield str(target)
            else:
                for ip in ip_network(target, strict=False):
                    yield str(ip)
    except ValueError:
        yield str(target)
