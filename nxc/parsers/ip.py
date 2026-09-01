import netifaces
from ipaddress import ip_address, ip_network, summarize_address_range, ip_interface


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
