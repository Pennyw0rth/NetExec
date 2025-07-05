from ipaddress import ip_address, ip_network, summarize_address_range, ip_interface
import netifaces


def get_local_ip():
    """Get the local IP address using netifaces library."""
    try:
        interfaces = netifaces.interfaces()
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
                        return ip
                        
    except Exception:
        pass
    
    return None


def parse_exclusions(exclusions):
    excluded_ips = set()
    for exclusion in exclusions:
        for ip in parse_targets(exclusion):
            excluded_ips.add(ip)
    return excluded_ips


def parse_targets(target):
    try:
        if "-" in target:
            start_ip, end_ip = target.split("-")
            try:
                end_ip = ip_address(end_ip)
            except ValueError:
                first_three_octets = start_ip.split(".")[:-1]
                first_three_octets.append(end_ip)
                end_ip = ip_address(".".join(first_three_octets))

            for ip_range in summarize_address_range(ip_address(start_ip), end_ip):
                for ip in ip_range:
                    yield str(ip)
        else:
            if ip_interface(target).ip.version == 6 and ip_address(target).is_link_local:
                yield str(target)
            else:
                for ip in ip_network(target, strict=False):
                    yield str(ip)
    except ValueError:
        yield str(target)
