# Credit to https://twitter.com/snovvcrash/status/1550518555438891009
# Credit to https://github.com/dirkjanm/adidnsdump @_dirkjan
# module by @mpgn_x64
import re
import codecs
import socket
from datetime import datetime
from struct import unpack

from impacket.structure import Structure
from ldap3 import LEVEL
from os.path import expanduser
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH
from nxc.parsers.ldap_results import parse_result_attributes


def get_dns_zones(connection, root, debug=False):
    connection.search(root, "(objectClass=dnsZone)", search_scope=LEVEL, attributes=["dc"])
    zones = []
    for entry in connection.response:
        if entry["type"] != "searchResEntry":
            continue
        zones.append(entry["attributes"]["dc"])
    return zones


def ldap2domain(baseDN):
    return re.sub(r",DC=", ".", baseDN[baseDN.lower().find("dc="):], flags=re.IGNORECASE)[3:]


def new_record(rtype, serial):
    nr = DNS_RECORD()
    nr["Type"] = rtype
    nr["Serial"] = serial
    nr["TtlSeconds"] = 180
    # From authoritative zone
    nr["Rank"] = 240
    return nr


# From: https://docs.microsoft.com/en-us/windows/win32/dns/dns-constants
RECORD_TYPE_MAPPING = {
    0: "ZERO",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}

ZERO = 0
A = 1
NS = 2
CNAME = 5
SOA = 6
PTR = 12
MX = 15
TXT = 16
AAAA = 28
SRV = 33


class NXCModule:
    name = "get-network"
    description = "Query all DNS records with the corresponding IP from the domain."
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ALL           Get DNS and IP (default: false)
        ONLY_HOSTS    Get DNS only (no ip) (default: false)
        """
        self.showall = False
        self.showhosts = False

        if module_options and "ALL" in module_options:
            if module_options["ALL"].lower() == "true" or module_options["ALL"] == "1":
                self.showall = True
            else:
                context.log.display("Could not parse ALL option.")
        if module_options and "ONLY_HOSTS" in module_options:
            if module_options["ONLY_HOSTS"].lower() == "true" or module_options["ONLY_HOSTS"] == "1":
                self.showhosts = True
            else:
                context.log.display("Could not parse ONLY_HOSTS option.")

    def on_login(self, context, connection):
        zone = ldap2domain(connection.baseDN)
        dns_root = f"CN=MicrosoftDNS,DC=DomainDnsZones,{connection.baseDN}"
        search_target = f"DC={zone},{dns_root}"
        context.log.display("Querying zone for records")

        list_sites = connection.search(
            searchFilter="(DC=*)",
            attributes=["dnsRecord", "dNSTombstoned", "name"],
            baseDN=search_target,
        )
        list_sites_parsed = parse_result_attributes(list_sites)

        outdata = []
        for site in list_sites_parsed:
            recordname = site["name"]

            if "dnsRecord" in site:
                if isinstance(site["dnsRecord"], list):  # noqa: SIM108
                    records = [bytes(r) for r in site["dnsRecord"]]
                else:
                    records = [bytes(site["dnsRecord"])]

                for record in records:
                    dr = DNS_RECORD(record)
                    if dr["Type"] == A:
                        address = DNS_RPC_RECORD_A(dr["Data"])
                        if str(recordname) != "DomainDnsZones" and str(recordname) != "ForestDnsZones":
                            outdata.append(
                                {
                                    "name": recordname,
                                    "type": RECORD_TYPE_MAPPING[dr["Type"]],
                                    "value": address.formatCanonical(),
                                }
                            )
                    # Skip without "ALL" and "ONLY_HOSTS" => only IPs
                    elif dr["Type"] in [CNAME, NS, PTR] and (self.showall or self.showhosts):
                        address = DNS_RPC_RECORD_NODE_NAME(dr["Data"])
                        if str(recordname) != "DomainDnsZones" and str(recordname) != "ForestDnsZones":
                            outdata.append(
                                {
                                    "name": recordname,
                                    "type": RECORD_TYPE_MAPPING[dr["Type"]],
                                    "value": address["nameNode"].toFqdn(),
                                }
                            )
                    elif dr["Type"] == AAAA:
                        address = DNS_RPC_RECORD_AAAA(dr["Data"])
                        if str(recordname) != "DomainDnsZones" and str(recordname) != "ForestDnsZones":
                            outdata.append(
                                {
                                    "name": recordname,
                                    "type": RECORD_TYPE_MAPPING[dr["Type"]],
                                    "value": address.formatCanonical(),
                                }
                            )

        # Filter duplicate IPs if "ALL"  and "ONLY_HOSTS" are not set
        if not (self.showall or self.showhosts):
            seen_ips = set()
            outdata = [x for x in outdata if not (x["value"] in seen_ips or seen_ips.add(x["value"]))]

        context.log.highlight(f"Found {len(outdata)} records")
        path = expanduser(f"{NXC_PATH}/logs/{connection.domain}_network_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log")
        with codecs.open(path, "w", "utf-8") as outfile:
            for row in outdata:
                if self.showhosts:
                    outfile.write(f"{row['name'] + '.' + connection.domain}\n")
                elif self.showall:
                    outfile.write(f"{row['name'] + '.' + connection.domain} \t {row['value']}\n")
                else:
                    outfile.write(f"{row['value']}\n")
        context.log.success(f"Dumped {len(outdata)} records to {path}")
        if not self.showall and not self.showhosts:
            context.log.display(f"To extract CIDR from the {len(outdata)} ip, run  the following command: cat your_file | mapcidr -aa -silent | mapcidr -a -silent")


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """

    structure = (
        ("DataLength", "<H-Data"),
        ("Type", "<H"),
        ("Version", "B=5"),
        ("Rank", "B"),
        ("Flags", "<H=0"),
        ("Serial", "<L"),
        ("TtlSeconds", ">L"),
        ("Reserved", "<L=0"),
        ("TimeStamp", "<L=0"),
        ("Data", ":"),
    )


# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.


class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """

    structure = (("cchNameLength", "B-dnsName"), ("dnsName", ":"))


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """

    structure = (("Length", "B-RawName"), ("LabelCount", "B"), ("RawName", ":"))

    def toFqdn(self):
        ind = 0
        labels = []
        for _i in range(self["LabelCount"]):
            nextlen = unpack("B", self["RawName"][ind: ind + 1])[0]
            labels.append(self["RawName"][ind + 1: ind + 1 + nextlen].decode("utf-8"))
            ind += nextlen + 1
        # For the final dot
        labels.append("")
        return ".".join(labels)


class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """

    structure = (
        ("wLength", ">H"),
        ("wRecordCount", ">H"),
        ("dwFlags", ">L"),
        ("dwChildCount", ">L"),
        ("dnsNodeName", ":"),
    )


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """

    structure = (("address", ":"),)

    def formatCanonical(self):
        return socket.inet_ntoa(self["address"])

    def fromCanonical(self, canonical):
        self["address"] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """

    structure = (("nameNode", ":", DNS_COUNT_NAME),)


class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """

    structure = (
        ("dwSerialNo", ">L"),
        ("dwRefresh", ">L"),
        ("dwRetry", ">L"),
        ("dwExpire", ">L"),
        ("dwMinimumTtl", ">L"),
        ("namePrimaryServer", ":", DNS_COUNT_NAME),
        ("zoneAdminEmail", ":", DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """

    structure = (("bData", ":"),)


# Some missing structures here that I skipped


class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """

    structure = (("wPreference", ">H"), ("nameExchange", ":", DNS_COUNT_NAME))


# Some missing structures here that I skipped


class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """

    structure = (("ipv6Address", "16s"),)

    def formatCanonical(self):
        return socket.inet_ntop(socket.AF_INET6, self["ipv6Address"])


class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """

    structure = (
        ("wPriority", ">H"),
        ("wWeight", ">H"),
        ("wPort", ">H"),
        ("nameTarget", ":", DNS_COUNT_NAME),
    )


class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """

    structure = (("entombedTime", "<Q"),)

    def toDatetime(self):
        microseconds = int(self["entombedTime"] / 10)
        try:
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)
        except OverflowError:
            return None
