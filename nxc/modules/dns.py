import datetime
import random
import re
import socket
import struct

from impacket.ldap import ldapasn1
from impacket.ldap.ldap import LDAPSessionError, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from impacket.structure import Structure
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

RECORD_TYPE_MAPPING = {
    0: "ZERO",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    33: "SRV",
    65281: "WINS",
}


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


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME, used for FQDNs in LDAP communication
    [MS-DNSP] section 2.2.2.2.2
    """

    structure = (
        ("Length", "B-RawName"),
        ("LabelCount", "B"),
        ("RawName", ":"),
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for _i in range(self["LabelCount"]):
            nextlen = struct.unpack("B", self["RawName"][ind:ind + 1])[0]
            labels.append(self["RawName"][ind + 1:ind + 1 + nextlen].decode("utf-8"))
            ind += nextlen + 1
        # For the final dot
        labels.append("")
        return ".".join(labels)


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


class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS (Tombstone Record)
    [MS-DNSP] section 2.2.2.2.4.23
    """

    structure = (("entombedTime", "<Q"),)

    def toDatetime(self):
        microseconds = self["entombedTime"] / 10.0
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)


class NXCModule:
    """
    Manage DNS records of Active Directory integrated DNS zones via LDAP.
    Module by @lodos2005 inspired by @dirkjanm // https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
    """

    name = "dns"
    description = "Query/modify DNS records of Active Directory integrated DNS via LDAP"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION
    opsec_safe = True
    multiple_hosts = True

    ALIASES = {"A": "ACTION", "R": "RECORD", "D": "DATA", "O": "OPTIONS", "Z": "ZONE", "M": "ALLOWMULTIPLE", "T": "TOMBSTONED"}
    VALID_ACTIONS = ("list", "list-dn", "enum", "query", "add", "modify", "remove", "ldapdelete", "resurrect")
    RECORD_ACTIONS = ("query", "add", "modify", "remove", "ldapdelete", "resurrect")

    def options(self, context, module_options):
        """
        ACTION          Action to perform (default: add with RECORD+DATA, query with RECORD, otherwise list):
                          list         list DNS zones of the domain and forest partitions
                          list-dn      same as list, but show the zones' Distinguished Names
                          enum         dump every record of the zone (set ZONE/OPTIONS to target another one)
                          query        show one record and all its values
                          add          add an A record (requires RECORD + DATA)
                          modify       change the IP of an existing A record (requires RECORD + DATA)
                          remove       tombstone the record (DATA removes one IP of a multi-record node)
                          ldapdelete   delete the record object directly from LDAP, bypassing the tombstone
                          resurrect    revive a tombstoned record, re-add its IP afterwards with ACTION=add
        RECORD          Target DNS record, FQDN or relative to the zone (e.g. 'web01' or 'web01.corp.local')
        DATA            Record data, an IPv4 address for A records (e.g. 10.0.20.5)
        ZONE            Zone to operate in (default: current domain)
        OPTIONS         DNS partition: forest (ForestDnsZones) or legacy (CN=System); default: DomainDnsZones
        ALLOWMULTIPLE   With ACTION=add: append the record even if another A record exists (default: false)
        TOMBSTONED      With ACTION=enum: also show tombstoned records, marked [TOMBSTONED] (default: false)

        Short aliases: A=ACTION, R=RECORD, D=DATA, Z=ZONE, O=OPTIONS, M=ALLOWMULTIPLE, T=TOMBSTONED

        Usage:
            nxc ldap 192.168.20.05 -u user -p pass -M dns                                # list zones
            nxc ldap 192.168.20.05 -u user -p pass -M dns -o ACTION=enum                 # dump zone records
            nxc ldap 192.168.20.05 -u user -p pass -M dns -o ACTION=add RECORD=web01 DATA=10.0.20.5
            nxc ldap 192.168.20.05 -u user -p pass -M dns -o A=query R=web01             # short aliases
            nxc ldap 192.168.20.05 -u user -p pass -M dns -o A=add R=web01 D=10.0.20.6 M=true   # second IP
            nxc ldap 192.168.20.05 -u user -p pass -M dns -o ACTION=enum ZONE=_msdcs.corp.local OPTIONS=forest T=true
        """
        options = {self.ALIASES.get(key.upper(), key.upper()): value for key, value in module_options.items()}

        self.action = options.get("ACTION", "").lower()
        self.record = options.get("RECORD", "")
        self.data = options.get("DATA", "")
        self.zone = options.get("ZONE", "")
        self.partition = options.get("OPTIONS", "").lower() or "domain"
        self.allow_multiple = options.get("ALLOWMULTIPLE", "").lower() in ("true", "1", "yes")
        self.include_tombstoned = options.get("TOMBSTONED", "").lower() in ("true", "1", "yes")

        # Derive the default action before validating it
        if not self.action:
            if self.record and self.data:
                self.action = "add"
            elif self.record:
                self.action = "query"
            else:
                self.action = "list"

        if self.action not in self.VALID_ACTIONS:
            context.log.fail(f"Invalid ACTION '{self.action}', valid actions: {', '.join(self.VALID_ACTIONS)}")
            return False

        if self.partition not in ("domain", "forest", "legacy"):
            context.log.fail("OPTIONS must be 'forest' or 'legacy' (default: DomainDnsZones)")
            return False

        if self.action in self.RECORD_ACTIONS and not self.record:
            context.log.fail(f"Action '{self.action}' requires the RECORD option")
            return False

        if self.action in ("add", "modify") and not self.data:
            context.log.fail(f"Action '{self.action}' requires the DATA option")
            return False

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.ldap = connection.ldap_connection
        self.dns_server = getattr(connection.args, "dns_server", None) or connection.host
        self.dns_timeout = getattr(connection.args, "dns_timeout", None) or 3
        rootdse = parse_result_attributes(self.ldap.search(searchBase="", searchFilter="(objectClass=*)", attributes=["schemaNamingContext"], scope=ldapasn1.Scope("baseObject")))
        self.schema_root = rootdse[0]["schemaNamingContext"] if rootdse else ""

        if self.action in ("list", "list-dn"):
            self._list_zones(context)
        elif self.action == "enum":
            self._enum(context)
        elif self.action == "query":
            self._query(context)
        elif self.action == "add":
            self._add(context)
        elif self.action == "modify":
            self._modify(context)
        elif self.action == "remove":
            self._remove(context)
        elif self.action == "ldapdelete":
            self._ldap_delete(context)
        elif self.action == "resurrect":
            self._resurrect(context)

    def _dns_root(self, partition=None):
        partition = partition or self.partition
        if partition == "forest":
            return f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.connection.forestDN}"
        if partition == "legacy":
            return f"CN=MicrosoftDNS,CN=System,{self.connection.baseDN}"
        return f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.connection.baseDN}"

    @staticmethod
    def _ldap2domain(ldap_dn):
        return re.sub(r",DC=", ".", ldap_dn[ldap_dn.find("DC="):], flags=re.I)[3:]

    def _zone_and_target(self):
        zone = self.zone or self._ldap2domain(self.connection.baseDN)
        target = self.record
        if target.lower().endswith(zone.lower()):
            target = target[:-(len(zone) + 1)]
        return zone, target

    def _find_record(self):
        zone, target = self._zone_and_target()
        resp = self.connection.search(
            searchFilter=f"(&(objectClass=dnsNode)(name={self._escape_filter_chars(target)}))",
            attributes=["dnsRecord", "dNSTombstoned", "distinguishedName"],
            baseDN=f"DC={zone},{self._dns_root()}",
        )
        entries = parse_result_attributes(resp)
        if not entries:
            return None
        records = entries[0].get("dnsRecord", b"")
        if isinstance(records, bytes):
            records = [records]
        return {"dn": entries[0]["distinguishedName"], "tombstoned": entries[0].get("dNSTombstoned", "FALSE").upper() == "TRUE", "records": records}

    @staticmethod
    def _escape_filter_chars(value):
        value = value.replace("\\", "\\5c")
        for char, escaped in (("\x00", "\\00"), ("*", "\\2a"), ("(", "\\28"), (")", "\\29")):
            value = value.replace(char, escaped)
        return value

    def _list_zones(self, context):
        if self.partition == "forest":
            partitions = [("forest", "forest")]
        elif self.partition == "legacy":
            partitions = [("legacy", "legacy")]
        else:
            partitions = [("domain", "domain"), ("forest", "forest")]

        attribute = "distinguishedName" if self.action == "list-dn" else "dc"
        found_any = False
        for partition, label in partitions:
            resp = self.connection.search(searchFilter="(objectClass=dnsZone)", attributes=[attribute], baseDN=self._dns_root(partition))
            zones = [zone[attribute] for zone in parse_result_attributes(resp) if zone]
            if zones:
                found_any = True
                context.log.success(f"Found {len(zones)} {label} DNS zones:")
                for zone in zones:
                    context.log.highlight(f"    {zone}")

        if not found_any:
            context.log.fail("No DNS zones found")

    def _enum(self, context):
        zone = self.zone or self._ldap2domain(self.connection.baseDN)
        resp = self.connection.search(searchFilter="(objectClass=dnsNode)", attributes=["dnsRecord", "dNSTombstoned", "name"], baseDN=f"DC={zone},{self._dns_root()}")
        entries = [entry for entry in parse_result_attributes(resp) if entry]
        if not entries:
            context.log.fail(f"No records found in zone {zone} ({self.partition})")
            return

        tombstoned_entries, visible_entries = [], []
        for entry in entries:
            if entry.get("dNSTombstoned", "FALSE").upper() == "TRUE":
                tombstoned_entries.append(entry)
            else:
                visible_entries.append(entry)
        entries_to_show = visible_entries + tombstoned_entries if self.include_tombstoned else visible_entries

        context.log.success(f"Found {len(entries_to_show)} records in zone {zone}:")
        for entry in sorted(entries_to_show, key=lambda e: e["name"].lower()):
            records = entry.get("dnsRecord", b"")
            if isinstance(records, bytes):
                records = [records]
            name = f"[TOMBSTONED] {entry['name']}" if entry.get("dNSTombstoned", "FALSE").upper() == "TRUE" else entry["name"]
            for data in records:
                context.log.highlight(f"    {name:<35} {self._summarize_record(DNS_RECORD(data))}")

        if tombstoned_entries and not self.include_tombstoned:
            context.log.display(f"{len(tombstoned_entries)} tombstoned records hidden (use TOMBSTONED=true to show them)")

    @staticmethod
    def _summarize_record(record):
        rtype = RECORD_TYPE_MAPPING.get(record["Type"], "UNKNOWN")
        if record["Type"] == 1:
            return f"A {DNS_RPC_RECORD_A(record['Data']).formatCanonical()}"
        if record["Type"] in (2, 5):
            return f"{rtype} {DNS_RPC_RECORD_NODE_NAME(record['Data'])['nameNode'].toFqdn()}"
        if record["Type"] == 33:
            srv = DNS_RPC_RECORD_SRV(record["Data"])
            return f"SRV {srv['wPriority']} {srv['wWeight']} {srv['wPort']} {srv['nameTarget'].toFqdn()}"
        if record["Type"] == 0:
            return f"Tombstone ({DNS_RPC_RECORD_TS(record['Data']).toDatetime()})"
        return rtype

    @staticmethod
    def _format_record(record, ts=False):
        lines = ["Record entry:", f" - Type: {record['Type']} ({RECORD_TYPE_MAPPING.get(record['Type'], 'Unsupported')}) (Serial: {record['Serial']})"]
        if ts:
            lines.insert(0, "Record is tombStoned (inactive)")
        if record["Type"] == 0:
            lines.append(f" - Tombstoned at: {DNS_RPC_RECORD_TS(record['Data']).toDatetime()}")
        elif record["Type"] == 1:
            lines.append(f" - Address: {DNS_RPC_RECORD_A(record['Data']).formatCanonical()}")
        elif record["Type"] in (2, 5):
            lines.append(f" - Address: {DNS_RPC_RECORD_NODE_NAME(record['Data'])['nameNode'].toFqdn()}")
        elif record["Type"] == 33:
            srv = DNS_RPC_RECORD_SRV(record["Data"])
            lines.append(f" - Priority: {srv['wPriority']}")
            lines.append(f" - Weight: {srv['wWeight']}")
            lines.append(f" - Port: {srv['wPort']}")
            lines.append(f" - Name: {srv['nameTarget'].toFqdn()}")
        elif record["Type"] == 6:
            soa = DNS_RPC_RECORD_SOA(record["Data"])
            lines.append(f" - Serial: {soa['dwSerialNo']}")
            lines.append(f" - Refresh: {soa['dwRefresh']}")
            lines.append(f" - Retry: {soa['dwRetry']}")
            lines.append(f" - Expire: {soa['dwExpire']}")
            lines.append(f" - Minimum TTL: {soa['dwMinimumTtl']}")
            lines.append(f" - Primary server: {soa['namePrimaryServer'].toFqdn()}")
            lines.append(f" - Zone admin email: {soa['zoneAdminEmail'].toFqdn()}")
        return lines

    def _query(self, context):
        entry = self._find_record()
        if entry is None:
            context.log.fail("Target record not found!")
            return
        context.log.success(f"Found record {self.record}")
        context.log.display(entry["dn"])
        for data in entry["records"]:
            for line in self._format_record(DNS_RECORD(data), entry["tombstoned"]):
                context.log.display(line)

    def _next_serial(self, zone):
        if self.dns_server:
            serial = self._query_soa_serial(zone)
            if serial is not None:
                return serial + 1
        return int(datetime.datetime.now().timestamp())

    def _query_soa_serial(self, zone):
        try:
            try:
                socket.inet_aton(self.dns_server)
            except OSError:
                server = socket.gethostbyname(self.dns_server)
            else:
                server = self.dns_server
            qname = b"".join(struct.pack("B", len(label)) + label.encode() for label in zone.rstrip(".").split(".")) + b"\x00"
            query = struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 6, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.dns_timeout)
            try:
                sock.sendto(query, (server, 53))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
            flags, qdcount, ancount = struct.unpack(">HHH", data[2:8])
            if not flags & 0x8000 or ancount == 0:
                return None
            offset = self._skip_name(data, 12) + 4
            offset = self._skip_name(data, offset)
            rtype, _rclass, _ttl, _rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype != 6:
                return None
            offset = self._skip_name(data, offset)
            offset = self._skip_name(data, offset)
            return struct.unpack(">I", data[offset:offset + 4])[0]
        except Exception:
            return None

    @staticmethod
    def _skip_name(data, offset):
        while True:
            length = data[offset]
            if length & 0xC0 == 0xC0:
                return offset + 2
            if length == 0:
                return offset + 1
            offset += length + 1

    def _new_record(self, rtype, serial, ttl=180):
        record = DNS_RECORD()
        record["Type"] = rtype
        record["Serial"] = serial
        record["TtlSeconds"] = ttl
        # From authoritative zone
        record["Rank"] = 240
        return record

    def _build_a_record(self, serial):
        record = self._new_record(1, serial)
        data = DNS_RPC_RECORD_A()
        data.fromCanonical(self.data)
        record["Data"] = data
        return record

    def _build_tombstone_record(self, serial):
        record = self._new_record(0, serial)
        data = DNS_RPC_RECORD_TS()
        diff = datetime.datetime.today() - datetime.datetime(1601, 1, 1)
        data["entombedTime"] = int(diff.total_seconds() * 10000000)
        record["Data"] = data
        return record

    def _add(self, context):
        try:
            socket.inet_aton(self.data)
        except OSError:
            context.log.fail(f"'{self.data}' is not a valid IPv4 address")
            return

        zone, target = self._zone_and_target()
        entry = self._find_record()
        record = self._build_a_record(self._next_serial(zone))
        try:
            if entry is not None:
                if not self.allow_multiple:
                    for data in entry["records"]:
                        existing = DNS_RECORD(data)
                        if existing["Type"] == 1:
                            address = DNS_RPC_RECORD_A(existing["Data"]).formatCanonical()
                            context.log.fail(f"Record already exists and points to {address}. Use ACTION=modify to overwrite or ALLOWMULTIPLE=true to override this")
                            return
                self.ldap.modify(entry["dn"], {"dnsRecord": [(MODIFY_ADD, record.getData())]})
            else:
                self.ldap.add(f"DC={target},DC={zone},{self._dns_root()}", ["top", "dnsNode"], {"objectCategory": f"CN=Dns-Node,{self.schema_root}", "dNSTombstoned": b"FALSE", "name": target, "dnsRecord": record.getData()})
            context.log.highlight(f"Successfully added DNS record {self.record}")
        except LDAPSessionError as e:
            context.log.fail(str(e))

    def _modify(self, context):
        try:
            socket.inet_aton(self.data)
        except OSError:
            context.log.fail(f"'{self.data}' is not a valid IPv4 address")
            return

        zone, _target = self._zone_and_target()
        entry = self._find_record()
        if entry is None:
            context.log.fail("Target record not found!")
            return

        records = []
        modified = False
        for data in entry["records"]:
            existing = DNS_RECORD(data)
            if existing["Type"] == 1 and not modified:
                records.append(self._build_a_record(self._next_serial(zone)).getData())
                modified = True
            else:
                records.append(data)

        if not modified:
            context.log.fail("No A record exists yet. Use ACTION=add to add it")
            return

        try:
            self.ldap.modify(entry["dn"], {"dnsRecord": [(MODIFY_REPLACE, records)]})
            context.log.highlight(f"Successfully modified DNS record {self.record}")
        except LDAPSessionError as e:
            context.log.fail(str(e))

    def _remove(self, context):
        zone, _target = self._zone_and_target()
        entry = self._find_record()
        if entry is None:
            context.log.fail("Target record not found!")
            return

        try:
            if len(entry["records"]) > 1:
                target_data = None
                for data in entry["records"]:
                    existing = DNS_RECORD(data)
                    if existing["Type"] == 1 and self.data and DNS_RPC_RECORD_A(existing["Data"]).formatCanonical() == self.data:
                        target_data = data
                        break
                if target_data is None:
                    context.log.fail("Could not find a record with the specified data")
                    return
                self.ldap.modify(entry["dn"], {"dnsRecord": [(MODIFY_DELETE, target_data)]})
            else:
                tombstone = self._build_tombstone_record(self._next_serial(zone))
                self.ldap.modify(entry["dn"], {"dnsRecord": [(MODIFY_REPLACE, tombstone.getData())], "dNSTombstoned": [(MODIFY_REPLACE, b"TRUE")]})
            context.log.highlight(f"Successfully removed DNS record {self.record}")
        except LDAPSessionError as e:
            context.log.fail(str(e))

    def _ldap_delete(self, context):
        entry = self._find_record()
        if entry is None:
            context.log.fail("Target record not found!")
            return
        try:
            self.ldap.delete(entry["dn"])
            context.log.highlight(f"Successfully deleted DNS node {self.record} over LDAP")
        except LDAPSessionError as e:
            context.log.fail(str(e))

    def _resurrect(self, context):
        zone, _target = self._zone_and_target()
        entry = self._find_record()
        if entry is None:
            context.log.fail("Target record not found!")
            return

        if len(entry["records"]) > 1:
            context.log.fail("Target has multiple records, I dont know how to handle this.")
            return

        tombstone = self._build_tombstone_record(self._next_serial(zone))
        try:
            self.ldap.modify(entry["dn"], {"dnsRecord": [(MODIFY_REPLACE, tombstone.getData())], "dNSTombstoned": [(MODIFY_REPLACE, b"FALSE")]})
            context.log.highlight(f"Record {self.record} resurrected. Re-add it with ACTION=add to set the IP address")
        except LDAPSessionError as e:
            context.log.fail(str(e))
