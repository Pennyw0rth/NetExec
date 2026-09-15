import sys
from impacket.dnsp import (
    ADIDNSManager,
    DNS_RECORD,
    DNS_RPC_RECORD_A,
    DNS_RPC_RECORD_NODE_NAME,
    DNS_RPC_RECORD_SRV,
    DNS_RPC_RECORD_TS,
    RECORD_TYPE_MAPPING,
    format_record,
)
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

# Short aliases for faster use: -o A=query R=new-pc D=10.0.20.5
ALIASES = {
    "A": "ACTION",
    "R": "RECORD",
    "D": "DATA",
    "O": "OPTIONS",
    "Z": "ZONE",
    "M": "ALLOWMULTIPLE",
    "T": "TOMBSTONED",
}

VALID_ACTIONS = (
    "list",
    "list-dn",
    "enum",
    "query",
    "add",
    "modify",
    "remove",
    "ldapdelete",
    "resurrect",
)

# Actions that operate on a specific record / that write record data
RECORD_ACTIONS = ("query", "add", "modify", "remove", "ldapdelete", "resurrect")
DATA_ACTIONS = ("add", "modify")


class NXCModule:
    """
    Manage DNS records of Active Directory integrated DNS zones via LDAP.
    Module by @lodos2005 inspired by @dirkjanm // https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
    Record handling is provided by impacket.dnsp.ADIDNSManager.
    """

    name = "dns"
    description = "Query/modify DNS records of Active Directory integrated DNS via LDAP"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION
    opsec_safe = True
    multiple_hosts = True

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
        options = {}
        for key, value in module_options.items():
            options[ALIASES.get(key.upper(), key.upper())] = value

        self.action = options.get("ACTION", "").lower()
        self.record = options.get("RECORD", "")
        self.data = options.get("DATA", "")
        self.zone = options.get("ZONE", "")
        self.partition = options.get("OPTIONS", "").lower() or "domain"
        self.allow_multiple = options.get("ALLOWMULTIPLE", "").lower() in (
            "true",
            "1",
            "yes",
        )
        self.include_tombstoned = options.get("TOMBSTONED", "").lower() in (
            "true",
            "1",
            "yes",
        )

        # Derive the default action before validating it
        if not self.action:
            if self.record and self.data:
                self.action = "add"
            elif self.record:
                self.action = "query"
            else:
                self.action = "list"

        if self.action not in VALID_ACTIONS:
            context.log.fail(
                f"Invalid ACTION '{self.action}', valid actions: {', '.join(VALID_ACTIONS)}"
            )
            sys.exit(1)

        if self.partition not in ("domain", "forest", "legacy"):
            context.log.fail(
                "OPTIONS must be 'forest' or 'legacy' (default: DomainDnsZones)"
            )
            sys.exit(1)

        if self.action in RECORD_ACTIONS and not self.record:
            context.log.fail(f"Action '{self.action}' requires the RECORD option")
            sys.exit(1)

        if self.action in DATA_ACTIONS and not self.data:
            context.log.fail(f"Action '{self.action}' requires the DATA option")
            sys.exit(1)

    def on_login(self, context, connection):
        manager = ADIDNSManager(
            connection.ldap_connection,
            dns_server=getattr(connection.args, "dns_server", None) or connection.host,
            dns_timeout=getattr(connection.args, "dns_timeout", None) or 3,
            domain_root=connection.baseDN or None,
            forest_root=getattr(connection, "forestDN", "") or None,
        )

        if self.action in ("list", "list-dn"):
            self._list_zones(context, manager)
        elif self.action == "enum":
            self._enum(context, connection, manager)
        elif self.action == "query":
            self._query(context, manager)
        else:
            self._mutate(context, manager)

    def _list_zones(self, context, manager):
        partitions = (
            [("legacy", "legacy")]
            if self.partition == "legacy"
            else [("domain", "domain"), ("forest", "forest")]
        )
        if self.partition == "forest":
            partitions = [("forest", "forest")]

        found_any = False
        for partition, label in partitions:
            zones = manager.get_dns_zones(partition, return_dn=self.action == "list-dn")
            if zones:
                found_any = True
                context.log.success(f"Found {len(zones)} {label} DNS zones:")
                for zone in zones:
                    context.log.highlight(f"    {zone}")

        if not found_any:
            context.log.fail("No DNS zones found")

    def _enum(self, context, connection, manager):
        zone = self.zone or manager.domain
        search_base = f"DC={zone},{manager.get_dns_root(self.partition)}"
        response = connection.search(
            searchFilter="(objectClass=dnsNode)",
            attributes=["dnsRecord", "dNSTombstoned", "name"],
            baseDN=search_base,
        )
        entries = [e for e in parse_result_attributes(response) if e]
        tombstoned_entries = [
            e for e in entries if str(e.get("dNSTombstoned", "FALSE")).upper() == "TRUE"
        ]
        visible_entries = (
            entries
            if self.include_tombstoned
            else [
                e
                for e in entries
                if str(e.get("dNSTombstoned", "FALSE")).upper() != "TRUE"
            ]
        )
        if not visible_entries:
            context.log.fail(f"No records found in zone {zone} ({self.partition})")
            return

        context.log.success(f"Found {len(visible_entries)} records in zone {zone}:")
        for entry in sorted(
            visible_entries, key=lambda e: str(e.get("name", "")).lower()
        ):
            records = entry.get("dnsRecord", [])
            if isinstance(records, bytes):
                records = [records]
            tombstoned = str(entry.get("dNSTombstoned", "FALSE")).upper() == "TRUE"
            name = (
                f"[TOMBSTONED] {entry.get('name', '?')}"
                if tombstoned
                else entry.get("name", "?")
            )
            for data in records:
                context.log.highlight(
                    f"    {name!s:<35} {self._summarize_record(DNS_RECORD(data))}"
                )

        if tombstoned_entries and not self.include_tombstoned:
            context.log.display(
                f"{len(tombstoned_entries)} tombstoned records hidden (use TOMBSTONED=true to show them)"
            )

    @staticmethod
    def _summarize_record(record):
        rtype = RECORD_TYPE_MAPPING.get(record["Type"], "UNKNOWN")
        if record["Type"] == 1:
            return f"A {DNS_RPC_RECORD_A(record['Data']).formatCanonical()}"
        if record["Type"] in (2, 5):
            fqdn = DNS_RPC_RECORD_NODE_NAME(record["Data"])["nameNode"].toFqdn()
            return f"{rtype} {fqdn}"
        if record["Type"] == 33:
            srv = DNS_RPC_RECORD_SRV(record["Data"])
            return f"SRV {srv['wPriority']} {srv['wWeight']} {srv['wPort']} {srv['nameTarget'].toFqdn()}"
        if record["Type"] == 0:
            return f"Tombstone ({DNS_RPC_RECORD_TS(record['Data']).toDatetime()})"
        return rtype

    def _query(self, context, manager):
        entry = manager.query_record(self.record, self.zone, self.partition)
        if entry is None:
            context.log.fail(manager.last_error)
            return

        context.log.success(f"Found record {entry['name']}")
        context.log.display(entry["dn"])
        for record in entry["records"]:
            for line in format_record(record, entry["tombstoned"]):
                context.log.display(line)

    def _mutate(self, context, manager):
        actions = {
            "add": lambda: manager.add_record(
                self.record,
                self.data,
                "A",
                self.zone,
                self.partition,
                self.allow_multiple,
            ),
            "modify": lambda: manager.modify_record(
                self.record, self.data, self.zone, self.partition
            ),
            "remove": lambda: manager.remove_record(
                self.record, self.zone, self.partition, self.data or None
            ),
            "ldapdelete": lambda: manager.ldap_delete(
                self.record, self.zone, self.partition
            ),
            "resurrect": lambda: manager.resurrect_record(
                self.record, self.zone, self.partition
            ),
        }

        if actions[self.action]():
            messages = {
                "add": f"Successfully added DNS record {self.record}",
                "modify": f"Successfully modified DNS record {self.record}",
                "remove": f"Successfully removed DNS record {self.record}",
                "ldapdelete": f"Successfully deleted DNS node {self.record} over LDAP",
                "resurrect": f"Record {self.record} resurrected. Re-add it with ACTION=add to set the IP address",
            }
            context.log.highlight(messages[self.action])
        else:
            context.log.fail(manager.last_error)
