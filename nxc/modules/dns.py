import sys

from impacket.dnsp import ADIDNSManager, format_record
from nxc.helpers.misc import CATEGORY

# Short aliases for faster use: -o A=query R=new-pc D=10.0.20.5
ALIASES = {
    "A": "ACTION",
    "R": "RECORD",
    "D": "DATA",
    "O": "OPTIONS",
    "Z": "ZONE",
    "M": "ALLOWMULTIPLE",
}

VALID_ACTIONS = (
    "list",
    "list-dn",
    "query",
    "add",
    "modify",
    "remove",
    "ldapdelete",
    "resurrect",
)


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
        ACTION          Action to perform: list, list-dn, query, add, modify, remove, ldapdelete, resurrect.
                        Default is derived from the given options (add with RECORD+DATA, query with RECORD, else list)
        RECORD          Target DNS record (FQDN or relative to the zone)
        DATA            Record data (IP address for A records). For remove, the IP of the record to remove
        ZONE            Zone to operate in (default: current domain)
        OPTIONS         DNS partition: forest or legacy (default: DomainDnsZones)
        ALLOWMULTIPLE   Allow adding another A record when one already exists (default: false)
        Short aliases: A, R, D, Z, O, M

        Usage:
            nxc ldap 192.168.56.100 -u user -p pass -M dns -o ACTION=list
            nxc ldap 192.168.56.100 -u user -p pass -M dns -o ACTION=add RECORD=new-pc DATA=10.0.20.5
            nxc ldap 192.168.56.100 -u user -p pass -M dns -o A=query R=new-pc OPTIONS=forest
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

        if self.action not in ("list", "list-dn") and not self.record:
            context.log.fail(f"Action '{self.action}' requires the RECORD option")
            sys.exit(1)

        if self.action in ("add", "modify") and not self.data:
            context.log.fail(f"Action '{self.action}' requires the DATA option")
            sys.exit(1)

    def on_login(self, context, connection):
        manager = ADIDNSManager(
            connection.ldap_connection,
            dns_server=connection.host,
            domain_root=connection.baseDN or None,
            forest_root=getattr(connection, "forestDN", "") or None,
        )

        if self.action in ("list", "list-dn"):
            self._list_zones(context, manager)
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
