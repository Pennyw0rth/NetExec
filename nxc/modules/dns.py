import sys
import re
import socket
import datetime
from struct import unpack
from impacket.structure import Structure
from ldap3 import LEVEL, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, Tls, Server, Connection, NTLM
import ldap3
import dns.resolver
import ssl


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
        ("Data", ":")
    )


class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ("Length", "B-RawName"),
        ("LabelCount", "B"),
        ("RawName", ":")
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for _i in range(self["LabelCount"]):
            nextlen = unpack("B", self["RawName"][ind:ind + 1])[0]
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
    structure = (
        ("address", ":"),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self["address"])

    def fromCanonical(self, canonical):
        self["address"] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ("nameNode", ":", DNS_COUNT_NAME),
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
        ("zoneAdminEmail", ":", DNS_COUNT_NAME)
    )


class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ("wPriority", ">H"),
        ("wWeight", ">H"),
        ("wPort", ">H"),
        ("nameTarget", ":", DNS_COUNT_NAME)
    )


class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ("entombedTime", "<Q"),
    )

    def toDatetime(self):
        microseconds = self["entombedTime"] / 10.
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)


RECORD_TYPE_MAPPING = {
    0: "ZERO",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    33: "SRV",
    65281: "WINS"
}


class NXCModule:
    """
    DNS management module for Active Directory integrated DNS via LDAP
    Module by @lodos2005 inspired by @dirkjanm // https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
    """

    name = "dns"
    description = "Query/modify DNS records for Active Directory integrated DNS via LDAP"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None
        self.show_usage = False

    def print_usage(self, context):
        context.log.highlight("DNS management module for Active Directory integrated DNS via LDAP")
        context.log.highlight("Module by @lodos2005 inspired by @dirkjanm")
        context.log.highlight("Usage: -M dns -o <options>")
        context.log.highlight("")
        context.log.highlight("ACTIONS (specify with -o ACTION=<action> or A=<action>):")
        context.log.highlight("")
        context.log.highlight("  add:          Adds a new A record. Requires RECORD and DATA.")
        context.log.highlight("    Example: -M dns -o ACTION=add RECORD=new-pc DATA=10.0.20.05")
        context.log.highlight("")
        context.log.highlight("  modify:       Modifies an existing A record. Requires RECORD and DATA.")
        context.log.highlight("    Example: -M dns -o ACTION=modify RECORD=new-pc DATA=10.0.20.05")
        context.log.highlight("")
        context.log.highlight("  query:        Queries an existing record. Requires RECORD.")
        context.log.highlight("    Example: -M dns -o A=query R=new-pc")
        context.log.highlight("")
        context.log.highlight("  remove:       Removes a record by tombstoning it. Requires RECORD and optionally DATA.")
        context.log.highlight("    Example: -M dns -o ACTION=remove RECORD=new-pc DATA=10.0.20.05")
        context.log.highlight("")
        context.log.highlight("  ldapdelete:   Deletes a record object directly from LDAP. Requires RECORD.")
        context.log.highlight("    Example: -M dns -o A=ldapdelete R=new-pc")
        context.log.highlight("")
        context.log.highlight("  resurrect:    Resurrects a tombstoned record object. Requires RECORD.")
        context.log.highlight("    Example: -M dns -o ACTION=resurrect RECORD=tombstoned-pc")
        context.log.highlight("")
        context.log.highlight("  list:         Lists all DNS zones. (Default action if no options are given)")
        context.log.highlight("    Example: -M dns -o ACTION=list")
        context.log.highlight("")
        context.log.highlight("  list-dn:      Lists all DNS zones with their Distinguished Names.")
        context.log.highlight("    Example: -M dns -o ACTION=list-dn")
        context.log.highlight("")
        context.log.highlight("OTHER OPTIONS:")
        context.log.highlight("  RECORD / R:       The FQDN of the record to target (e.g., 'lodos2005').")
        context.log.highlight("  DATA / D:         The data for the record. For A records, this is the IP address. (e.g., 10.0.20.05)")
        context.log.highlight("  OPTIONS / O:      DNS partition to use ('forest' or 'legacy'). Default is DomainDnsZones.")
        context.log.highlight("  ZONE / Z:         Zone to search in, if different from the current domain. (e.g., lodos2005.local)")
        context.log.highlight("  ALLOWMULTIPLE / M: Allow multiple A records for the same name (e.g., 'true').")
        context.log.highlight("  HELP / H:         Show this help message.")
        
    def options(self, context, module_options):
        """
        Options:
        --------
        ACTION      Action to perform: add, modify, query, remove, resurrect, ldapdelete, list, list-dn (default: auto)
        RECORD      Target DNS record (FQDN)
        DATA        Record data (IP address for A records)
        OPTIONS     DNS zone options: legacy, forest
        ZONE        Zone to search in (if different than the current domain)
        ALLOWMULTIPLE   Allow multiple A records for the same name (default: false)
        HELP          Show usage examples
        A           Alias for ACTION
        R           Alias for RECORD
        D           Alias for DATA
        O           Alias for OPTIONS
        Z           Alias for ZONE
        M           Alias for ALLOWMULTIPLE
        H           Show usage examples

        
        """
        self.context = context
        self.module_options = module_options
        self.show_usage = False

        if "HELP" in module_options or "H" in module_options:
            self.action = "help"
            return

        # Parse options with aliases
        self.action = module_options.get("ACTION", "").lower()
        if "A" in module_options:
            self.action = module_options["A"].lower()

        # if action not valid list show usage
        if self.action not in ["add", "modify", "query", "remove", "ldapdelete", "resurrect", "list", "list-dn"]:
            self.print_usage(context)
            sys.exit(1)
            
        self.record = module_options.get("RECORD", "")
        if "R" in module_options:
            self.record = module_options["R"]
            
        self.data = module_options.get("DATA", "")
        if "D" in module_options:
            self.data = module_options["D"]
            
        self.dns_options = module_options.get("OPTIONS", "").lower()
        if "O" in module_options:
            self.dns_options = module_options["O"].lower()
            
        self.zone = module_options.get("ZONE", "")
        if "Z" in module_options:
            self.zone = module_options["Z"]
            
        self.allow_multiple = module_options.get("ALLOWMULTIPLE", "false").lower() == "true"
        if "M" in module_options:
            self.allow_multiple = module_options["M"].lower() == "true"
            
        help_value = module_options.get("HELP", "false").lower()
        self.show_usage = help_value == "true" or help_value == "" or len(help_value) > 0 or "H" in module_options
        if help_value == "false":
            self.show_usage = False

        # Determine default action based on provided parameters
        if not self.action:
            if self.record and self.data:
                self.action = "add"
            elif self.record and not self.data:
                self.action = "query"
            elif not self.record and not self.data:
                self.action = "list"
            else:
                context.log.fail("You must specify ACTION when RECORD and DATA are not provided together")
                sys.exit(1)

        # Validate required parameters
        if self.action in ["add", "modify", "remove"] and not self.data:
            context.log.fail(f"Action '{self.action}' requires DATA parameter")
            sys.exit(1)

        if self.action in ["modify", "remove", "ldapdelete", "resurrect", "query"] and not self.record:
            context.log.fail(f"Action '{self.action}' requires RECORD parameter")
            sys.exit(1)

    def get_dns_zones(self, ldap_conn, root, attr="dc"):
        """Get DNS zones from LDAP"""
        ldap_conn.search(search_base=root, search_filter="(objectClass=dnsZone)", search_scope=LEVEL, attributes=[attr])
        zones = []
        for entry in ldap_conn.response:
            if entry["type"] != "searchResEntry":
                continue
            zones.append(entry["attributes"][attr])
        return zones

    def get_next_serial(self, dc, zone):
        """Get next serial number for DNS record"""
        try:
            dnsresolver = dns.resolver.Resolver()
            try:
                socket.inet_aton(dc)
                dnsresolver.nameservers = [dc]
            except OSError:
                pass

            res = dnsresolver.resolve(zone, "SOA", tcp=True)
            for answer in res:
                return answer.serial + 1
        except Exception:
            # If we can't get serial, use current timestamp
            return int(datetime.datetime.now().timestamp())

    def ldap2domain(self, ldap):
        """Convert LDAP DN to domain name"""
        return re.sub(r",DC=", ".", ldap[ldap.find("DC="):], flags=re.I)[3:]

    def print_record(self, context, record, ts=False):
        """Print DNS record information"""
        try:
            rtype = RECORD_TYPE_MAPPING[record["Type"]]
        except KeyError:
            rtype = "Unsupported"
        
        if ts:
            context.log.highlight("Record is tombStoned (inactive)")
        
        context.log.success("Record entry:")
        context.log.display(f' - Type: {record["Type"]} ({rtype}) (Serial: {record["Serial"]})')
        
        if record["Type"] == 0:
            tstime = DNS_RPC_RECORD_TS(record["Data"])
            context.log.display(f" - Tombstoned at: {tstime.toDatetime()}")
        # A record
        elif record["Type"] == 1:
            address = DNS_RPC_RECORD_A(record["Data"])
            context.log.display(f" - Address: {address.formatCanonical()}")
        # NS record or CNAME record
        elif record["Type"] == 2 or record["Type"] == 5:
            address = DNS_RPC_RECORD_NODE_NAME(record["Data"])
            context.log.display(f' - Address: {address["nameNode"].toFqdn()}')
        # SRV record
        elif record["Type"] == 33:
            record_data = DNS_RPC_RECORD_SRV(record["Data"])
            context.log.display(f' - Priority: {record_data["wPriority"]}')
            context.log.display(f' - Weight: {record_data["wWeight"]}')
            context.log.display(f' - Port: {record_data["wPort"]}')
            context.log.display(f' - Name: {record_data["nameTarget"].toFqdn()}')
        # SOA record
        elif record["Type"] == 6:
            record_data = DNS_RPC_RECORD_SOA(record["Data"])
            context.log.display(f' - Serial: {record_data["dwSerialNo"]}')
            context.log.display(f' - Refresh: {record_data["dwRefresh"]}')
            context.log.display(f' - Retry: {record_data["dwRetry"]}')
            context.log.display(f' - Expire: {record_data["dwExpire"]}')
            context.log.display(f' - Minimum TTL: {record_data["dwMinimumTtl"]}')
            context.log.display(f' - Primary server: {record_data["namePrimaryServer"].toFqdn()}')
            context.log.display(f' - Zone admin email: {record_data["zoneAdminEmail"].toFqdn()}')

    def new_record(self, rtype, serial):
        """Create new DNS record"""
        nr = DNS_RECORD()
        nr["Type"] = rtype
        nr["Serial"] = serial
        nr["TtlSeconds"] = 180
        # From authoritive zone
        nr["Rank"] = 240
        return nr

    def on_login(self, context, connection):
        """Main module execution"""
        self.context = context
        
        if hasattr(self, "action") and self.action == "help":
            self.print_usage(context)
            return

        if not hasattr(self, "action"):
            context.log.fail("Module options not properly initialized")
            return

        # Establish a new ldap3 connection
        use_ssl = connection.port == 636
        tls_config = None
        if use_ssl:
            tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        
        try:
            server = Server(connection.host, port=connection.port, use_ssl=use_ssl, tls=tls_config, get_info=ldap3.ALL)
            ldap_conn = Connection(server, user=f"{connection.domain}\\{connection.username}", password=connection.password, authentication=NTLM, auto_bind=True)
        except Exception as e:
            context.log.fail(f"Failed to establish LDAP connection: {e}")
            return

        # Get domain information
        domainroot = ldap_conn.server.info.other["defaultNamingContext"][0]
        forestroot = ldap_conn.server.info.other["rootDomainNamingContext"][0]
        
        # Determine DNS root based on options
        if self.dns_options == "forest":
            dnsroot = f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}"
        elif self.dns_options == "legacy":
            dnsroot = f"CN=MicrosoftDNS,CN=System,{domainroot}"
        else:
            dnsroot = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}"

        # Handle list operations
        if self.action in ["list", "list-dn"]:
            attr = "distinguishedName" if self.action == "list-dn" else "dc"
            
            zones = self.get_dns_zones(ldap_conn, dnsroot, attr)
            if len(zones) > 0:
                context.log.success(f"Found {len(zones)} domain DNS zones:")
                for zone in zones:
                    context.log.highlight(f"    {zone}")
            
            if self.dns_options != "legacy":
                forestdns = f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}"
                zones = self.get_dns_zones(ldap_conn, forestdns, attr)
                if len(zones) > 0:
                    context.log.success(f"Found {len(zones)} forest DNS zones:")
                    for zone in zones:
                        context.log.highlight(f"    {zone}")
            
            if self.show_usage:
                self.print_usage(context)

            ldap_conn.unbind()
            return

        # Validate record parameter for record operations
        if not self.record:
            context.log.fail("You need to specify a RECORD parameter")
            ldap_conn.unbind()
            return

        # Determine zone
        zone = self.zone if self.zone else self.ldap2domain(domainroot)

        # Clean target record
        target = self.record
        if target.lower().endswith(zone.lower()):
            target = target[:-(len(zone) + 1)]

        searchtarget = f"DC={zone},{dnsroot}"
        
        # Search for existing record
        try:
            ldap_conn.search(
                search_base=searchtarget, 
                search_filter=f"(&(objectClass=dnsNode)(name={ldap3.utils.conv.escape_filter_chars(target)}))", 
                attributes=["dnsRecord", "dNSTombstoned", "name"]
            )
        except Exception as e:
            context.log.fail(f"Failed to search for DNS record: {e}")
            ldap_conn.unbind()
            return

        targetentry = None
        for entry in ldap_conn.response:
            if entry["type"] != "searchResEntry":
                continue
            targetentry = entry

        # Check if record exists when required
        if self.action in ["modify", "remove", "ldapdelete", "resurrect", "query"] and not targetentry:
            context.log.fail("Target record not found!")
            ldap_conn.unbind()
            return

        # Execute action
        if self.action == "query":
            context.log.success(f'Found record {targetentry["attributes"]["name"]}')
            context.log.display(targetentry["dn"])
            for record in targetentry["raw_attributes"]["dnsRecord"]:
                dr = DNS_RECORD(record)
                self.print_record(context, dr, targetentry["attributes"]["dNSTombstoned"])

        elif self.action == "add":
            addtype = 1  # A record
            if targetentry:
                if not self.allow_multiple:
                    for record in targetentry["raw_attributes"]["dnsRecord"]:
                        dr = DNS_RECORD(record)
                        if dr["Type"] == 1:
                            address = DNS_RPC_RECORD_A(dr["Data"])
                            context.log.fail(f"Record already exists and points to {address.formatCanonical()}. Use ACTION=modify to overwrite or ALLOWMULTIPLE=true to override this")
                            ldap_conn.unbind()
                            return

                # Add extra record
                record = self.new_record(addtype, self.get_next_serial(connection.host, zone))
                record["Data"] = DNS_RPC_RECORD_A()
                record["Data"].fromCanonical(self.data)
                context.log.display("Adding extra record")
                ldap_conn.modify(targetentry["dn"], {"dnsRecord": [(MODIFY_ADD, record.getData())]})
                if ldap_conn.result["result"] == 0:
                    context.log.success("LDAP operation completed successfully")
                else:
                    context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')
            else:
                # Create new record
                node_data = {
                    "objectCategory": f'CN=Dns-Node,{ldap_conn.server.info.other["schemaNamingContext"][0]}',
                    "dNSTombstoned": False,
                    "name": target
                }
                record = self.new_record(addtype, self.get_next_serial(connection.host, zone))
                record["Data"] = DNS_RPC_RECORD_A()
                record["Data"].fromCanonical(self.data)
                record_dn = f"DC={target},{searchtarget}"
                node_data["dnsRecord"] = [record.getData()]
                context.log.display("Adding new record")
                ldap_conn.add(record_dn, ["top", "dnsNode"], node_data)
                if ldap_conn.result["result"] == 0:
                    context.log.success("LDAP operation completed successfully")
                else:
                    context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')

        elif self.action == "modify":
            addtype = 1  # A record
            targetrecord = None
            records = []
            for record in targetentry["raw_attributes"]["dnsRecord"]:
                dr = DNS_RECORD(record)
                if dr["Type"] == 1:
                    targetrecord = dr
                else:
                    records.append(record)
            
            if not targetrecord:
                context.log.fail("No A record exists yet. Use ACTION=add to add it")
                ldap_conn.unbind()
                return
            
            targetrecord["Serial"] = self.get_next_serial(connection.host, zone)
            targetrecord["Data"] = DNS_RPC_RECORD_A()
            targetrecord["Data"].fromCanonical(self.data)
            records.append(targetrecord.getData())
            context.log.display("Modifying record")
            ldap_conn.modify(targetentry["dn"], {"dnsRecord": [(MODIFY_REPLACE, records)]})
            if ldap_conn.result["result"] == 0:
                context.log.success("LDAP operation completed successfully")
            else:
                context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')

        elif self.action == "remove":
            if len(targetentry["raw_attributes"]["dnsRecord"]) > 1:
                context.log.display("Target has multiple records, removing the one specified")
                targetrecord = None
                for record in targetentry["raw_attributes"]["dnsRecord"]:
                    dr = DNS_RECORD(record)
                    if dr["Type"] == 1:
                        tr = DNS_RPC_RECORD_A(dr["Data"])
                        if tr.formatCanonical() == self.data:
                            targetrecord = record
                            break
                
                if not targetrecord:
                    context.log.fail("Could not find a record with the specified data")
                    ldap_conn.unbind()
                    return
                
                ldap_conn.modify(targetentry["dn"], {"dnsRecord": [(MODIFY_DELETE, targetrecord)]})
                if ldap_conn.result["result"] == 0:
                    context.log.success("LDAP operation completed successfully")
                else:
                    context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')
            else:
                context.log.display("Target has only one record, tombstoning it")
                diff = datetime.datetime.today() - datetime.datetime(1601, 1, 1)
                tstime = int(diff.total_seconds() * 10000)
                record = self.new_record(0, self.get_next_serial(connection.host, zone))
                record["Data"] = DNS_RPC_RECORD_TS()
                record["Data"]["entombedTime"] = tstime
                ldap_conn.modify(targetentry["dn"], {
                    "dnsRecord": [(MODIFY_REPLACE, [record.getData()])],
                    "dNSTombstoned": [(MODIFY_REPLACE, True)]
                })
                if ldap_conn.result["result"] == 0:
                    context.log.success("LDAP operation completed successfully")
                else:
                    context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')

        elif self.action == "ldapdelete":
            context.log.display("Deleting record over LDAP")
            ldap_conn.delete(targetentry["dn"])
            if ldap_conn.result["result"] == 0:
                context.log.success("LDAP operation completed successfully")
            else:
                context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')

        elif self.action == "resurrect":
            if len(targetentry["raw_attributes"]["dnsRecord"]) > 1:
                context.log.fail("Target has multiple records, I dont know how to handle this.")
                ldap_conn.unbind()
                return
            else:
                context.log.display("Target has only one record, resurrecting it")
                diff = datetime.datetime.today() - datetime.datetime(1601, 1, 1)
                tstime = int(diff.total_seconds() * 10000)
                record = self.new_record(0, self.get_next_serial(connection.host, zone))
                record["Data"] = DNS_RPC_RECORD_TS()
                record["Data"]["entombedTime"] = tstime
                ldap_conn.modify(targetentry["dn"], {
                    "dnsRecord": [(MODIFY_REPLACE, [record.getData()])],
                    "dNSTombstoned": [(MODIFY_REPLACE, False)]
                })
                if ldap_conn.result["result"] == 0:
                    context.log.success("Record resurrected. You will need to (re)add the record with the IP address.")
                else:
                    context.log.fail(f'LDAP operation failed: {ldap_conn.result["description"]} {ldap_conn.result.get("message", "")}')
        
        # Close the connection
        ldap_conn.unbind() 
