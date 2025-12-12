# Module by @MaxToffy
from impacket.structure import Structure
from nxc.helpers.misc import CATEGORY


# [MS-DNSP] - 2.3.2.1 - dnsProperty
class DNS_PROPERTY(Structure):
    structure = (
        ("DataLength", "<L-Data"),
        ("NameLength", "<L"),
        ("Flag", "<L"),
        ("Version", "<L"),
        ("Id", "<L"),
        ("Data", ":"),
        ("Name", "1s"),
    )


# [MS-DNSP] - 2.3.2.1.1 - Property Id
DSPROPERTY_ZONE_ALLOW_UPDATE = 0x02


class NXCModule:
    name = "dns-nonsecure"
    description = "Detects DNS zones that allow nonsecure dynamic updates"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):

        base_dn = connection.baseDN
        forest_root_dn = ",".join(f"DC={part}" for part in connection.domain.split(".")[-2:])
        search_bases = {
            "domain": f"CN=MicrosoftDNS,DC=DomainDnsZones,{base_dn}",
            "forest": f"CN=MicrosoftDNS,DC=ForestDnsZones,{forest_root_dn}"
        }

        for dns_type, search_base in search_bases.items():
            # Search for domain DNS zones
            list_zones = connection.search(
                searchFilter="(objectClass=dnsZone)",
                attributes=["name", "dNSProperty"],
                baseDN=search_base,
            )

            # Get dNSProperty for each zones
            zones_props = {}
            for entry in list_zones:
                for attribute in entry["attributes"]:
                    if str(attribute["type"]) == "name":
                        name = str(attribute["vals"].components[0]).encode("utf-8").decode("utf-8")
                    else:
                        dns_attribute = [val.__bytes__() for val in attribute["vals"].components]
                zones_props[name] = dns_attribute

            # Get dynamic updates configuration for each zones
            found = False
            for zone, dns_props in zones_props.items():
                for prop in dns_props:
                    parsed_prop = DNS_PROPERTY(prop)

                    if parsed_prop["Id"] == DSPROPERTY_ZONE_ALLOW_UPDATE:
                        value = int.from_bytes(parsed_prop["Data"])
                        context.log.debug(f"Dynamic update set to {value!s} for '{zone}'")

                        # [MS-DNSP] 2.2.5.2.4.1 - DNS_RPC_ZONE_INFO_W2K - fAllowUpdate
                        if value == 1:
                            if not found:
                                context.log.success(f"{dns_type.capitalize()} DNS zone(s) allowing nonsecure dynamic updates")
                                found = True
                            context.log.highlight(zone)
            if not found:
                context.log.fail(f"No {dns_type} DNS zone allowing insecure dynamic updates")
