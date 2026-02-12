from impacket.structure import Structure
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module by @MaxToffy"""
    name = "dns-nonsecure"
    description = "Detects DNS zones that allow nonsecure dynamic updates"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        search_bases = {
            "domain": f"CN=MicrosoftDNS,DC=DomainDnsZones,{connection.baseDN}",
            "forest": f"CN=MicrosoftDNS,DC=ForestDnsZones,{connection.forestDN}"
        }

        for dns_type, search_base in search_bases.items():
            # Search for domain DNS zones
            resp = connection.search(
                searchFilter="(objectClass=dnsZone)",
                attributes=["name", "dNSProperty"],
                baseDN=search_base,
            )
            zones = parse_result_attributes(resp)

            # Get dynamic updates configuration for each zones
            allows_nonsecure_updates = []
            for zone in zones:
                for prop in zone["dNSProperty"]:
                    dns_properties = DNS_PROPERTY(prop)

                    # [MS-DNSP] 2.2.5.2.4.1 - DNS_RPC_ZONE_INFO_W2K - fAllowUpdate
                    if dns_properties["Id"] == DSPROPERTY_ZONE_ALLOW_UPDATE and int.from_bytes(dns_properties["Data"]) == ZONE_UPDATE_UNSECURE:
                        allows_nonsecure_updates.append(zone["name"])

            if allows_nonsecure_updates:
                context.log.success(f"{dns_type.capitalize()} DNS zone(s) allowing nonsecure dynamic updates")
                for zone in allows_nonsecure_updates:
                    context.log.highlight(zone)
            else:
                context.log.fail(f"No {dns_type} DNS zones allowing nonsecure dynamic updates")


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

# [MS-DNSP] - 2.2.5.2.4.1 - fAllowUpdate values
ZONE_UPDATE_OFF = 0x00000000
ZONE_UPDATE_UNSECURE = 0x00000001
ZONE_UPDATE_SECURE = 0x00000002
