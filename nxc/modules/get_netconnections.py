from datetime import datetime
from nxc.helpers.logger import write_log
import json


class NXCModule:
    """
    Uses WMI to extract network connections, used to find multi-homed hosts.
    Module by @fang0654

    """

    name = "get_netconnections"
    description = "Uses WMI to query network connections."
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No options"""

    def on_admin_login(self, context, connection):
        data = []
        cards = connection.wmi("select DNSDomainSuffixSearchOrder, IPAddress from win32_networkadapterconfiguration")
        if cards:
            for c in cards:
                if c["IPAddress"].get("value"):
                    context.log.success(f"IP Address: {c['IPAddress']['value']}\tSearch Domain: {c['DNSDomainSuffixSearchOrder']['value']}")

            data.append(cards)

        log_name = f"network-connections-{connection.host}-{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"
        write_log(json.dumps(data), log_name)
        context.log.display(f"Saved raw output to ~/.nxc/logs/{log_name}")
