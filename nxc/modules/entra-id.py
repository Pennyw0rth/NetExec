
import re

from termcolor import colored
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.config import host_info_colors


class NXCModule:
    """Module by @NeffIsBack"""

    name = "entra-id"
    description = "Find the Entra ID sync server"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options available."""

    def on_login(self, context, connection):
        self.context = context

        # For every Entra ID syncronization server, there is a corresponding MSOL_ account and likely an ADSyncMSA service account.
        msol_parsed = parse_result_attributes(connection.search(
            searchFilter="(sAMAccountName=MSOL_*)",
            attributes=["sAMAccountName", "cn", "description"],
        ))
        self.context.log.info(f"Found the following MSOL accounts: {msol_parsed}")
        adsync_parsed = parse_result_attributes(connection.search(
            searchFilter="(sAMAccountName=ADSyncMSA*)",
            attributes=["sAMAccountName", "cn", "msDS-HostServiceAccountBL"],
        ))
        self.context.log.info(f"Found the following ADSyncMSA accounts: {adsync_parsed}")

        hosts = []
        for acc in msol_parsed:
            host = re.search(r"computer (?P<host>.*) configured", acc["description"])
            if host:
                hostname = host.group("host")
                # Try to get the dNSHostName for the host, if not use the NetBIOS name from the description
                resp = parse_result_attributes(connection.search(f"(sAMAccountName={hostname}$)", ["dNSHostName"]))
                ip = connection.resolver(resp[0]["dNSHostName"] if resp else hostname)

                hosts.append({
                    "hostname": hostname,
                    "ip": ip,
                    "msol_account": acc["sAMAccountName"],
                })

        for adsync in adsync_parsed:
            # The last 5 chars of the ADSyncMSA account name are the identifier for the corresponding MSOL account
            identifier = str(adsync["cn"]).removeprefix("ADSyncMSA")
            msol_acc = next((x for x in msol_parsed if str(x["sAMAccountName"]).startswith(f"MSOL_{identifier}")), None)
            self.context.log.debug(f"Found ADSyncMSA account: {adsync['sAMAccountName']}, corresponding MSOL account: {msol_acc['sAMAccountName'] if msol_acc else 'None'}")

            # Get the computer object for the ADSyncMSA service account
            computer = parse_result_attributes(connection.search(
                searchFilter=f"(distinguishedName={adsync['msDS-HostServiceAccountBL']})",
                attributes=["dNSHostName", "cn", "sAMAccountName"],
            ))[0]

            # If we already found a host with its MSOL account, extend that info, otherwise create a new host entry
            host = next((x for x in hosts if x["hostname"] == computer["cn"]), None)
            if host and host["ip"]:   # Skip if host and IP are already set
                self.context.log.debug(f"Host '{host['hostname']}' already exists with IP {host['ip'].get('host')}, skipping update.")
                continue
            elif host:                # If host exists but IP is not set, update it
                host["ip"] = connection.resolver(computer["dNSHostName"])
            else:                     # If host does not exist, create a new entry
                hosts.append({
                    "hostname": computer["cn"],
                    "ip": connection.resolver(computer["dNSHostName"]),
                })

        if hosts:
            self.context.log.success("Found Entra ID sync servers:")
        for host in hosts:
            self.context.log.highlight(f"{host['hostname']}: {colored(host['ip'].get('host', '<not found>'), host_info_colors[0])}" + colored(f" (MSOL Account: {host.get('msol_account', 'N/A')})", "yellow", attrs=["bold"]))
