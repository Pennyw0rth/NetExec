
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
        self.connection = None
        self.module_options = None

    def options(self, context, module_options):
        """No options available."""

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        self.check_aadconnect()
        self.check_desktopsso()
        self.check_cloudsync()
        self.check_adfs()

    def check_aadconnect(self):
        # For every Entra ID syncronization server, there is a corresponding MSOL_ account and likely an ADSyncMSA service account.
        msol_parsed = parse_result_attributes(self.connection.search(
            searchFilter="(sAMAccountName=MSOL_*)",
            attributes=["sAMAccountName", "cn", "description"],
        ))
        self.context.log.info(f"Found the following MSOL accounts: {msol_parsed}")
        adsync_parsed = parse_result_attributes(self.connection.search(
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
                resp = parse_result_attributes(self.connection.search(f"(sAMAccountName={hostname}$)", ["dNSHostName"]))
                ip = self.connection.resolver(resp[0]["dNSHostName"] if resp else hostname) or {}

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
            computer = parse_result_attributes(self.connection.search(
                searchFilter=f"(distinguishedName={adsync['msDS-HostServiceAccountBL']})",
                attributes=["dNSHostName", "cn", "sAMAccountName"],
            ))[0]

            # If we already found a host with its MSOL account, extend that info, otherwise create a new host entry
            host = next((x for x in hosts if x["hostname"] == computer["cn"]), None)
            if host and host["ip"]:   # Skip if host and IP are already set
                self.context.log.debug(f"Host '{host['hostname']}' already exists with IP {host['ip'].get('host')}, skipping update.")
                continue
            elif host:                # If host exists but IP is not set, update it
                host["ip"] = self.connection.resolver(computer["dNSHostName"])
            else:                     # If host does not exist, create a new entry
                hosts.append({
                    "hostname": computer["cn"],
                    "ip": self.connection.resolver(computer["dNSHostName"]),
                })

        if hosts:
            self.context.log.success("Microsoft Entra Connect/Azure AD Connect:")
        else:
            self.context.log.fail("Microsoft Entra Connect/Azure AD Connect not configured.")
        for host in hosts:
            self.context.log.highlight(f"    Found related sync server {host['hostname']}: {colored(host['ip'].get('host', '<not found>'), host_info_colors[0])}" + colored(f" (MSOL Account: {host.get('msol_account', 'N/A')})", "yellow", attrs=["bold"]))

    def check_desktopsso(self):
        # Searching AZUREADSSOACC$ computer account used for desktop SSO.
        dsso_parsed = parse_result_attributes(self.connection.search(
            searchFilter="(sAMAccountName=AZUREADSSOACC$)",
            attributes=["sAMAccountName"],
        ))
        self.context.log.info(f"Found the following account: {dsso_parsed}")
        if dsso_parsed:
            self.context.log.success("Desktop SSO:")
            self.context.log.highlight("    Found related computer account: AZUREADSSOACC$")
        else:
            self.context.log.fail("Desktop SSO not configured.")

    def check_cloudsync(self):
        # Check for cloud sync GMSA account, by default format is pGMSA_*$ and description is "Azure AD cloud sync service account"
        cloudsync_parsed = parse_result_attributes(self.connection.search(
            searchFilter="(sAMAccountName=pGMSA_*$)",
            attributes=["sAMAccountName", "cn", "description"],
        ))
        self.context.log.info(f"Found the following Cloud Sync GMSA account: {cloudsync_parsed}")
        if cloudsync_parsed and cloudsync_parsed[0].get("description") == "Azure AD cloud sync service account":
            self.context.log.success("Cloud Sync:")
            self.context.log.highlight(f"    Found related GMSA account: {cloudsync_parsed[0].get('sAMAccountName')} - {cloudsync_parsed[0].get('description')}")
        else:
            self.context.log.fail("Cloud Sync not configured.")

    def check_adfs(self):
        # Check for ADFS object
        search_base = "CN=Microsoft,CN=Program Data," + self.connection.baseDN
        adfs_parsed = parse_result_attributes(self.connection.search(
            baseDN=search_base,
            searchFilter="(CN=ADFS)",
            attributes=["cn"],
        ))
        self.context.log.info(f"Found the ADFS object: {adfs_parsed}")

        if adfs_parsed:
            self.context.log.success("Domain federated with Entra ID via ADFS:")
            # As far as I know the is no reliable way to get info about the ADCS via ldap in newer adfs version

            # Searching accounts with adfs in name or description
            adfs1_parsed = parse_result_attributes(self.connection.search(
                searchFilter="(|(sAMAccountName=*adfs*)(description=*adfs*))",
                attributes=["sAMAccountName", "description"],
            ))
            self.context.log.info(f"Found the following adfs related accounts: {adfs1_parsed}")
            # Checking SPN for adfs or sts keyword
            adfs2_parsed = parse_result_attributes(self.connection.search(
                searchFilter="(|(servicePrincipalName=*adfs*)(servicePrincipalName=*STS*))",
                attributes=["sAMAccountName", "servicePrincipalName"],
            ))
            self.context.log.info(f"Found the following adfs related spn: {adfs2_parsed}")

            for account in adfs1_parsed:
                self.context.log.highlight(f"    Found related account: {account.get('sAMAccountName')} - {account.get('description')}")
            for account in adfs2_parsed:
                SPNs = [spn for spn in account.get("servicePrincipalName") if "adfs" in spn.lower() or "sts" in spn.lower()]
                self.context.log.highlight(f"    Found related SPN: {account.get('sAMAccountName')} - {SPNs}")
        else:
            self.context.log.fail("ADFS object not found.")
