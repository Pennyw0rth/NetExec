import sys
from impacket.ldap import ldap
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from nxc.parsers.ldap_results import parse_result_attributes
from ldap3 import Server, Connection, ALL, MODIFY_ADD, SIMPLE, MODIFY_DELETE

class NXCModule:
    """
    Module for adding/removing users to/from groups and/or moving users to different OUs
    Module inspired by the change-password module
    """

    name = "add-group"
    description = "Add or remove users from groups or move them to different OUs"
    supported_protocols = ["smb", "ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Required (at least one of):
        GROUP       Name of the group to add/remove the user to/from
        OU          Distinguished name of the OU to move the user to

        Required:
        USER        Username of the account to modify

        Optional:
        REMOVE      Set to 'True' to remove the user from the specified group instead of adding (default: False)

        Examples
        --------
        Adding a user to a group:
            netexec smb <DC_IP> -u adminuser -p password -M manage-user -o USER='targetuser' GROUP='Domain Admins'
            netexec ldap <DC_IP> -u adminuser -p password -M manage-user -o USER='targetuser' GROUP='Enterprise Admins'

        Removing a user from a group:
            netexec smb <DC_IP> -u adminuser -p password -M manage-user -o USER='targetuser' GROUP='Domain Admins' REMOVE=True
            netexec ldap <DC_IP> -u adminuser -p password -M manage-user -o USER='targetuser' GROUP='Enterprise Admins' REMOVE=True
        """
        self.context = context
        self.group = module_options.get("GROUP")
        self.ou = module_options.get("OU")
        self.target_user = module_options.get("USER")
        self.remove = module_options.get("REMOVE", "False").lower() == "true"

        if not self.target_user:
            context.log.fail("USER parameter is required!")
            sys.exit(1)

        if not self.group and not self.ou:
            context.log.fail("Either GROUP or OU parameter is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        if context.protocol == "smb":
            if self.group:
                if self.remove:
                    self._remove_user_from_group_smb(context, connection)
                else:
                    self._add_user_to_group_smb(context, connection)
            if self.ou:
                context.log.fail("OU operations are only supported with LDAP protocol")
        elif context.protocol == "ldap":
            if self.group:
                if self.remove:
                    self._remove_user_from_group_ldap(context, connection)
                else:
                    self._add_user_to_group_ldap(context, connection)
            if self.ou:
                self._move_user_to_ou_ldap(context, connection)
    
    def _authenticate_dce(self, context, connection, protocol="ncacn_np", interface=samr.MSRPC_UUID_SAMR):
        """Authenticate to the target using DCE/RPC"""
        try:
            # Map to the endpoint on the target
            string_binding = epm.hept_map(connection.host, interface, protocol=protocol)
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(connection.host)
            
            rpctransport.set_credentials(
                connection.username,
                connection.password,
                connection.domain,
                connection.lmhash,
                connection.nthash,
                aesKey=connection.aesKey,
            )
            context.log.info(f"Connecting as {connection.domain}\\{connection.username}")

            # Connect to the DCE/RPC endpoint and bind to the service
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            context.log.info("[+] Successfully connected to DCE/RPC")
            dce.bind(interface)
            context.log.info(f"[+] Successfully bound to {interface}")
            return dce
        except DCERPCException as e:
            context.log.fail(f"DCE/RPC Exception: {e!s}")
            raise

    def _add_user_to_group_smb(self, context, connection):
        """Add user to group using SMB/SAMR protocol"""
        try:
            context.log.info("Started adding user to group via SMB")
            # Connect to SAMR service
            dce = self._authenticate_dce(context, connection)
            
            # Open server connection
            server_handle = samr.hSamrConnect(dce, connection.host + "\x00")["ServerHandle"]
            
            # Get domain SID and open domain
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, connection.domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
            
            # Find the user and group RIDs
            try:
                user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.target_user,))["RelativeIds"]["Element"][0]
            except Exception as e:
                context.log.fail(f"User {self.target_user} not found in domain {connection.domain}")
                context.log.debug(f"Fail user rid smb: {e}")
                return
                
            try:
                group_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.group,))["RelativeIds"]["Element"][0]
            except Exception as e:
                context.log.fail(f"Group {self.group} not found in domain {connection.domain}")
                context.log.debug(f"Fail group rid smb: {e}")
                return
            
            # Open the group
            group_handle = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)["GroupHandle"]
            
            # Add member to the group
            samr.hSamrAddMemberToGroup(dce, group_handle, user_rid, 0x7)
            
            context.log.success(f"Successfully added {self.target_user} to group {self.group}")
            
        except Exception as e:
            if connection:
                context.log.fail("Failed to add user to group via SMB. Please try it with LDAP.")
            else:
                context.log.fail(f"Failed to add user to group via SMB: {e}")
        finally:
            if "dce" in locals():
                dce.disconnect()

    def _remove_user_from_group_smb(self, context, connection):
        """Remove user from group using SMB/SAMR protocol"""
        try:
            context.log.info("Started removing user to group via SMB")
            # Connect to SAMR service
            dce = self._authenticate_dce(context, connection)
            
            # Open server connection
            server_handle = samr.hSamrConnect(dce, connection.host + "\x00")["ServerHandle"]
            
            # Get domain SID and open domain
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, connection.domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
            
            # Find the user and group RIDs
            try:
                user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.target_user,))["RelativeIds"]["Element"][0]
            except Exception as e:
                context.log.fail(f"User {self.target_user} not found in domain {connection.domain}")
                context.log.debug(f"Fail user rid smb: {e}")
                return
                
            try:
                group_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.group,))["RelativeIds"]["Element"][0]
            except Exception as e:
                context.log.fail(f"Group {self.group} not found in domain {connection.domain}")
                context.log.debug(f"Fail group rid smb: {e}")
                return
            
            # Open the group
            group_handle = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)["GroupHandle"]
            
            # Remove member from the group
            samr.hSamrRemoveMemberFromGroup(dce, group_handle, user_rid)
            
            context.log.success(f"Successfully removed {self.target_user} from group {self.group}")
            
        except Exception as e:
            if connection:
                context.log.fail("Failed to remove user to group via SMB. Please try it with LDAP.")
            else:
                context.log.fail(f"Failed to add user to group via SMB: {e}")
        finally:
            if "dce" in locals():
                dce.disconnect()


    def _add_user_to_group_ldap(self, context, connection):
        """Add user to group using LDAP protocol"""
        try:
            context.log.info("Started adding user to group via LDAP")
            # Search for the target user
            user_dn = self._find_object_dn(self._get_ldap_connection(connection), connection.domain, "sAMAccountName", self.target_user)
            if not user_dn:
                context.log.fail(f"User {self.target_user} not found")
                return

            # Search for the target group
            group_dn = self._find_object_dn(self._get_ldap_connection(connection), connection.domain, "sAMAccountName", self.group)
            if not group_dn:
                context.log.fail(f"Group {self.group} not found")
                return

            context.log.info("Checking for if the target user is in target group.")
            # Check if user is already in target group
            if self._is_user_in_group(context, connection, user_dn, group_dn):
                context.log.display(f"User {self.target_user} is already a member of group {self.group}")
                return

            context.log.info("Creating LDAP3 connection for add.")           
            # Create LDAP connection using ldap3
            server = Server(connection.host, use_ssl=True, get_info=ALL)  # Need SSL auth for StrongAuth connection
            conn = Connection(server, user=user_dn, password=connection.password, authentication=SIMPLE, auto_bind=True)
            context.log.info("LDAP3 connection established.") 
 
            # Add user to group by modifying the group's "member" attribute
            success = conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
            if success:
                context.log.success(f"Successfully added {self.target_user} to group {self.group}")
            else:
                context.log.debug(f"LDAP modify failed: {conn.result['description']} - {conn.result.get('message', '')}")
                context.log.fail("LDAP modify failed")

            conn.unbind()
        except Exception as e:
            context.log.fail(f"Failed to add user to group via LDAP: {e}")

    def _remove_user_from_group_ldap(self, context, connection):
        """Remove user from group using LDAP protocol"""
        try:
            context.log.info("Started removing user to group via LDAP")
            # Search for the target user
            user_dn = self._find_object_dn(self._get_ldap_connection(connection), connection.domain, "sAMAccountName", self.target_user)
            if not user_dn:
                context.log.fail(f"User {self.target_user} not found")
                return

            # Search for the target group
            group_dn = self._find_object_dn(self._get_ldap_connection(connection), connection.domain, "sAMAccountName", self.group)
            if not group_dn:
                context.log.fail(f"Group {self.group} not found")
                return
            
            context.log.info("Checking for if the target user is not in target group.")
            # Check if user is already in target group
            if not self._is_user_in_group(context, connection, user_dn, group_dn):
                context.log.display(f"User {self.target_user} is not already a member of group {self.group}")
                return

            context.log.info("Creating LDAP3 connection for remove.")           
            # Create LDAP connection using ldap3
            server = Server(connection.host, use_ssl=True, get_info=ALL)  # Need SSL auth for StrongAuth connection
            conn = Connection(server, user=user_dn, password=connection.password, authentication=SIMPLE, auto_bind=True)
            context.log.info("LDAP3 connection established.") 

            # Remove user from group by modifying the group's "member" attribute
            success = conn.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
            if success:
                context.log.success(f"Successfully removed {self.target_user} from group {self.group}")
            else:
                context.log.debug(f"LDAP modify failed: {conn.result['description']} - {conn.result.get('message', '')}")
                context.log.fail("LDAP modify failed")

            conn.unbind()
        except Exception as e:
            context.log.fail(f"Failed to remove user from group via LDAP: {e}")
    
    def _is_user_in_group(self, context, connection, user_dn, group_dn):
        """Check if the given user DN is already a member of the target group DN."""
        try:
            search_filter = f"(cn={self.group})"
            attributes = ["member"]
            # LDAP connection
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            resp_parsed = parse_result_attributes(resp)

            for dn in resp_parsed:
                if user_dn in dn["member"]:
                    return user_dn

        except Exception as e:
            context.log.debug(f"Error checking group membership: {e}")
            return False
    
    def _get_ldap_connection(self, connection):
        """Create and return an authenticated LDAP connection"""
        ldap_server = f"ldap://{connection.host}"
        
        ldap_connection = ldap.LDAPConnection(ldap_server, connection.domain)
        ldap_connection.login(
            connection.username, 
            connection.password, 
            connection.domain, 
            connection.lmhash, 
            connection.nthash
        )
        return ldap_connection

    def _find_object_dn(self, ldap_connection, domain, attribute, value):
        """Find the distinguished name (DN) of an object by attribute"""
        domain_parts = domain.split(".")
        base_dn = ",".join([f"DC={part}" for part in domain_parts])
        search_filter = f"({attribute}={value})"
        
        try:
            resp = ldap_connection.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["distinguishedName"]
            )
            resp_parsed = parse_result_attributes(resp)
            return resp_parsed[0]["distinguishedName"]
        except ldap.LDAPSearchError as e:
            self.context.log.fail(f"LDAP search error: {e}")
            return None
