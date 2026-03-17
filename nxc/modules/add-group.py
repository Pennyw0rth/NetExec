import sys
from impacket.ldap import ldap, ldapasn1
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for adding/removing users to/from groups
    Module by @termanix
    """

    name = "add-group"
    description = "Add or remove users from groups"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Required (at least one of):
        GROUP       Name of the group to add/remove the user to/from
        OU          TO DO --> Distinguished name of the OU to move the user to

        Required:
        USER        Username of the account to modify

        Optional:
        REMOVE      Set to 'True' to remove the user from the specified group instead of adding (default: False)

        Examples
        --------
        Adding a user to a group:
            netexec smb <DC_IP> -u adminuser -p password -M add-group -o USER='targetuser' GROUP='Domain Admins'
            netexec ldap <DC_IP> -u adminuser -p password -M add-group -o USER='targetuser' GROUP='Enterprise Admins'

        Removing a user from a group:
            netexec smb <DC_IP> -u adminuser -p password -M add-group -o USER='targetuser' GROUP='Domain Admins' REMOVE=True
            netexec ldap <DC_IP> -u adminuser -p password -M add-group -o USER='targetuser' GROUP='Enterprise Admins' REMOVE=True

        For Using SMB, Need to Know
        SMB/SAMR KNOWN LIMITATIONS:
            - SAMR only supports modification of Global security groups.
            Domain Local and Universal groups require the LDAP protocol.
            - Cross-domain groups (e.g. Enterprise Admins) cannot be modified via SAMR.
            Use LDAP instead.
            - The authenticating user must have sufficient SAMR privileges
            (e.g. Account Operators, Domain Admins).

        """
        self.context = context
        self.group = module_options.get("GROUP")
        self.ou = module_options.get("OU")
        self.target_user = module_options.get("USER")
        self.remove = module_options.get("REMOVE", "False").lower() == "true"

        if not (self.target_user and self.group):
            context.log.fail("USER and GROUP parameter is required!")
            sys.exit(1)

        """
        To do
        if not self.group and not self.ou:
            context.log.fail("Either GROUP or OU parameter is required!")
            sys.exit(1)"""

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
            context.log.fail(f"Failed to add user to group via SMB: {e}")
            context.log.info("If the group is domain-local or universal, try with LDAP instead.")
        finally:
            if "dce" in locals():
                dce.disconnect()

    def _remove_user_from_group_smb(self, context, connection):
        """Remove user from group using SMB/SAMR protocol"""
        try:
            context.log.info("Started removing user from group via SMB")
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
            context.log.fail(f"Failed to remove user from group via SMB: {e}")
            context.log.info("If the group is domain-local or universal, try with LDAP instead.")
        finally:
            if "dce" in locals():
                dce.disconnect()

    def _add_user_to_group_ldap(self, context, connection):
        """Add user to group using LDAP protocol"""
        try:
            context.log.info("Started adding user to group via LDAP")
            ldap_conn = self._get_ldap_connection(connection)

            # Search for the target user
            target_user_dn = self._find_object_dn(ldap_conn, connection.domain, "sAMAccountName", self.target_user)
            if not target_user_dn:
                context.log.fail(f"User {self.target_user} not found")
                return

            # Search for the target group
            group_dn = self._find_object_dn(ldap_conn, connection.domain, "sAMAccountName", self.group)
            if not group_dn:
                context.log.fail(f"Group {self.group} not found")
                return

            context.log.info("Checking if the target user is already in target group.")
            # Check if user is already in target group
            if self._is_user_in_group(context, connection, target_user_dn, group_dn):
                context.log.display(f"User {self.target_user} is already a member of group {self.group}")
                return

            # Create LDAP connection
            context.log.info("Creating LDAPS connection for modify.")
            ldaps_conn = self._get_ldaps_connection(connection)
            context.log.info("LDAPS connection established.")

            # Add user to group by modifying the group's "member" attribute
            self._modify_group_member(ldaps_conn, group_dn, target_user_dn, operation="add")
            context.log.success(f"Successfully added {self.target_user} to group {self.group}")

        except Exception as e:
            context.log.fail(f"Failed to add user to group via LDAP: {e}")

    def _remove_user_from_group_ldap(self, context, connection):
        """Remove user from group using LDAP protocol"""
        try:
            context.log.info("Started removing user from group via LDAP")
            ldap_conn = self._get_ldap_connection(connection)

            # Search for the target user
            target_user_dn = self._find_object_dn(ldap_conn, connection.domain, "sAMAccountName", self.target_user)
            if not target_user_dn:
                context.log.fail(f"User {self.target_user} not found")
                return

            # Search for the target group
            group_dn = self._find_object_dn(ldap_conn, connection.domain, "sAMAccountName", self.group)
            if not group_dn:
                context.log.fail(f"Group {self.group} not found")
                return

            context.log.info("Checking if the target user is in target group.")
            # Check if user is already in target group
            if not self._is_user_in_group(context, connection, target_user_dn, group_dn):
                context.log.display(f"User {self.target_user} is not a member of group {self.group}")
                return

            # Create LDAP connection
            context.log.info("Creating LDAPS connection for modify.")
            ldaps_conn = self._get_ldaps_connection(connection)
            context.log.info("LDAPS connection established.")

            # Remove user from group by modifying the group's "member" attribute
            self._modify_group_member(ldaps_conn, group_dn, target_user_dn, operation="delete")
            context.log.success(f"Successfully removed {self.target_user} from group {self.group}")

        except Exception as e:
            context.log.fail(f"Failed to remove user from group via LDAP: {e}")

    def _modify_group_member(self, ldaps_conn, group_dn, target_user_dn, operation):
        """
        Modify group membership by building a raw ldapasn1.ModifyRequest
        and sending it via LDAPConnection.sendReceive().

        operation: "add" to add a member, "delete" to remove a member.

        Note: pyasn1 auto-populates the nested Change structure when you
        index into request["changes"][n] — no separate Change class needed.
        Operation takes the string name ("add", "delete", "replace").
        """
        request = ldapasn1.ModifyRequest()
        request["object"] = group_dn
        request["changes"][0]["operation"] = ldapasn1.Operation(operation)
        request["changes"][0]["modification"]["type"] = "member"
        request["changes"][0]["modification"]["vals"][0] = target_user_dn

        # Send over the already-authenticated LDAPS connection
        resp = ldaps_conn.sendReceive(request)

        # Check every returned message for a non-success result code
        for message in resp:
            component = message["protocolOp"].getComponent()
            result_code = int(component["resultCode"])
            if result_code != 0:
                diagnostic = str(component.get("diagnosticMessage", ""))
                raise Exception(f"LDAP modify failed (resultCode={result_code}): {diagnostic}")

    def _is_user_in_group(self, context, connection, target_user_dn, group_dn):
        """Check if the given user DN is already a member of the target group DN."""
        try:
            search_filter = f"(cn={self.group})"
            attributes = ["member"]
            # LDAP connection
            resp = connection.ldap_connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
            resp_parsed = parse_result_attributes(resp)

            for dn in resp_parsed:
                if target_user_dn in dn["member"]:
                    return target_user_dn

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

    def _get_ldaps_connection(self, connection):
        """Create and return an authenticated LDAPS connection (SSL, for writes)"""
        ldaps_server = f"ldaps://{connection.host}"

        ldaps_connection = ldap.LDAPConnection(ldaps_server, connection.domain)
        ldaps_connection.login(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash
        )
        return ldaps_connection

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
