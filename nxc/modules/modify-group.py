import sys
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for adding/removing users to/from groups
    Module by @termanix
    """

    name = "modify-group"
    description = "Modify the group membership of users and computers"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        """
        Required (at least one of):
        GROUP       Name of the group to add/remove the user to/from
        USER        Username of the account to modify

        Optional:
        REMOVE      Set to 'True' to remove the user from the specified group instead of adding (default: False)

        Examples
        --------
        Adding a user to a group:
            netexec smb <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Domain Admins'
            netexec ldap <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Enterprise Admins'

        Removing a user from a group:
            netexec smb <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Domain Admins' REMOVE=True
            netexec ldap <DC_IP> -u adminuser -p password -M modify-group -o USER='targetuser' GROUP='Enterprise Admins' REMOVE=True

        For Using SMB, Need to Know
        SMB/SAMR KNOWN LIMITATIONS:
            - SAMR only supports modification of Global security groups.
            Domain Local and Universal groups require the LDAP protocol.
            - Cross-domain groups (e.g. Enterprise Admins) cannot be modified via SAMR.
            Use LDAP instead.
            - The authenticating user must have sufficient SAMR privileges
            (e.g. Account Operators, Domain Admins).

        """
        self.group = module_options.get("GROUP")
        self.target_user = module_options.get("USER")
        self.remove = module_options.get("REMOVE", "False").lower() == "true"

        if not (self.target_user and self.group):
            self.context.log.fail("USER and GROUP parameters are required!")
            sys.exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        if context.protocol == "smb":
            if self.group:
                if self.remove:
                    self._remove_user_from_group_smb()
                else:
                    self._add_user_to_group_smb()
        elif context.protocol == "ldap" and self.group:
            if self.remove:
                self._remove_user_from_group_ldap()
            else:
                self._add_user_to_group_ldap()

    def _authenticate_dce(self, protocol="ncacn_np", interface=samr.MSRPC_UUID_SAMR):
        """Authenticate to the target using DCE/RPC"""
        try:
            # Map to the endpoint on the target
            string_binding = epm.hept_map(self.connection.host, interface, protocol=protocol)
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(self.connection.host)
            rpctransport.set_credentials(
                self.connection.username,
                self.connection.password,
                self.connection.domain,
                self.connection.lmhash,
                self.connection.nthash,
                aesKey=self.connection.aesKey,
            )
            self.context.log.info(f"Connecting as {self.connection.domain}\\{self.connection.username}")

            # Connect to the DCE/RPC endpoint and bind to the service
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            self.context.log.info("[+] Successfully connected to DCE/RPC")
            dce.bind(interface)
            self.context.log.info(f"[+] Successfully bound to {interface}")
            return dce
        except DCERPCException as e:
            self.context.log.fail(f"DCE/RPC Exception: {e!s}")
            raise

    def _add_user_to_group_smb(self):
        """Add user to group using SMB/SAMR protocol"""
        try:
            self.context.log.info("Started adding user to group via SMB")
            # Connect to SAMR service
            dce = self._authenticate_dce()

            # Open server connection
            server_handle = samr.hSamrConnect(dce, self.connection.host + "\x00")["ServerHandle"]

            # Get domain SID and open domain
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.connection.domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]

            # Find the user and group RIDs
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.target_user,))["RelativeIds"]["Element"][0]
            group_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.group,))["RelativeIds"]["Element"][0]

            # Open the group
            group_handle = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)["GroupHandle"]

            # Add member to the group
            samr.hSamrAddMemberToGroup(dce, group_handle, user_rid, 0x7)
            self.context.log.success(f"Successfully added {self.target_user} to group {self.group}")

        except Exception as e:
            if "STATUS_MEMBER_IN_GROUP" in str(e):
                self.context.log.display(f"User {self.target_user} is already a member of group {self.group}")
            elif "STATUS_ACCESS_DENIED" in str(e):
                self.context.log.fail(f"Failed to add user to group via SMB. Try with LDAP: {e}")
            elif "STATUS_NONE_MAPPED" in str(e):
                self.context.log.fail(f"Target user or group not found: {self.target_user} / {self.group}")
            else:
                self.context.log.fail(f"Failed to add user to group via SMB: {e}")
        finally:
            if "dce" in locals():
                dce.disconnect()

    def _remove_user_from_group_smb(self):
        """Remove user from group using SMB/SAMR protocol"""
        try:
            self.context.log.info("Started removing user from group via SMB")
            # Connect to SAMR service
            dce = self._authenticate_dce()

            # Open server connection
            server_handle = samr.hSamrConnect(dce, self.connection.host + "\x00")["ServerHandle"]

            # Get domain SID and open domain
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.connection.domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]

            # Find the user and group RIDs
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.target_user,))["RelativeIds"]["Element"][0]
            group_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.group,))["RelativeIds"]["Element"][0]

            # Open the group
            group_handle = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)["GroupHandle"]

            # Remove member from the group
            samr.hSamrRemoveMemberFromGroup(dce, group_handle, user_rid)
            self.context.log.success(f"Successfully removed {self.target_user} from group {self.group}")

        except Exception as e:
            if "STATUS_MEMBER_NOT_IN_GROUP" in str(e):
                self.context.log.display(f"User {self.target_user} is not a member of group {self.group}")
            elif "STATUS_ACCESS_DENIED" in str(e):
                self.context.log.fail(f"Failed to remove user to group via SMB. Try with LDAP: {e}")
            elif "STATUS_NONE_MAPPED" in str(e):
                self.context.log.fail(f"Target user or group not found: {self.target_user} / {self.group}")
            else:
                self.context.log.fail(f"Failed to remove user to group via SMB: {e}")
        finally:
            if "dce" in locals():
                dce.disconnect()

    def _add_user_to_group_ldap(self):
        """Add user to group using LDAP protocol"""
        self.context.log.info("Started adding user to group via LDAP")

        try:
            # Search for the target user and group
            target_user_dn = self._find_object_dn(self.target_user)
            group_dn = self._find_object_dn(self.group)

            # Add user to group by modifying the group's "member" attribute
            self.connection.ldap_connection.modify(group_dn, {"member": [(0, [target_user_dn])]})  # 0 means Add
            self.context.log.success(f"Successfully added {self.target_user} to group {self.group}")

        except Exception as e:
            if "entryAlreadyExists" in str(e):
                self.context.log.display(f"User {self.target_user} is already a member of group {self.group}")
            elif "index out of range" in str(e):
                self.context.log.fail(f"Target user or group not found: {self.target_user} / {self.group}")
            else:
                self.context.log.fail(f"Failed to add user to group via LDAP: {e!s}")

    def _remove_user_from_group_ldap(self):
        """Remove user from group using LDAP protocol"""
        self.context.log.info("Started removing user from group via LDAP")

        try:
            # Search for the target user and group
            target_user_dn = self._find_object_dn(self.target_user)
            group_dn = self._find_object_dn(self.group)

            # Remove user from group by modifying the group's "member" attribute
            self.connection.ldap_connection.modify(group_dn, {"member": [(1, [target_user_dn])]})  # 1 means Delete
            self.context.log.success(f"Successfully removed {self.target_user} from group {self.group}")

        except Exception as e:
            if "WILL_NOT_PERFORM" in str(e):
                self.context.log.display(f"User {self.target_user} is not a member of group {self.group}")
            elif "index out of range" in str(e):
                self.context.log.fail(f"Target user or group not found: {self.target_user} / {self.group}")
            else:
                self.context.log.fail(f"Failed to add user to group via LDAP: {e!s}")

    def _find_object_dn(self, value):
        """Find the distinguished name (DN) of an object by sAMAccountName"""
        resp = self.connection.ldap_connection.search(
            searchFilter=f"(sAMAccountName={value})",
            attributes=["distinguishedName"]
        )
        resp_parsed = parse_result_attributes(resp)
        return resp_parsed[0]["distinguishedName"]
