import contextlib
import sys
from impacket.ldap.ldap import MODIFY_ADD, MODIFY_DELETE
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

        SMB/SAMR KNOWN LIMITATIONS:
            - SAMR only supports modification of Global security groups.
              Domain Local and Universal groups require the LDAP protocol.
            - Cross-domain groups (e.g. Enterprise Admins) cannot be modified via SAMR.
              Use LDAP instead.

        """
        self.group = module_options.get("GROUP")
        self.target_user = module_options.get("USER")
        self.remove = module_options.get("REMOVE", "False").lower() == "true"

        if not (self.target_user and self.group):
            context.log.fail("USER and GROUP parameters are required!")
            sys.exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        if context.protocol == "smb":
            self._modify_group_smb()
        elif context.protocol == "ldap" and self.group:
            self._modify_group_ldap()

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
            self.context.log.info("Successfully connected to DCE/RPC")
            dce.bind(interface)
            self.context.log.info(f"Successfully bound to {interface}")
            return dce
        except DCERPCException as e:
            self.context.log.fail(f"DCE/RPC Exception: {e!s}")

    def _modify_group_smb(self):
        """Modify group membership using SMB/SAMR protocol"""
        dce = self._authenticate_dce()
        if not dce:
            return

        # Get domain handle
        try:
            server_handle = samr.hSamrConnect(dce, self.connection.host + "\x00")["ServerHandle"]
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.connection.domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
        except Exception as e:
            self.context.log.fail(f"Failed to connect to SAMR service: {e}")
            return

        # Find the user RID
        try:
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.target_user,))["RelativeIds"]["Element"][0]
        except Exception as e:
            if "STATUS_NONE_MAPPED" in str(e):
                self.context.log.fail(f"Target user not found: {self.target_user}")
            else:
                self.context.log.fail(f"Failed to find user RID: {e}")
            return

        # Find the group RID and open the group
        try:
            group_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (self.group,))["RelativeIds"]["Element"][0]
            group_handle = samr.hSamrOpenGroup(dce, domain_handle, groupId=group_rid)["GroupHandle"]
        except Exception as e:
            if "STATUS_NONE_MAPPED" in str(e):
                self.context.log.fail(f"Target group not found: {self.group}")
            else:
                self.context.log.fail(f"Failed to find group: {e}")
            return

        # Modify group membership
        if self.remove:
            try:
                samr.hSamrRemoveMemberFromGroup(dce, group_handle, user_rid)
                self.context.log.success(f"Successfully removed {self.target_user} from group {self.group}")
            except Exception as e:
                if "STATUS_MEMBER_NOT_IN_GROUP" in str(e):
                    self.context.log.fail(f"User {self.target_user} is not a member of group {self.group}")
                else:
                    self.context.log.fail(f"Failed to remove user from group via SMB: {e}")
        else:
            try:
                samr.hSamrAddMemberToGroup(dce, group_handle, user_rid, 0x7)
                self.context.log.success(f"Successfully added {self.target_user} to group {self.group}")
            except Exception as e:
                if "STATUS_MEMBER_IN_GROUP" in str(e):
                    self.context.log.fail(f"User {self.target_user} is already a member of group {self.group}")
                else:
                    self.context.log.fail(f"Failed to add user to group via SMB: {e}")

        # Disconnect from DCE/RPC
        with contextlib.suppress(Exception):
            dce.disconnect()

    def _modify_group_ldap(self):
        """Modify group membership using LDAP protocol"""
        # Get the DN of the target user
        resp = self._find_object_dn(self.target_user)
        if not resp:
            self.context.log.fail(f"Target user not found: {self.target_user}")
            return
        else:
            target_user_dn = resp[0]["distinguishedName"]

        # Get the DN of the target group
        resp = self._find_object_dn(self.group)
        if not resp:
            self.context.log.fail(f"Target group not found: {self.group}")
            return
        else:
            group_dn = resp[0]["distinguishedName"]

        # Modify group membership
        if self.remove:
            try:
                self.connection.ldap_connection.modify(group_dn, {"member": [(MODIFY_DELETE, [target_user_dn])]})
                self.context.log.success(f"Successfully removed {self.target_user} from group {self.group}")
            except Exception as e:
                if "unwillingToPerform" in str(e):
                    self.context.log.fail(f"User {self.target_user} is not a member of group {self.group}")
                else:
                    self.context.log.fail(f"Failed to remove user from group via LDAP: {e}")
        else:
            try:
                self.connection.ldap_connection.modify(group_dn, {"member": [(MODIFY_ADD, [target_user_dn])]})
                self.context.log.success(f"Successfully added {self.target_user} to group {self.group}")
            except Exception as e:
                if "entryAlreadyExists" in str(e):
                    self.context.log.fail(f"User {self.target_user} is already a member of group {self.group}")
                else:
                    self.context.log.fail(f"Failed to add user to group via LDAP: {e}")

    def _find_object_dn(self, value):
        """Find the distinguished name (DN) of an object by sAMAccountName"""
        resp = self.connection.ldap_connection.search(
            searchFilter=f"(sAMAccountName={value})",
            attributes=["distinguishedName"]
        )
        return parse_result_attributes(resp)
