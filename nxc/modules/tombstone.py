from impacket.ldap.ldap import LDAPSessionError, MODIFY_DELETE, MODIFY_REPLACE
from impacket.ldap.ldapasn1 import Control, SimplePagedResultsControl

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """Module by Fabrizzio: @Fabrizzio53"""

    name = "tombstone"
    description = "Query, restore and delete AD object"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ACTION: Specify the action to execute, by default it uses the "query" action which only retrieve deleted objects, "restore" recover the object from the "ID" param, delete will delete the object.
        ID: The id of which object you want to restore.
        DN: The DN of which object you want to delete.
        Usage: nxc ldap $DC-IP -u Username -p Password -M tombstone
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=delete DN="CN=test,OU=Users,DC=test,DC=local"
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=query
        """
        self.action = module_options.get("ACTION", "query").lower()
        self.id = module_options.get("ID", "")
        self.delete_dn = module_options.get("DN", "")
        if self.action == "restore" and not self.id:
            context.log.fail("ID is necessary when calling tombstone with the restore action")
            return False

        if self.action == "delete" and not self.delete_dn:
            context.log.fail("DN is necessary when calling tombstone with the delete action")
            return False

    def on_login(self, context, connection):
        if self.action == "query":
            self.query_deleted_objects(context, connection)
        elif self.action == "delete":
            self.delete_object(context, connection)
        elif self.action == "restore":
            self.restore_deleted_object(context, connection)
        else:
            context.log.fail(f'The action "{self.action}" is not valid, use only one available option (query, restore, delete)')

    def show_deleted_control(self):
        return Control().setComponents("1.2.840.113556.1.4.417", True)

    def search_deleted_objects(self, connection):
        return parse_result_attributes(
            connection.search(
                baseDN=f"CN=Deleted Objects,{connection.baseDN}",
                searchFilter="(isDeleted=TRUE)",
                attributes=[],
                searchControls=[self.show_deleted_control(), SimplePagedResultsControl(criticality=True, size=1000)],
            )
        )

    def restore_deleted_object(self, context, connection):
        object_dn = ""
        original_dn = ""

        context.log.highlight(f"Trying to find object with given id {self.id}")

        context.log.debug("Search Filter=(isDeleted=TRUE)")
        context.log.highlight("")

        for entries in self.search_deleted_objects(connection):
            if entries.get("distinguishedName", "").casefold() == f"CN=Deleted Objects,{connection.baseDN}".casefold():
                continue

            if self.id.casefold() == entries.get("name", "").rsplit(":", 1)[-1].casefold():
                context.log.highlight(f"{'sAMAccountName':<20}: {entries.get('sAMAccountName', '')}")
                context.log.highlight(f"{'description':<20}: {entries.get('description', '')}")
                context.log.highlight(f"{'dn':<20}: {entries.get('distinguishedName', '')}")
                context.log.highlight(f"{'ID':<20}: {entries.get('name', '').rsplit(':', 1)[-1]}")
                context.log.highlight(f"{'isDeleted':<20}: {entries.get('isDeleted', '')}")
                context.log.highlight(f"{'lastKnownParent':<20}: {entries.get('lastKnownParent', '')}")
                context.log.highlight("")

                object_dn = entries.get("distinguishedName", "")
                original_dn = object_dn.rsplit("\\0ADEL:", 1)[0] + "," + entries.get("lastKnownParent", "")
                break

        if not original_dn:
            context.log.fail(f"The object was not found with id {self.id}.")
            return False

        try:
            connection.ldap_connection.modify(dn=object_dn, modifications={"isDeleted": [(MODIFY_DELETE, [])], "distinguishedName": [(MODIFY_REPLACE, [original_dn])]}, controls=[self.show_deleted_control()])
            context.log.highlight(f"Success {original_dn} restored")

        except LDAPSessionError as e:
            context.log.fail(f"Error at trying to recover the object {e}")
            return False

    def delete_object(self, context, connection):
        context.log.highlight(f"Trying to delete {self.delete_dn}")

        try:
            connection.ldap_connection.delete(dn=self.delete_dn)
            context.log.highlight("")
            context.log.highlight(f'Success, "{self.delete_dn}" deleted')

        except LDAPSessionError as e:
            context.log.highlight("")
            context.log.fail(f'Error when trying to delete "{self.delete_dn}" {e}')

    def query_deleted_objects(self, context, connection):
        context.log.debug("Search Filter=(isDeleted=TRUE)")
        resp_parsed = self.search_deleted_objects(connection)

        if not resp_parsed:
            context.log.highlight("Could not find the Deleted Objects container, AD recycle bin might not be active")
            return False

        resp_parsed = [entries for entries in resp_parsed if entries.get("distinguishedName", "").casefold() != f"CN=Deleted Objects,{connection.baseDN}".casefold()]
        if not resp_parsed:
            context.log.highlight("No objects are in a tombstone state")
            return False

        context.log.highlight("")

        for entries in resp_parsed:
            context.log.highlight(f"{'sAMAccountName':<20}: {entries.get('sAMAccountName', '')}")
            context.log.highlight(f"{'description':<20}: {entries.get('description', '')}")
            context.log.highlight(f"{'dn':<20}: {entries.get('distinguishedName', '')}")
            context.log.highlight(f"{'ID':<20}: {entries.get('name', '').rsplit(':', 1)[-1]}")
            context.log.highlight(f"{'isDeleted':<20}: {entries.get('isDeleted', '')}")
            context.log.highlight(f"{'lastKnownParent':<20}: {entries.get('lastKnownParent', '')}")
            context.log.highlight("")

        context.log.highlight(f"Found {len(resp_parsed)} deleted objects")
