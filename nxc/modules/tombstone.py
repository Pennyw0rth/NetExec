from sys import exit

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

    def restore_deleted_object(self, context, connection):

        # ldap DN for deleted objects
        dn = f"CN=Deleted Objects,{connection.baseDN}"

        # LDAP control necessary to show the deleted objects LDAP_SERVER_SHOW_DELETED_OID
        show_deleted_control = Control()
        show_deleted_control["controlType"] = "1.2.840.113556.1.4.417"
        show_deleted_control["criticality"] = True

        context.log.highlight(f"Trying to find object with given id {self.id}")

        context.log.debug("Search Filter=(isDeleted=TRUE)")
        resp = self.connection.search(baseDN=dn, searchFilter="(isDeleted=TRUE)", attributes=["*"], searchControls=[show_deleted_control])

        resp_parsed = parse_result_attributes(resp)
        context.log.highlight("")

        for entries in resp_parsed:

            # This check ensures that we skip the result for the Default container and only get the result from the given ID.
            if "container" in entries["objectClass"] and entries["description"] == "Default container for deleted objects":

                continue

            if self.id == entries["name"].split(":")[1]:

                context.log.highlight(f"{'sAMAccountName':<20}: {entries.get('sAMAccountName', '')}")
                context.log.highlight(f"{'description':<20}: {entries.get('description', '')}")
                context.log.highlight(f"{'dn':<20}: {entries.get('distinguishedName', '')}")
                context.log.highlight(f"{'ID':<20}: {entries.get('name', '').split(':')[1]}")
                context.log.highlight(f"{'isDeleted':<20}: {entries.get('isDeleted', '')}")
                context.log.highlight(f"{'lastKnownParent':<20}: {entries.get('lastKnownParent', '')}")
                context.log.highlight("")

                self.__objectDN = entries.get("distinguishedName", "")
                self.__lastKnownParent = entries.get("lastKnownParent", "")
                object_prefix = self.__objectDN.split("\\")[0]
                self.__originalDN = f"{object_prefix},{self.__lastKnownParent}"

                break

        if self.__originalDN == "":
            context.log.highlight(f"The object was not found with id {self.id}.")
            return False

        try:
            connection.ldap_connection.modify(dn=self.__objectDN, modifications={"isDeleted": [(MODIFY_DELETE, [])], "distinguishedName": [(MODIFY_REPLACE, [self.__originalDN])]}, controls=[show_deleted_control])
            context.log.highlight(f"Success {self.__originalDN} restored")

        except LDAPSessionError as e:
            context.log.fail(f"Error at trying to recover the object {e}")
            return False

    def delete_object(self, context, connection):
        context.log.highlight(f"Trying to delete {self.deleteDN}")

        try:
            connection.ldap_connection.delete(dn=self.deleteDN)
            context.log.highlight("")
            context.log.highlight(f'Success, "{self.deleteDN}" deleted')

        except LDAPSessionError as e:
            context.log.highlight("")
            context.log.fail(f'Error when trying to delete "{self.deleteDN}" {e}')

    def query_deleted_objects(self, context):

        # ldap DN for deleted objects
        dn = f"CN=Deleted Objects,{self.connection.baseDN}"

        # LDAP control necessary to show the deleted objects LDAP_SERVER_SHOW_DELETED_OID
        show_deleted_control = Control()
        show_deleted_control["controlType"] = "1.2.840.113556.1.4.417"
        show_deleted_control["criticality"] = True

        context.log.debug("Search Filter=(isDeleted=TRUE)")
        resp = self.connection.search(baseDN=dn, searchFilter="(isDeleted=TRUE)", attributes=["*"], searchControls=[show_deleted_control])
        resp_parsed = parse_result_attributes(resp)

        if len(resp_parsed) == 0:
            context.log.highlight("Could not find the Deleted Objects container, AD recycle bin might not be active")
            return False

        elif len(resp_parsed) < 2:
            context.log.highlight("No objects are in a tombstone state")
            return False

        number_of_deleted_objects = 0
        context.log.highlight("")

        for entries in resp_parsed:

            # This check ensures that we skip the result for the Default container and only get results that are valid for us.
            if "container" in entries["objectClass"] and entries["description"] == "Default container for deleted objects":

                continue

            context.log.highlight(f"{'sAMAccountName':<20}: {entries.get('sAMAccountName', '')}")
            context.log.highlight(f"{'description':<20}: {entries.get('description', '')}")
            context.log.highlight(f"{'dn':<20}: {entries.get('distinguishedName', '')}")
            context.log.highlight(f"{'ID':<20}: {entries.get('name', '').split(':')[1]}")
            context.log.highlight(f"{'isDeleted':<20}: {entries.get('isDeleted', '')}")
            context.log.highlight(f"{'lastKnownParent':<20}: {entries.get('lastKnownParent', '')}")
            context.log.highlight("")

            number_of_deleted_objects += 1

        context.log.highlight(f"Found {number_of_deleted_objects} deleted objects")
