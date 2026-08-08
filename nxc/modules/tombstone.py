import sys
from nxc.parsers.ldap_results import parse_result_attributes
from impacket.ldap.ldapasn1 import Control
from impacket.ldap.ldap import LDAPSessionError, MODIFY_REPLACE, MODIFY_DELETE
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module by Fabrizzio: @Fabrizzio53"""

    name = "tombstone"
    description = "Query, restore and delete AD object"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.domains = None

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
        self.action = module_options.get("ACTION", "query")
        self.id = ""
        self.deleteDN = ""
        if "ACTION" in module_options:
            self.action = module_options.get("ACTION")
        if "ID" in module_options:
            self.id = module_options["ID"]
        if "DN" in module_options:
            self.deleteDN = module_options["DN"]
        if "ACTION" in module_options and self.action.lower() == "restore" and "ID" not in module_options:
            context.log.error("ID is necessary when calling tombstone with the restore action")
            sys.exit(1)

        if "ACTION" in module_options and self.action.lower() == "delete" and "DN" not in module_options:
            context.log.error("DN is necessary when calling tombstone with the delete action")
            sys.exit(1)

    def on_login(self, context, connection):
        self.__sAMAccountName = ""
        self.__objectDN = ""
        self.__lastKnownParent = ""
        self.connection = connection

        if self.action.lower() == "query":
            self.query_deleted_objects(context)
        elif self.action.lower() == "delete":
            self.delete_object(context, connection)
        elif self.action.lower() == "restore":
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
            context.log.highlight(f"{'dn':<20}: {entries.get('distinguishedName', '')}")
            context.log.highlight(f"{'ID':<20}: {entries.get('name', '').split(':')[1]}")
            context.log.highlight(f"{'isDeleted':<20}: {entries.get('isDeleted', '')}")
            context.log.highlight(f"{'lastKnownParent':<20}: {entries.get('lastKnownParent', '')}")
            context.log.highlight("")

            number_of_deleted_objects += 1

        context.log.highlight(f"Found {number_of_deleted_objects} deleted objects")
