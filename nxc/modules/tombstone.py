import sys
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1
from nxc.logger import nxc_logger
from nxc.parsers.ldap_results import parse_result_attributes
from impacket.ldap.ldapasn1 import Control
from impacket.ldap.ldap import LDAPSessionError, MODIFY_REPLACE, MODIFY_DELETE
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Module by Fabrizzio: @Fabrizzio53"""

    name = "tombstone"
    description = "Query, restore and delete AD object"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
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
        Usage: nxc ldap $DC-IP -u Username -p Password -M tombstone"
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=delete DN="CN=test,OU=Users,DC=test,DC=local"
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=query
        """
        self.action = "query"
        self.id = ""
        self.deleteDN = ""
        self.ssl = True
        if "ACTION" in module_options:
            self.action = module_options["ACTION"]
        if "ID" in module_options:
            self.id = module_options["ID"]
        if "DN" in module_options:
            self.deleteDN = module_options["DN"]
        
        if "ACTION" in module_options and self.action == "restore" and "ID" not in module_options:
            context.log.error("ID is necessary when calling tombstone with the restore action")
            sys.exit(1)

        if "ACTION" in module_options and self.action == "delete" and "DN" not in module_options:
            context.log.error("DN is necessary when calling tombstone with the delete action")
            sys.exit(1)

    def domain_to_dn(self, domain):
        return ",".join(f"DC={part}" for part in domain.split("."))

    def restore_deleted_object(self, context, connection):

        # ldap DN for deleted objects
        dn = "CN=Deleted Objects," + self.domain_to_dn(self.__domain)

        # Search filter used to recover only Deleted objects and only the one with the specified id
        searchFilter = "(isDeleted=TRUE)"
        
        # LDAP control necessary to show the deleted objects LDAP_SERVER_SHOW_DELETED_OID
        show_deleted_control = Control()
        show_deleted_control["controlType"] = "1.2.840.113556.1.4.417"
        show_deleted_control["criticality"] = True

        context.log.highlight(f"Trying to find object with given id {self.id}")

        try:
            context.log.debug(f"Search Filter={searchFilter}")
            resp = connection.ldap_connection.search(
                dn,
                2,
                searchFilter=searchFilter,
                attributes=["*"],
                sizeLimit=0,
                searchControls=[show_deleted_control]
            )

        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False
    
        resp_parsed = parse_result_attributes(resp)

        context.log.highlight(f"")

        for response in resp_parsed:
            
            # The value 17 is the first entry from the ldap query when returning deleted objects and it should by default return the Deleted Objects OU information, by skipping this we return only objects that we want
            if len(response) != 17 and self.id == response["name"].split(":")[1]:
              
                context.log.highlight("Found target!")
                context.log.highlight(f"sAMAccountName      {response['sAMAccountName']}")
                context.log.highlight(f"dn      {response['distinguishedName']}")
                context.log.highlight(f"ID      {response['name'].split(':')[1]}")
                context.log.highlight(f"isDeleted       {response['isDeleted']}")
                context.log.highlight(f"lastKnownParent       {response['lastKnownParent']}")
                context.log.highlight("")
                self.__sAMAccountName = response["sAMAccountName"]
                self.__objectDN = response["distinguishedName"]
                self.__lastKnownParent = response["lastKnownParent"]

                break

        if self.__sAMAccountName == "":
            context.log.highlight(f"The object was not found with id {self.id}.")
            return None

        # LDAP control necessary to pass when recovering deleted objects [LDAP_SERVER_SHOW_DELETED_OID]
        show_deleted_control = Control()
        show_deleted_control["controlType"] = "1.2.840.113556.1.4.417"
        show_deleted_control["criticality"] = True

        try:
            connection.ldap_connection.modify(dn=self.__objectDN,
                           modifications={
                               "isDeleted": [(MODIFY_DELETE, [])], # Remove the isDeleted atribute
                               "distinguishedName": [(MODIFY_REPLACE, [f"CN={self.__sAMAccountName},{self.__lastKnownParent}"])] #restore the user DN
                               },
                            controls=[show_deleted_control]
            )

            context.log.highlight(f'Success "CN={self.__sAMAccountName},{self.__lastKnownParent}" restored')

        except LDAPSessionError as e:
            context.log.highlight(f"Error at trying to recover the object {e}")

        return
            
    def delete_object(self, context, connection):
        
        context.log.highlight(f"Trying to delete {self.deleteDN}")

        try:
            connection.ldap_connection.delete(dn=self.deleteDN)
            
            context.log.highlight("")
            context.log.highlight(f'Success, "{self.deleteDN}" deleted')

        except LDAPSessionError as e:
            context.log.highlight("")
            context.log.highlight(f'Error when trying to delete "{self.deleteDN}" {e}')                

        return

    def query_deleted_objects(self, context, connection):

        # ldap DN for deleted objects
        dn = "CN=Deleted Objects," + self.domain_to_dn(self.__domain)

        # Search filter used to recover only Deleted objects
        searchFilter = "(isDeleted=TRUE)"

        # LDAP control necessary to show the deleted objects LDAP_SERVER_SHOW_DELETED_OID
        show_deleted_control = Control()
        show_deleted_control["controlType"] = "1.2.840.113556.1.4.417"
        show_deleted_control["criticality"] = True

        try:
            context.log.debug(f"Search Filter={searchFilter}")
            resp = connection.ldap_connection.search(
                dn,
                2,
                searchFilter=searchFilter,
                attributes=["*"],
                sizeLimit=0,
                searchControls=[show_deleted_control]
            )

        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        entries = [item for item in resp if isinstance(item, ldapasn1.SearchResultEntry)]  

        if len(entries) < 2:
            context.log.highlight("Recycle bin is not active on the domain or no user is in a tombstone state")

            return None

        context.log.highlight(f"Found {len(resp)} deleted objects")
        context.log.highlight("")

        resp_parsed = parse_result_attributes(resp)

        for response in resp_parsed:

            # The value 17 is the first entry from the ldap query when returning deleted objects and it should by default return the Deleted Objects OU information, by skipping this we return only objects that we want
            if len(response) != 17:
               
                context.log.highlight(f"sAMAccountName      {response['sAMAccountName']}")
                context.log.highlight(f"dn      {response['distinguishedName']}")
                context.log.highlight(f"ID      {response['name'].split(':')[1]}")
                context.log.highlight(f"isDeleted       {response['isDeleted']}")
                context.log.highlight(f"lastKnownParent       {response['lastKnownParent']}")
                context.log.highlight("")
    
    def on_login(self, context, connection):
        self.__domain = connection.domain
        self.__sAMAccountName = ""
        self.__objectDN = ""
        self.__lastKnownParent = ""
        
        self.__domain = connection.domain

        if self.action == "query":
            self.query_deleted_objects(context, connection)

        if self.action == "delete":
            self.delete_object(context, connection)
        
        if self.action == "restore":
            self.restore_deleted_object(context, connection)
