import sys
from impacket.ldap import ldap as ldap_impacket
from nxc.logger import nxc_logger
from nxc.parsers.ldap_results import parse_result_attributes
from impacket.ldap.ldapasn1 import Control
from impacket.examples.utils import init_ldap_session
from ldap3 import MODIFY_REPLACE, MODIFY_DELETE


class NXCModule:
    """Module by Fabrizzio: @Fabrizzio53"""

    name = "tombstone"
    description = "Query, restore and delete AD object"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.domains = None

    def options(self, context, module_options):
        """
        ACTION: Specify the action to execute, by default it uses the "query" action which only retrieve deleted objects, "restore" recover the object from the "ID" param, delete will delete the object.
        ID: The id of which object you want to restore.
        DN: The DN of which object you want to delete.
        SCHEME: Force to use ldap or ldaps when trying to restore or delete an object, by default it uses ldaps.
        Usage: nxc ldap $DC-IP -u Username -p Password -M tombstone"
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=delete DN="CN=test,OU=Users,DC=test,DC=local"
               nxc ldap $DC-IP -u Username -p Password -M tombstone -o ACTION=restore ID=5ad162c9-97b1-4a90-a17c-5c2aedb7d1e3 SCHEME=ldap
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
        if "SCHEME" in module_options and module_options["SCHEME"] == "ldap":
            self.ssl = False
        
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
        
        if len(resp) < 1:
            context.log.highlight("Recycle is not active on that domain or no object is deleted.")

            return None

        context.log.highlight(f"Found {len(resp)} deleted objects, parsing results to recover necessary informations from given ID")
        context.log.highlight("")

        resp_parsed = parse_result_attributes(resp)

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

        #If Kerberos True, then fqdn is used, similar to the -dc-host from impacket, set the machine_name to a fqdn and don't call _get_machine_name (good when NTLM is disabled)
        if self.__doKerberos == True:

            self.__kdcHost = self.__host

        ldap_server, ldap_session = init_ldap_session(self.__domain, self.__username, self.__password, self.__lmhash, self.__nthash, self.__doKerberos, self.__host, self.__kdcHost, self.__aesKey, self.ssl)

        control = ("1.2.840.113556.1.4.417", True, None)      

        success = ldap_session.modify(
            dn=self.__objectDN,
            changes={
            "isDeleted": [(MODIFY_DELETE, [])],  # Remove the isDeleted atribute
            "distinguishedName": [(MODIFY_REPLACE, [f"CN={self.__sAMAccountName},{self.__lastKnownParent}"])]  # Change the old dn to the original DN
            },
            controls=[control]
        )
       
        if success:

            context.log.highlight(f'Success "CN={self.__sAMAccountName},{self.__lastKnownParent}" restored')

        else:

            context.log.highlight(f"Error at trying to recover the object {ldap_session.result['description']}")

    def delete_object(self, context, connection):

        #If Kerberos True, then fqdn is used, similar to the -dc-host from impacket, set the machine_name to a fqdn and don't call _get_machine_name (good when NTLM is disabled)
        if self.__doKerberos == True:

            self.__kdcHost = self.__host

        ldap_server, ldap_session = init_ldap_session(self.__domain, self.__username, self.__password, self.__lmhash, self.__nthash, self.__doKerberos, self.__host, self.__kdcHost, self.__aesKey, self.ssl)
        
        context.log.highlight(f"Trying to delete {self.deleteDN}")
                    
        success = ldap_session.delete(self.deleteDN)

        if success:
            
            context.log.highlight("")
            context.log.highlight(f'Success, "{self.deleteDN}" deleted')

        else:

            context.log.highlight("")
            context.log.highlight(f'Error when trying to delete "{self.deleteDN}" {ldap_session.result}')                

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
            
        if len(resp) < 1:
            context.log.highlight("Recycle is not active on that domain or no object is deleted with that id.")

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
        self.__domainNetbios = connection.domain
        self.__kdcHost = connection.kdcHost
        self.__username = connection.username
        self.__password = connection.password
        self.__host = connection.host
        self.__aesKey = context.aesKey
        self.__hashes = context.hash
        self.__doKerberos = connection.kerberos
        self.__nthash = ""
        self.__lmhash = ""
        self.__sAMAccountName = ""
        self.__objectDN = ""
        self.__lastKnownParent = ""

        if context.hash and ":" in context.hash[0]:
            hashList = context.hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif context.hash and ":" not in context.hash[0]:
            self.__nthash = context.hash[0]
            self.__lmhash = "00000000000000000000000000000000"
        
        self.__domain = connection.domain

        if self.action == "query":
            self.query_deleted_objects(context, connection)

        if self.action == "delete":
            self.delete_object(context, connection)
        
        if self.action == "restore":
            self.restore_deleted_object(context, connection)
