import re
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldap import LDAPSearchError


class NXCModule:
    """
    Find PKI Enrollment Services in Active Directory and Certificate Templates Names.

    Module by Tobias Neitzel (@qtc_de) and Sam Freeside (@snovvcrash)
    """

    name = "adcs"
    description = "Find PKI Enrollment Services in Active Directory and Certificate Templates Names"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.server = None
        self.regex = None

    def options(self, context, module_options):
        """
        BASE_DN            The base domain name for the LDAP query
        """
        self.regex = re.compile("(https?://.+)")

        self.server = None
        self.base_dn = None
        if module_options and "SERVER" in module_options:
            self.server = module_options["SERVER"]
        if module_options and "BASE_DN" in module_options:
            self.base_dn = module_options["BASE_DN"]

    def on_login(self, context, connection):
        """On a successful LDAP login we perform a search for all PKI Enrollment Server or Certificate Templates Names."""
        self.context = context
        search_filter = "(|(objectClass=mSSMSSite)(objectClass=mSSMSManagementPoint)(objectClass=mSSMSRoamingBoundaryRange)(objectClass=mSSMSServer))"
        context.log.display(f"Starting LDAP search with search filter '{search_filter}'")

        try:
            sc = ldap.SimplePagedResultsControl()
            base_dn_root = connection.ldapConnection._baseDN if self.base_dn is None else self.base_dn

            result = connection.ldapConnection.search(
                searchFilter=search_filter,
                attributes=[],
                sizeLimit=0,
                searchControls=[sc],
                searchBase=base_dn_root,
            )
        except LDAPSearchError as e:
            context.log.fail(f"Obtained unexpected exception: {e}")

 