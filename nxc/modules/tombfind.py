from nxc.helpers.misc import CATEGORY
from impacket.ldap import ldap, ldapasn1


class NXCModule:
    name = "tombfind"
    description = "Find tombstoned Active Directory objects"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        ACTION      Action to perform: find or restore (default: find)
        PAGE_SIZE   Number of results per page for find operation (default: 10)
        OUTPUT      Output results to file (optional, only for find)
        """
        self.action = module_options.get("ACTION", "find").lower()
        self.page_size = int(module_options.get("PAGE_SIZE", 10))
        self.output_file = module_options.get("OUTPUT", None)

    # Checks if an action is supplied
    def on_login(self, context, connection):
        try:
            if self.action == "find":
                self.find_deleted_objects(context, connection)
            else:
                context.log.error(f"Unknown action: {self.action}. Use 'find'")
        except Exception as e:
            context.log.error(f"Module execution error: {e!s}")
            context.log.debug(f"Exception details: {e}", exc_info=True)

    # Handles LDAP Authentication
    def _get_ldap_connection(self, context, connection):
        if hasattr(connection, "ldapConnection") and connection.ldapConnection:
            context.log.debug("Using existing ldapConnection")
            return connection.ldapConnection

        if hasattr(connection, "conn") and connection.conn:
            context.log.debug("Using existing conn")
            return connection.conn

        context.log.debug("Creating new LDAP connection")

        ldap_url = f"ldap://{connection.host}"
        ldap_conn = ldap.LDAPConnection(ldap_url)

        try:
            if hasattr(connection, "kerberos") and connection.kerberos:
                if connection.password and connection.password != "":
                    ldap_conn.kerberosLogin(
                        user=connection.username,
                        password=connection.password,
                        domain=connection.domain,
                        lmhash="",
                        nthash=""
                    )
                else:
                    ldap_conn.kerberosLogin(
                        user=connection.username,
                        password="",
                        domain=connection.domain,
                        lmhash="",
                        nthash=""
                    )
            elif hasattr(connection, "nthash") and connection.nthash:
                context.log.debug("Authenticating with NTLM hash")
                ldap_conn.login(
                    user=connection.username,
                    password="",
                    domain=connection.domain,
                    lmhash="aad3b435b51404eeaad3b435b51404ee",
                    nthash=connection.nthash
                )
            else:
                # Use password
                context.log.debug("Authenticating with password")
                ldap_conn.login(
                    user=connection.username,
                    password=connection.password,
                    domain=connection.domain
                )

            context.log.debug("LDAP connection authenticated successfully")
            return ldap_conn

        except Exception as e:
            context.log.error(str(e))
            raise

    def find_deleted_objects(self, context, connection):
        try:
            # Gets the domain from the connection Object
            domain_parts = connection.domain.split(".")
            # Builds the Search Base
            search_base = f'CN=Deleted Objects,DC={",DC=".join(domain_parts)}'
            # Defines the search filter
            search_filter = (
                "(&(|(objectClass=User)"
                "(objectCategory=Computer))"
                "(isDeleted=TRUE))")
            # Defines  the attributes to be fetched
            attributes = [
                "cn",
                "sAMAccountName",
                "objectClass",
                "lastKnownParent"
            ]

            context.log.info("[*] Searching for deleted objects...")

            show_deleted_control = ldapasn1.Control()
            show_deleted_control["controlType"] = ldapasn1.LDAPOID(
                "1.2.840.113556.1.4.417"
            )
            show_deleted_control["criticality"] = True

            ldap_conn = self._get_ldap_connection(context, connection)

            entry_list = []
            cookie = b""

            while True:
                # Defines  the number of Pages returned per query [default: 10]
                paging_control = ldapasn1.SimplePagedResultsControl(
                    criticality=False,
                    size=self.page_size,
                    cookie=cookie
                )

                try:
                    # Initiates the search
                    resp = ldap_conn.search(
                        searchBase=search_base,
                        searchFilter=search_filter,
                        scope=ldapasn1.Scope("wholeSubtree"),
                        attributes=attributes,
                        searchControls=[show_deleted_control, paging_control]
                    )
                except Exception as e:
                    context.log.error(f"Search error: {e!s}")
                    break

                for item in resp:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        entry_list.append(item)

                break

            if not entry_list:
                context.log.info(
                    "No deleted objects found (or insufficient permissions)"
                )
                return

            context.log.success(
                f"Found {len(entry_list)} deleted object(s)"
            )

            results = []
            for entry in entry_list:
                attrs = self._parse_entry_attributes(entry)

                if not attrs:
                    continue
                # Filters  attributes for each object returned from the query
                cn = attrs.get("cn", [""])[0]
                guid = cn.split("\n")[1].split(":")[1]
                ou = attrs.get("lastKnownParent", [""])[0]
                sam = attrs.get("sAMAccountName", [""])[0]
                obj_class = attrs.get("objectClass", [""])[-1]

                result_str = f"[{obj_class}] {sam} | GUID: {guid} |  OU: {ou}"
                context.log.highlight(result_str)
                context.log.info(f"  Last Known Parent: {ou}")

                results.append(f"{sam},{guid},{ou},{obj_class}")
            if self.output_file:
                try:
                    with open(self.output_file, "w") as f:
                        f.write("\n".join(str(result) for result in results) + "\n")
                    context.log.success(
                        f"Results saved to {self.output_file}"
                    )
                except Exception as e:
                    context.log.error(f"Failed to write to file: {e!s}")

        except Exception as e:
            context.log.error(f"Error in find operation: {e!s}")
            context.log.debug(f"Exception details: {e}", exc_info=True)

    def _parse_entry_attributes(self, entry):
        attrs = {}
        try:
            for attr in entry["attributes"]:
                attr_name = str(attr["type"])
                attr_values = [str(val) for val in attr["vals"]]
                attrs[attr_name] = attr_values
        except Exception:
            pass
        return attrs
