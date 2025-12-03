import ssl
from io import BytesIO
import ldap3
from nxc.helpers.misc import CATEGORY
from nxc.protocols.smb.samrfunc import LSAQuery


class NXCModule:
    """
    Module to check which users/groups can add workstations to domain
    Author : @Blatzy github.com/Blatzy   
    """

    name = "check-add-computer"
    description = "Checks the 'Add workstations to domain' policy from Default Domain Controllers Policy"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        Check the SeMachineAccountPrivilege in the Default Domain Controllers Policy and MachineAccountQuota via LDAP.
        Displays which users/groups can add workstations to the domain.
        Usage: nxc smb $DC-IP -u 'username' -p 'password' -M check-add-computer
        """

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        # Check if SYSVOL share exists (DC verification)
        if not self.check_sysvol_exists():
            self.context.log.fail("SYSVOL share not found - This may not be a Domain Controller")
            return

        self.context.log.debug("SYSVOL share found - Confirmed Domain Controller")

        # Initialize LSA for SID resolution
        try:
            self.lsa_query = LSAQuery(
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                remote_name=connection.hostname,
                remote_host=connection.host,
                lmhash=connection.lmhash,
                nthash=connection.nthash,
                kerberos=connection.kerberos,
                kdcHost=connection.kdcHost,
                aesKey=connection.aesKey,
                logger=context.log
            )
        except Exception as e:
            self.context.log.fail(f"Failed to initialize LSA connection: {e}")
            self.lsa_query = None

        # Try static path first (most reliable)
        # Use targetDomain (DC's domain) not domain (user's auth domain) for trust scenarios
        dc_domain = connection.targetDomain
        dc_policy_guid = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
        dc_policy_path = f"{dc_domain}\\Policies\\{dc_policy_guid}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"

        self.context.log.info("Trying static path for Default Domain Controllers Policy...")
        self.context.log.debug(f"Static path: {dc_policy_path}")

        # Test if static path works
        try:
            buf = BytesIO()
            connection.conn.getFile("SYSVOL", dc_policy_path, buf.write)
            if buf.getvalue():
                self.context.log.highlight("Found Default Domain Controllers Policy via static path")
            else:
                dc_policy_path = None
        except Exception as e:
            self.context.log.debug(f"Static path failed: {e}")
            dc_policy_path = None

        # If static path fails, try spider
        if not dc_policy_path:
            self.context.log.info("Static path failed, searching with spider...")
            try:
                paths = connection.spider("SYSVOL", pattern=["GptTmpl.inf"])
                self.context.log.debug(f"Spider found {len(paths) if paths else 0} GptTmpl.inf files")

                if paths:
                    for path in paths:
                        self.context.log.debug(f"  - {path}")
                        # Look for Default Domain Controllers Policy GUID
                        if "6AC1786C-016F-11D2-945F-00C04fB984F9" in path.upper():
                            dc_policy_path = path
                            self.context.log.success(f"Found Default Domain Controllers Policy: {path}")
                            break
                else:
                    self.context.log.fail("No GptTmpl.inf files found in SYSVOL")
            except Exception as e:
                self.context.log.fail(f"Failed to search SYSVOL: {e}")

        if not dc_policy_path:
            self.context.log.fail("Default Domain Controllers Policy not found")
            return

        # Get the policy file content
        policy_content = self.get_policy_file(dc_policy_path)
        if not policy_content:
            self.context.log.fail("Could not retrieve Default Domain Controllers Policy")
            return

        # Parse and display SeMachineAccountPrivilege
        self.parse_machine_account_privilege(policy_content)

    def check_sysvol_exists(self):
        """Check if SYSVOL share exists on the target"""
        try:
            shares = self.connection.conn.listShares()
            for share in shares:
                if share["shi1_netname"].rstrip("\x00").upper() == "SYSVOL":
                    return True
            return False
        except Exception as e:
            self.context.log.debug(f"Error checking for SYSVOL: {e}")
            return False

    def get_policy_file(self, policy_path):
        """Retrieve GptTmpl.inf content from given path"""
        self.context.log.info("Reading policy file...")
        self.context.log.debug(f"Policy path: {policy_path}")

        try:
            # Use getFile with BytesIO like gpp_privileges.py
            buf = BytesIO()
            self.connection.conn.getFile("SYSVOL", policy_path, buf.write)

            content = buf.getvalue()

            if not content:
                self.context.log.fail("File is empty or could not be read")
                return None

            self.context.log.debug(f"Read {len(content)} bytes from policy file")

            # Try different encodings
            for encoding in ["utf-16-le", "utf-16", "latin-1", "utf-8"]:
                try:
                    decoded = content.decode(encoding, errors="ignore")
                    if decoded and len(decoded) > 0:
                        self.context.log.debug(f"Successfully decoded with {encoding}")
                        return decoded
                except:
                    continue

            self.context.log.fail("Could not decode policy file with any known encoding")
            return None

        except Exception as e:
            self.context.log.fail(f"Error reading policy file: {e}")
            self.context.log.debug(f"Full error details: {type(e).__name__}: {e!s}")
            return None

    def parse_machine_account_privilege(self, content):
        """Parse GptTmpl.inf to find SeMachineAccountPrivilege"""
        self.context.log.info("Parsing security policy...")

        # Find the [Privilege Rights] section
        in_privilege_section = False
        machine_account_line = None

        for line in content.split("\n"):
            line = line.strip()

            if line.upper() == "[PRIVILEGE RIGHTS]":
                in_privilege_section = True
                continue

            if in_privilege_section:
                # Check if we've moved to another section
                if line.startswith("["):
                    break

                # Look for SeMachineAccountPrivilege
                if line.startswith("SeMachineAccountPrivilege"):
                    machine_account_line = line
                    break

        if not machine_account_line:
            self.context.log.info("SeMachineAccountPrivilege not found in policy")
            self.context.log.highlight("=" * 60)
            self.context.log.highlight("Default configuration applies:")
            self.context.log.highlight("  - Authenticated Users can join computers to the domain")
            self.context.log.highlight("")

            # Query MachineAccountQuota
            maq_value = self.get_machine_account_quota()
            if maq_value is not None:
                if maq_value == 0:
                    self.context.log.highlight(f"ms-DS-MachineAccountQuota: {maq_value} (You cannot add any machines)")
                else:
                    self.context.log.highlight(f"ms-DS-MachineAccountQuota: {maq_value} ")
            else:
                self.context.log.info("Default: ms-DS-MachineAccountQuota (default: 10 machines per user)")

            self.context.log.highlight("=" * 60)
            return

        # Parse the line: SeMachineAccountPrivilege = *S-1-5-32-544,*S-1-5-21-...-512
        parts = machine_account_line.split("=", 1)
        if len(parts) != 2:
            self.context.log.fail("Could not parse SeMachineAccountPrivilege line")
            return

        sids = parts[1].strip()

        if not sids:
            self.context.log.info("No users/groups explicitly assigned (using default)")
            return

        # Split by comma and process each SID
        sid_list = [s.strip().lstrip("*") for s in sids.split(",") if s.strip()]

        if not sid_list:
            self.context.log.info("No SIDs found in policy")
            return

        # Resolve all SIDs at once using LSA
        resolved_names = self.resolve_sids(sid_list)

        # Display results
        self.context.log.highlight("Users/Groups that can add computers to the domain:")
        self.context.log.highlight("=" * 60)

        for sid, name in zip(sid_list, resolved_names, strict=False):
            if name and name != "":
                self.context.log.highlight(f"  - {name} ({sid})")
            else:
                self.context.log.highlight(f"  - UNKNOWN ({sid})")

        self.context.log.highlight("=" * 60)

    def resolve_sids(self, sid_list):
        """Resolve a list of SIDs to friendly names using LSA"""
        if not self.lsa_query:
            self.context.log.debug("LSA not available, cannot resolve SIDs")
            return ["UNKNOWN"] * len(sid_list)

        try:
            # Use LSAQuery to resolve all SIDs at once
            resolved_names = self.lsa_query.lookup_sids(sid_list)
            return resolved_names
        except Exception as e:
            self.context.log.debug(f"Error resolving SIDs via LSA: {e}")
            # Fallback to returning UNKNOWN for all SIDs
            return [""] * len(sid_list)

    def get_machine_account_quota(self):
        """Query ms-DS-MachineAccountQuota via LDAP"""
        try:
            # Build LDAP domain DN
            ldap_domain = f"dc={self.connection.targetDomain.replace('.', ',dc=')}"

            self.context.log.debug(f"Querying MachineAccountQuota via LDAP on {self.connection.host}")

            # Connect to LDAP (try LDAPS first, fallback to LDAP)
            ldap_server = None
            ldap_conn = None

            # Try LDAPS (port 636)
            try:
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL:@SECLEVEL=0")
                ldap_server = ldap3.Server(self.connection.host, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
                ldap_conn = ldap3.Connection(
                    ldap_server,
                    user=f"{self.connection.username}@{self.connection.domain}",
                    password=self.connection.password
                )
                if not ldap_conn.bind():
                    ldap_conn = None
                else:
                    self.context.log.debug("Connected via LDAPS")
            except Exception as e:
                self.context.log.debug(f"LDAPS connection failed: {e}")

            # Fallback to LDAP (port 389)
            if not ldap_conn:
                try:
                    ldap_server = ldap3.Server(self.connection.host, port=389, get_info=ldap3.ALL)
                    ldap_conn = ldap3.Connection(
                        ldap_server,
                        user=f"{self.connection.username}@{self.connection.domain}",
                        password=self.connection.password
                    )
                    if not ldap_conn.bind():
                        self.context.log.debug("LDAP connection failed")
                        return None
                    else:
                        self.context.log.debug("Connected via LDAP")
                except Exception as e:
                    self.context.log.debug(f"LDAP connection failed: {e}")
                    return None

            # Search for ms-DS-MachineAccountQuota
            ldap_conn.search(
                search_base=ldap_domain,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["ms-DS-MachineAccountQuota"]
            )

            if ldap_conn.entries:
                maq = ldap_conn.entries[0]["ms-DS-MachineAccountQuota"].value
                self.context.log.debug(f"MachineAccountQuota retrieved: {maq}")
                ldap_conn.unbind()
                return int(maq) if maq is not None else None

            ldap_conn.unbind()
            return None

        except Exception as e:
            self.context.log.debug(f"Error querying MachineAccountQuota: {e}")
            return None
