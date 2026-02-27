import io
from pathlib import Path
import xml.etree.ElementTree as ET

from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH


class NXCModule:
    """TaskHound - Simplified Windows Scheduled Task Discovery Tool.

    Module by 0xr0BIT - Adapted for NetExec

    Enumerates scheduled tasks from remote Windows hosts and identifies tasks
    running with privileged domain accounts via LDAP group membership lookups.

    Task XMLs are automatically backed up to ~/.nxc/modules/taskhound/<hostname>/
    for offline analysis with the standalone TaskHound tool:
    https://github.com/1r0BIT/TaskHound
    """

    name = "taskhound"
    description = "Enumerate scheduled tasks and detect privileged accounts via LDAP"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.include_ms = False
        self.show_unsaved_creds = False
        self.ldap_user = ""
        self.ldap_pass = ""
        self.ldap_domain = ""

    def options(self, context, module_options):
        """Module options.

        INCLUDE_MS      Include Microsoft tasks (slow, default: false)
        UNSAVED_CREDS   Show tasks without stored credentials (default: false)
        LDAP_USER       Use separate credentials for LDAP (username)
        LDAP_PASS       Use separate credentials for LDAP (password)
        LDAP_DOMAIN     Domain for LDAP authentication (auto-detected from DC if not specified)

        Example:
            nxc smb 192.168.1.100 -u user -p pass -M taskhound
            nxc smb 192.168.1.100 -u localadmin -p pass --local-auth -M taskhound -o LDAP_USER=domainuser LDAP_PASS=domainpass LDAP_DOMAIN=domain.local --kdcHost 192.168.1.10
        """
        self.include_ms = module_options.get("INCLUDE_MS", "").lower() in ("true", "yes", "1")
        self.show_unsaved_creds = module_options.get("UNSAVED_CREDS", "").lower() in ("true", "yes", "1")
        self.ldap_user = module_options.get("LDAP_USER", "")
        self.ldap_pass = module_options.get("LDAP_PASS", "")
        self.ldap_domain = module_options.get("LDAP_DOMAIN", "")

    def on_admin_login(self, context, connection):
        """Execute TaskHound enumeration"""
        if not self.include_ms:
            context.log.info("Skipping \\Microsoft tasks (use INCLUDE_MS=true to include)")

        if not self.show_unsaved_creds:
            context.log.info("Filtering to tasks with stored credentials only")

        # Skip LDAP privilege checking if using local authentication (unless separate LDAP creds provided)
        ldap_helper = None

        if connection.args.local_auth and not (self.ldap_user and self.ldap_pass):
            context.log.display("Local authentication detected - skipping LDAP privilege detection")
            context.log.info("Use -o LDAP_USER=user LDAP_PASS=pass LDAP_DOMAIN=domain.local to enable LDAP with domain credentials")
        elif connection.args.local_auth and self.ldap_user and self.ldap_pass and not self.ldap_domain:
            context.log.fail("LDAP_DOMAIN is required when using --local-auth with separate LDAP credentials")
            context.log.info("Example: -o LDAP_USER=user LDAP_PASS=pass LDAP_DOMAIN=domain.local --kdcHost <DC_IP>")
        else:
            ldap_helper = self._get_ldap_connection(connection, context)
            if not ldap_helper:
                context.log.warning("Could not establish LDAP connection - privilege detection disabled")
                context.log.display("Tasks will be displayed but cannot determine if users are privileged")

        # Setup backup directory
        backup_target_dir = Path(NXC_PATH).expanduser() / "modules" / "taskhound" / connection.hostname
        backup_target_dir.mkdir(parents=True, exist_ok=True)

        # Crawl and collect tasks
        tasks = self._crawl_tasks(connection, context, backup_target_dir)

        if not tasks:
            context.log.fail("No scheduled tasks found")
            return

        context.log.success(f"Found {len(tasks)} scheduled task files")

        # Process and classify tasks
        tier0_tasks = []
        other_tasks = []

        for path, xml_data in tasks:
            meta = parse_task_xml(xml_data, context)
            runas = meta["runas"]

            if not runas:
                continue

            if not looks_like_domain_user(runas):
                continue

            logon_type = (meta["logon_type"] or "").lower()
            has_stored_creds = logon_type not in {"interactive", "interactivetoken", "s4u"}

            if not has_stored_creds and not self.show_unsaved_creds:
                continue

            # Resolve SID if needed and LDAP available
            resolved_runas = runas
            if ldap_helper and runas.strip().upper().startswith("S-1-5-"):
                resolved_runas, _ = ldap_helper.resolve_sid(runas)

            # Check privilege via LDAP if available
            is_privileged = False
            priv_groups = []
            if ldap_helper:
                is_privileged, priv_groups = ldap_helper.check_if_admin(resolved_runas)

            task_info = (path, meta, resolved_runas, is_privileged, priv_groups, has_stored_creds)

            if is_privileged and has_stored_creds:
                tier0_tasks.append(task_info)
            else:
                other_tasks.append(task_info)

        # Display summary counts
        interesting_count = len(tier0_tasks) + len(other_tasks)
        tier0_count = len(tier0_tasks)

        context.log.success(f"Found {interesting_count} interesting tasks")
        if tier0_count > 0:
            context.log.display(f"Found {tier0_count} TIER-0 tasks with stored credentials!")

        context.log.display("")

        # Display tasks
        for task_info in tier0_tasks:
            self._display_task(context, *task_info)

        for task_info in other_tasks:
            self._display_task(context, *task_info)

        # Display backup info
        context.log.display("Analyze XMLs offline with full TaskHound features:")
        context.log.display("https://github.com/1r0BIT/TaskHound")

    def _get_ldap_connection(self, connection, context):
        """Create LDAP connection for privilege checking."""
        try:
            # Determine LDAP target
            ldap_target = connection.kdcHost or connection.host

            # Determine domain
            if self.ldap_domain:
                domain = self.ldap_domain
            elif hasattr(connection, "targetDomain") and connection.targetDomain:
                domain = connection.targetDomain
            else:
                domain = connection.domain

            # Validate domain format
            if not domain:
                context.log.debug("Domain is required for LDAP connection")
                return None
            domain_parts = domain.split(".")
            if len(domain_parts) < 2 or not all(domain_parts):
                context.log.debug(f"Invalid domain format for LDAP: {domain!r} (must be FQDN like 'example.local')")
                return None

            base_dn = ",".join([f"DC={part}" for part in domain_parts])

            # Credentials
            username = self.ldap_user if self.ldap_user else connection.username
            password = self.ldap_pass if self.ldap_pass else connection.password

            if self.ldap_user:
                context.log.display(f"Using separate LDAP credentials: {username}@{domain}")

            # Create LDAP connection
            ldap_url = f"ldap://{ldap_target}"
            ldap_conn = ldap_impacket.LDAPConnection(ldap_url, dstIp=ldap_target)

            # Login with hash or password
            nthash = connection.nthash
            lmhash = connection.lmhash
            if nthash and not password:
                context.log.debug("Using NTLM hash authentication for LDAP connection")
                ldap_conn.login(user=username, password="", domain=domain, lmhash=lmhash, nthash=nthash)
            else:
                ldap_conn.login(user=username, password=password, domain=domain)

            context.log.debug(f"LDAP connection established to {ldap_target} as {username}@{domain}")

            return LDAPWrapper(ldap_conn, base_dn, domain, username, context)

        except Exception as e:
            context.log.debug(f"Failed to create LDAP connection: {e}")
            return None

    def _crawl_tasks(self, connection, context, backup_target_dir):
        """Crawl task directory and collect XML files."""
        results = []
        backup_count = 0
        task_root = "\\Windows\\System32\\Tasks"

        def recurse(cur_path):
            nonlocal backup_count
            try:
                files = connection.conn.listPath("C$", cur_path + "\\*")
            except Exception as e:
                context.log.debug(f"Error listing {cur_path}: {e}")
                return

            for file_info in files:
                try:
                    name = file_info.get_longname()
                    if name in (".", ".."):
                        continue

                    full_path = cur_path + "\\" + name

                    if file_info.is_directory():
                        if not self.include_ms and name.lower() == "microsoft":
                            continue
                        recurse(full_path)
                    else:
                        buff = io.BytesIO()
                        connection.conn.getFile("C$", full_path, buff.write)
                        xml_data = buff.getvalue()

                        rel_path = full_path.lstrip("\\")
                        results.append((rel_path, xml_data))

                        # Backup XML file
                        backup_file = backup_target_dir / Path(rel_path.replace("\\", "/"))
                        backup_file.parent.mkdir(parents=True, exist_ok=True)
                        backup_file.write_bytes(xml_data)
                        backup_count += 1

                except Exception as e:
                    context.log.debug(f"Failed to process {file_info.get_longname()}: {e}")

        recurse(task_root)

        if backup_count > 0:
            context.log.debug(f"Backed up {backup_count} task XML files to {backup_target_dir}")

        return results

    def _display_task(self, context, path, meta, runas, is_privileged, priv_groups, has_stored_creds):
        """Display task information."""
        if is_privileged and has_stored_creds:
            prefix = "[TIER-0]"
        elif is_privileged:
            prefix = "[PRIV]"
        else:
            prefix = "[TASK]"

        command = meta["command"] or ""
        arguments = meta["arguments"] or ""
        command_line = f"{command} {arguments}".strip() if arguments else command

        context.log.highlight("")
        context.log.highlight(f"{prefix} {path}")
        context.log.highlight(f"        Enabled : {meta['enabled'] or 'Unknown'}")
        context.log.highlight(f"        RunAs   : {runas}")
        if command_line:
            context.log.highlight(f"        What    : {command_line}")
        if meta["author"]:
            context.log.highlight(f"        Author  : {meta['author']}")
        if meta["date"]:
            context.log.highlight(f"        Date    : {meta['date']}")

        if is_privileged:
            context.log.highlight("        Reason  : Member of TIER-0 groups, GG!")

        if has_stored_creds:
            context.log.highlight("        Password Analysis : Task uses stored credentials")
        else:
            context.log.highlight("        Password Analysis : No stored credentials")

        if is_privileged and has_stored_creds:
            context.log.highlight("        Next Step: Try DPAPI Dump / Task Manipulation")
        elif has_stored_creds:
            context.log.highlight("        Next Step: Analyze stored credentials")

        context.log.highlight("")


class LDAPWrapper:
    """Minimal LDAP wrapper with privilege checking functionality."""

    def __init__(self, conn, base_dn, domain, username, context):
        self.ldap_connection = conn
        self.baseDN = base_dn
        self.domain = domain
        self.username = username
        self.context = context
        self.sid_domain = None

    def search(self, searchFilter, attributes, sizeLimit=0):
        """Execute LDAP search."""
        paged_search_control = [ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)]
        return self.ldap_connection.search(
            scope=None,
            searchBase=self.baseDN,
            searchFilter=searchFilter,
            attributes=attributes,
            sizeLimit=sizeLimit,
            searchControls=paged_search_control
        )

    def resolve_sid(self, sid):
        """Resolve Windows SID to sAMAccountName."""
        try:
            if not sid or not sid.upper().startswith("S-1-5-"):
                return sid, False

            search_filter = f"(objectSid={sid})"
            resp = self.search(search_filter, ["sAMAccountName"], sizeLimit=1)

            if not resp:
                return sid, False

            resp_parsed = parse_result_attributes(resp)
            if resp_parsed and len(resp_parsed) > 0:
                sam = resp_parsed[0].get("sAMAccountName")
                if sam:
                    domain_name = self.domain.split(".")[0].upper() if self.domain else ""
                    return f"{domain_name}\\{sam}", True

            return sid, False

        except Exception as e:
            self.context.log.debug(f"SID resolution failed for {sid}: {e}")
            return sid, False

    def check_if_admin(self, username=None):
        """Check if user is member of privileged groups."""
        target_username = username.split("\\")[-1] if username and "\\" in username else username or self.username

        try:
            # Get domain SID
            search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
            resp = self.search(search_filter, ["objectSid"])
            resp_parsed = parse_result_attributes(resp)
            privileged_groups = []

            if not resp_parsed:
                return False, []

            for item in resp_parsed:
                self.sid_domain = "-".join(item["objectSid"].split("-")[:-1])
                break

            # Get privileged group DNs
            search_filter = f"(|(objectSid={self.sid_domain}-512)(objectSid={self.sid_domain}-544)(objectSid={self.sid_domain}-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            resp = self.search(search_filter, ["distinguishedName"])
            resp_parsed = parse_result_attributes(resp)
            answers = []
            for item in resp_parsed:
                answers.append(f"(memberOf:1.2.840.113556.1.4.1941:={item['distinguishedName']})")
                privileged_groups.append(item["distinguishedName"])

            if not answers:
                return False, []

            # Check if user is member
            search_filter = f"(&(objectCategory=user)(sAMAccountName={target_username})(|{''.join(answers)}))"
            resp = self.search(search_filter, [])
            resp_parsed = parse_result_attributes(resp)

            for item in resp_parsed:
                if item:
                    return True, privileged_groups

            return False, []

        except Exception as e:
            self.context.log.debug(f"Privilege check failed for {target_username}: {e}")
            return False, []


def parse_task_xml(xml_content, context=None):
    """Parse Windows Task Scheduler XML content."""
    tag_mapping = {
        "UserId": "runas",
        "LogonType": "logon_type",
        "Command": "command",
        "Arguments": "arguments",
        "Author": "author",
        "Date": "date",
        "Enabled": "enabled"
    }

    result = dict.fromkeys(tag_mapping.values())

    if not xml_content:
        return result

    try:
        if xml_content.startswith(b"<?xml"):
            declaration_end = xml_content.find(b"?>")
            if declaration_end != -1:
                xml_content = xml_content[declaration_end + 2:].lstrip()

        root = ET.fromstring(xml_content)

        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1]
            if tag_name in tag_mapping and elem.text:
                result[tag_mapping[tag_name]] = elem.text.strip()

    except ET.ParseError as e:
        if context:
            context.log.debug(f"Failed to parse task XML: {e}")

    return result


def looks_like_domain_user(runas):
    """Check if a RunAs value looks like a domain user."""
    if not runas:
        return False

    runas_lower = runas.lower().strip()

    if runas_lower.startswith(("nt authority\\", "nt service\\", "builtin\\")):
        return False

    if runas_lower.endswith("$"):
        return False

    if "\\" in runas_lower or "@" in runas_lower:
        return True

    return runas_lower in {"administrator"}
