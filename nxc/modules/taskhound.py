#!/usr/bin/env python3
# TaskHound - Simplified Windows Scheduled Task Discovery Tool
# Module by 0xr0BIT - Adapted for NetExec
# Stripped down version leveraging existing LDAP protocol functions

import io
import os
import xml.etree.ElementTree as ET

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH

# Constants
TASK_ROOT_PATH = "\\Windows\\System32\\Tasks"
DEFAULT_SHARE = "C$"
NO_CREDS_LOGON_TYPES = {"interactive", "interactivetoken", "s4u"}


def parse_task_xml(xml_content):
    """Parse Windows Task Scheduler XML content."""
    result = {
        "runas": None,
        "author": None,
        "date": None,
        "command": None,
        "arguments": None,
        "logon_type": None,
        "enabled": None
    }

    if not xml_content:
        return result

    try:
        # Handle encoding declaration
        if xml_content.startswith(b"<?xml"):
            declaration_end = xml_content.find(b"?>")
            if declaration_end != -1:
                xml_content = xml_content[declaration_end + 2:].lstrip()

        root = ET.fromstring(xml_content)

        # Extract elements (namespace-agnostic)
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1]

            if tag_name == "UserId" and elem.text:
                result["runas"] = elem.text.strip()
            elif tag_name == "LogonType" and elem.text:
                result["logon_type"] = elem.text.strip()
            elif tag_name == "Command" and elem.text:
                result["command"] = elem.text.strip()
            elif tag_name == "Arguments" and elem.text:
                result["arguments"] = elem.text.strip()
            elif tag_name == "Author" and elem.text:
                result["author"] = elem.text.strip()
            elif tag_name == "Date" and elem.text:
                result["date"] = elem.text.strip()
            elif tag_name == "Enabled" and elem.text:
                result["enabled"] = elem.text.strip()

    except ET.ParseError:
        pass

    return result


def is_sid(value):
    """Check if a value looks like a Windows SID"""
    if not value:
        return False
    return value.strip().upper().startswith("S-1-5-")


def looks_like_domain_user(runas):
    """Check if a RunAs value looks like a domain user"""
    if not runas:
        return False

    runas_lower = runas.lower().strip()

    # Skip system accounts
    if runas_lower.startswith(("nt ", "builtin\\")):
        return False

    # Skip computer accounts (end with $)
    if runas_lower.endswith("$"):
        return False

    # Domain-qualified or UPN format
    if "\\" in runas_lower or "@" in runas_lower:
        return True

    # Common admin accounts
    return runas_lower in {"administrator"}


def get_ldap_connection(smb_connection, context, ldap_user=None, ldap_pass=None, ldap_domain=None):
    """Create a lightweight LDAP wrapper that uses the enhanced functions from ldap.py.

    This creates a minimal object that delegates to the ldap protocol's resolve_sid()
    and check_if_admin() functions, avoiding code duplication.

    Args:
        smb_connection: SMB connection object (provides domain, kdcHost)
        context: Module context for logging
        ldap_user: Optional separate username for LDAP authentication
        ldap_pass: Optional separate password for LDAP authentication
        ldap_domain: Optional domain for LDAP (overrides SMB connection domain)

    Returns:
        LDAPWrapper object with resolve_sid and check_if_admin methods, or None on failure.
    """
    try:
        from impacket.ldap import ldap as ldap_impacket

        # Import ldap protocol module to use its functions
        import importlib.util
        from pathlib import Path

        ldap_module_path = Path(__file__).parent.parent / "protocols" / "ldap.py"
        spec = importlib.util.spec_from_file_location("nxc.protocols.ldap_proto", ldap_module_path)
        ldap_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ldap_module)

        # Determine LDAP target: use kdcHost (DC) if available
        ldap_target = getattr(smb_connection, "kdcHost", None) or smb_connection.host

        # Create LDAP connection
        ldap_url = f"ldap://{ldap_target}"
        ldap_conn = ldap_impacket.LDAPConnection(ldap_url, dstIp=ldap_target)

        # Determine domain: use ldap_domain if provided, otherwise try to get from SMB connection
        # When using --local-auth, smb_connection.domain is the machine name, not the AD domain
        if ldap_domain:
            domain = ldap_domain
            context.log.debug(f"Using provided LDAP domain: {domain}")
        elif hasattr(smb_connection, "targetDomain") and smb_connection.targetDomain:
            # targetDomain is the actual AD domain (not affected by --local-auth)
            domain = smb_connection.targetDomain
            context.log.debug(f"Using targetDomain: {domain}")
        else:
            domain = smb_connection.domain
            context.log.debug(f"Using SMB connection domain: {domain}")

        domain_parts = domain.split(".")
        base_dn = ",".join([f"DC={part}" for part in domain_parts])

        # Use separate LDAP credentials if provided, otherwise use SMB credentials
        username = ldap_user if ldap_user else smb_connection.username
        password = ldap_pass if ldap_pass else getattr(smb_connection, "password", "")

        if ldap_user:
            context.log.display(f"Using separate LDAP credentials: {username}@{domain}")

        ldap_conn.login(user=username, password=password, domain=domain)
        context.log.debug(f"LDAP connection established to {ldap_target} as {username}@{domain}")

        # Create a lightweight wrapper that delegates to ldap.py functions
        class LDAPWrapper:
            """Minimal wrapper that uses enhanced functions from ldap protocol"""
            def __init__(self, conn, base_dn, domain, username, password, context, ldap_funcs):
                self.ldap_connection = conn  # Named to match ldap protocol's attribute
                self.baseDN = base_dn
                self.domain = domain
                self.username = username
                self.password = password
                self.context = context
                self.sid_domain = None
                # Attributes needed by ldap.py functions
                self.lmhash = ""
                self.nthash = ""
                self.aesKey = ""
                self.use_kcache = False
                self.logger = context.log
                # Store references to the actual ldap.py functions
                self._resolve_sid_func = ldap_funcs["resolve_sid"]
                self._check_if_admin_func = ldap_funcs["check_if_admin"]

            def search(self, searchFilter, attributes, sizeLimit=0, baseDN=None, searchControls=None):
                """Search wrapper that matches ldap protocol's signature"""
                from impacket.ldap import ldapasn1 as ldapasn1_impacket
                if baseDN is None:
                    baseDN = self.baseDN
                paged_search_control = [ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)]
                # Use None for scope like ldap protocol does initially
                return self.ldap_connection.search(
                    scope=None,
                    searchBase=baseDN,
                    searchFilter=searchFilter,
                    attributes=attributes,
                    sizeLimit=sizeLimit,
                    searchControls=searchControls if searchControls else paged_search_control
                )

            def resolve_sid(self, sid):
                """Resolve Windows SID to username via LDAP."""
                return self._resolve_sid_func(self, sid)

            def check_if_admin(self, username=None):
                """Check if user is member of privileged groups via LDAP."""
                return self._check_if_admin_func(self, username)

        # Get the actual functions from ldap.py to avoid duplication
        ldap_functions = {
            "resolve_sid": ldap_module.ldap.resolve_sid,
            "check_if_admin": ldap_module.ldap.check_if_admin
        }

        return LDAPWrapper(ldap_conn, base_dn, domain, username, password, context, ldap_functions)

    except Exception as e:
        context.log.debug(f"Failed to create LDAP connection: {e}")
        return None


class NXCModule:
    """TaskHound - Simple Windows Scheduled Task Discovery.

    Enumerates scheduled tasks and identifies privileged tasks via LDAP.
    """

    name = "taskhound"
    description = "Enumerate scheduled tasks and detect privileged accounts via LDAP"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

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

        Task XMLs are automatically backed up to ~/.nxc/logs/taskhound_backup/ for offline analysis:
            taskhound --offline ~/.nxc/logs/taskhound_backup --bh-data bloodhound_export.json --bh-opengraph
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
        using_local_auth = hasattr(connection, "args") and getattr(connection.args, "local_auth", False)
        has_ldap_creds = self.ldap_user and self.ldap_pass

        if using_local_auth and not has_ldap_creds:
            context.log.display("Local authentication detected - skipping LDAP privilege detection")
            context.log.info("Use -o LDAP_USER=user LDAP_PASS=pass LDAP_DOMAIN=domain.local to enable LDAP with domain credentials")
        elif using_local_auth and has_ldap_creds and not self.ldap_domain:
            context.log.fail("LDAP_DOMAIN is required when using --local-auth with separate LDAP credentials")
            context.log.info("Example: -o LDAP_USER=user LDAP_PASS=pass LDAP_DOMAIN=domain.local --kdcHost <DC_IP>")
        else:
            # Try to establish LDAP connection for privilege checking
            ldap_helper = get_ldap_connection(connection, context, self.ldap_user, self.ldap_pass, self.ldap_domain)
            if not ldap_helper:
                context.log.warning("Could not establish LDAP connection - privilege detection disabled")
                context.log.display("Tasks will be displayed but cannot determine if users are privileged")

        # Setup backup directory (always enabled by default)
        base_backup_dir = os.path.join(os.path.expanduser(NXC_PATH), "logs", "taskhound_backup")
        hostname = getattr(connection, "hostname", connection.host)
        backup_target_dir = os.path.join(base_backup_dir, hostname)

        try:
            os.makedirs(backup_target_dir, exist_ok=True)
        except Exception as e:
            context.log.fail(f"Failed to create backup directory {backup_target_dir}: {e}")
            backup_target_dir = None

        try:
            # Crawl and collect tasks
            tasks = self._crawl_tasks(connection, context, backup_target_dir)

            if not tasks:
                context.log.fail("No scheduled tasks found")
                return

            context.log.success(f"Found {len(tasks)} scheduled task files")

            # Process and classify tasks first (collect all before displaying)
            tier0_tasks = []
            other_tasks = []

            for path, xml_data in tasks:
                # Parse task
                meta = parse_task_xml(xml_data)
                runas = meta.get("runas")

                if not runas:
                    continue

                # Check if domain user
                if not looks_like_domain_user(runas):
                    continue

                # Check credential storage
                logon_type = (meta.get("logon_type") or "").lower()
                has_stored_creds = logon_type not in NO_CREDS_LOGON_TYPES

                if not has_stored_creds and not self.show_unsaved_creds:
                    continue

                # Resolve SID if needed and LDAP available
                resolved_runas = runas
                if ldap_helper and is_sid(runas):
                    resolved_runas, success = ldap_helper.resolve_sid(runas)
                    if not success:
                        context.log.debug(f"Could not resolve SID {runas}")

                # Check privilege via LDAP if available
                is_privileged = False
                priv_groups = []
                if ldap_helper:
                    is_privileged, priv_groups = ldap_helper.check_if_admin(resolved_runas)

                # Classify task
                task_info = (path, meta, resolved_runas, is_privileged, priv_groups, has_stored_creds)

                if is_privileged and has_stored_creds:
                    tier0_tasks.append(task_info)
                else:
                    other_tasks.append(task_info)

            # Display summary counts BEFORE showing tasks
            interesting_count = len(tier0_tasks) + len(other_tasks)
            tier0_count = len(tier0_tasks)

            context.log.success(f"Found {interesting_count} interesting tasks")
            if tier0_count > 0:
                context.log.display(f"Found {tier0_count} TIER-0 tasks with stored credentials!")

            context.log.display("")  # Blank line for readability

            # Display TIER-0 tasks first, then others
            for task_info in tier0_tasks:
                self._display_task(context, *task_info)

            for task_info in other_tasks:
                self._display_task(context, *task_info)

            # Display backup info and next steps
            if backup_target_dir:
                context.log.display("Analyze XMLs offline with full TaskHound features:")
                context.log.display("https://github.com/1r0BIT/TaskHound")
        except Exception as e:
            context.log.fail(f"Error during enumeration: {e}")

    def _crawl_tasks(self, connection, context, backup_target_dir=None):
        """Crawl task directory and collect XML files"""
        results = []
        backup_count = 0

        def recurse(cur_path):
            nonlocal backup_count
            try:
                files = connection.conn.listPath(DEFAULT_SHARE, cur_path + "\\*")

                for file_info in files:
                    name = file_info.get_longname()
                    if name in (".", ".."):
                        continue

                    full_path = cur_path + "\\" + name

                    if file_info.is_directory():
                        # Skip Microsoft unless requested
                        if not self.include_ms and name.lower() == "microsoft":
                            continue
                        recurse(full_path)
                    else:
                        # Read task file
                        try:
                            buff = io.BytesIO()
                            connection.conn.getFile(DEFAULT_SHARE, full_path, buff.write)
                            xml_data = buff.getvalue()

                            # Normalize path
                            rel_path = full_path[1:] if full_path.startswith("\\") else full_path
                            results.append((rel_path, xml_data))

                            # Backup XML file if requested
                            if backup_target_dir:
                                try:
                                    # Convert Windows path to local OS path
                                    backup_file_path = os.path.join(backup_target_dir, rel_path.replace("\\", os.sep))
                                    backup_file_dir = os.path.dirname(backup_file_path)
                                    os.makedirs(backup_file_dir, exist_ok=True)
                                    with open(backup_file_path, "wb") as f:
                                        f.write(xml_data)
                                    backup_count += 1
                                except Exception as e:
                                    context.log.debug(f"Failed to backup {rel_path}: {e}")
                        except Exception as e:
                            context.log.debug(f"Failed to read {full_path}: {e}")

            except Exception as e:
                context.log.debug(f"Error listing {cur_path}: {e}")

        recurse(TASK_ROOT_PATH)

        if backup_target_dir and backup_count > 0:
            context.log.success(f"Backed up {backup_count} task XML files to {backup_target_dir}")

        return results

    def _display_task(self, context, path, meta, runas, is_privileged, priv_groups, has_stored_creds):
        """Display task information"""
        # Determine classification
        if is_privileged and has_stored_creds:
            prefix = "[TIER-0]"
            log_method = context.log.highlight
        elif is_privileged:
            prefix = "[PRIV]"
            log_method = context.log.highlight
        else:
            prefix = "[TASK]"
            log_method = context.log.display

        # Build command line
        command = meta.get("command", "")
        arguments = meta.get("arguments", "")
        what = f"{command} {arguments}".strip() if arguments else command

        # Display task
        log_method("")  # Blank line before each task
        log_method(f"{prefix} {path}")
        log_method(f"        Enabled : {meta.get('enabled', 'Unknown')}")
        log_method(f"        RunAs   : {runas}")
        if what:
            log_method(f"        What    : {what}")
        if meta.get("author"):
            log_method(f"        Author  : {meta['author']}")
        if meta.get("date"):
            log_method(f"        Date    : {meta['date']}")

        # Display privilege info
        if is_privileged:
            log_method("        Reason  : Member of TIER-0 groups, GG!")

        # Display credential info
        if has_stored_creds:
            log_method("        Password Analysis : Task uses stored credentials")
        else:
            log_method("        Password Analysis : No stored credentials")

        # Next steps
        if is_privileged and has_stored_creds:
            log_method("        Next Step: Try DPAPI Dump / Task Manipulation")
        elif has_stored_creds:
            log_method("        Next Step: Analyze stored credentials")

        log_method("")
