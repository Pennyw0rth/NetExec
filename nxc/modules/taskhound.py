#!/usr/bin/env python3

import io
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from nxc.helpers.misc import CATEGORY

# Constants for better maintainability
TASK_ROOT_PATH = "\\Windows\\System32\\Tasks"
DEFAULT_SHARE = "C$"
KNOWN_SYSTEM_ACCOUNTS = {"nt ", "builtin\\"}
KNOWN_ADMIN_ACCOUNTS = {"administrator"}
NO_CREDS_LOGON_TYPES = {"interactive", "interactivetoken", "s4u"}


def _convert_timestamp(timestamp_value):
    """Convert various timestamp formats to datetime. Returns None if conversion fails."""
    if not timestamp_value or timestamp_value == "0" or timestamp_value == 0:
        return None

    try:
        # Handle different input types
        if isinstance(timestamp_value, str):
            if timestamp_value.strip() == "":
                return None
            timestamp = float(timestamp_value)
        else:
            timestamp = float(timestamp_value)

        if timestamp == 0:
            return None

        # Detect format based on magnitude
        # Windows FILETIME is very large (> 100 billion for dates after 1970)
        # Unix timestamp is smaller (< 10 billion for dates before 2286)
        if timestamp > 10000000000:  # Likely Windows FILETIME
            # Windows FILETIME epoch: January 1, 1601 00:00:00 UTC
            # Convert 100-nanosecond intervals to seconds
            unix_timestamp = (timestamp - 116444736000000000) / 10000000.0
            return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        else:  # Likely Unix timestamp
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    except (ValueError, OSError, OverflowError):
        return None


class HighValueLoader:
    """Load and query high-value users from BloodHound export (CSV or JSON) - Supports both Legacy and BHCE formats"""

    def __init__(self, path: str):
        self.path = path
        self.hv_users: dict[str, dict[str, Any]] = {}
        self.hv_sids: dict[str, dict[str, Any]] = {}
        self.loaded = False
        self.format_type = "unknown"

    def load(self) -> bool:
        """Load high-value users from CSV or JSON file"""
        if not Path(self.path).exists():
            return False

        try:
            if self.path.lower().endswith(".json"):
                return self._load_json()
            elif self.path.lower().endswith(".csv"):
                return self._load_csv()
            return False
        except Exception:
            return False

    def _load_json(self) -> bool:
        with open(self.path, encoding="utf-8-sig") as f:  # Handle BOM
            data = json.load(f)

        if not data:
            return False

        # Detect format type
        if self._is_bhce_format(data):
            self.format_type = "bhce"
            return self._load_bhce_json(data)
        elif isinstance(data, list) and len(data) > 0:
            # Check if it's legacy format
            if self._has_fields(data[0].keys()):
                self.format_type = "legacy"
                return self._load_legacy_format(data)
            else:
                return False
        else:
            return False

    def _is_bhce_format(self, data: Any) -> bool:
        #         """Detect BHCE format by presence of isTierZero field in nodes"""
        if not isinstance(data, dict):
            return False

        nodes = data.get("nodes", {})
        if not isinstance(nodes, dict):
            return False

        # Check if any node has isTierZero field (key indicator)
        return any(isinstance(node_data, dict) and "isTierZero" in node_data for node_data in nodes.values())

    def _has_fields(self, headers) -> bool:
        #         """Return True if headers contain the required fields"""
        if not headers:
            return False
        lower = {h.strip().lower() for h in headers}

        # Traditional format: SamAccountName + (sid OR objectid)
        traditional_format = {"samaccountname"}.issubset(lower) and ({"sid"}.issubset(lower) or {"objectid"}.issubset(lower))

        # New lazy query format: SamAccountName + all_props
        new_format = {"samaccountname", "all_props"}.issubset(lower)

        return traditional_format or new_format

    def _load_bhce_json(self, data: dict[str, Any]) -> bool:
        #         """Load BloodHound Community Edition format"""
        nodes = data.get("nodes", {})

        # Process each node
        for node_data in nodes.values():
            if not isinstance(node_data, dict):
                continue

            # Only process Users for now (could extend to Groups later)
            if node_data.get("kind") != "User":
                continue

            # Extract core fields
            object_id = node_data.get("objectId", "").strip()
            label = node_data.get("label", "").strip()
            properties = node_data.get("properties", {})

            if not object_id or not label:
                continue

            # Extract samaccountname from label (e.g., "HIGHPRIV@BADSUCCESSOR.LAB" -> "highpriv")
            sam = label.split("@")[0].lower() if "@" in label else properties.get("samaccountname", "").strip().lower()

            if not sam:
                continue

            # Build user data structure compatible with existing code
            user_data = {
                "sid": object_id.upper(),
                "groups": [],  # Will be populated from edges
                "group_names": [],  # Will be populated from edges
                "admincount": properties.get("admincount", False),
                "pwdlastset": _convert_timestamp(properties.get("pwdlastset")),
                "lastlogon": _convert_timestamp(properties.get("lastlogon")),
            }

            # Copy all properties for extensibility
            # Exclude fields we've already processed with special handling
            for key, value in properties.items():
                if key.lower() not in ["samaccountname", "objectid", "pwdlastset", "lastlogon"]:
                    user_data[key.lower()] = value

            # Add BHCE-specific fields
            user_data["istierzero"] = node_data.get("isTierZero", False)
            user_data["system_tags"] = properties.get("system_tags", "")

            # Store in lookup dictionaries
            self.hv_users[sam] = user_data
            self.hv_sids[object_id.upper()] = dict(user_data)
            self.hv_sids[object_id.upper()]["sam"] = sam

        self.loaded = True
        return True

    def _load_legacy_format(self, data):
        """Load legacy BloodHound format"""
        for row in data:
            self._process_user_record(row)
        self.loaded = True
        return True

    def _process_user_record(self, user):
        """Process a single user record from JSON or CSV data"""
        # Check if this is the new "all_props" format
        if "all_props" in user:
            return self._process_all_props_format(user)
        else:
            return self._process_traditional_format(user)

    def _process_all_props_format(self, user):
        """Process legacy format with all_props structure"""
        sam_raw = (user.get("SamAccountName") or "").strip().strip('"').lower()
        all_props_raw = user.get("all_props", {})

        if not sam_raw or not all_props_raw:
            return False

        # Handle all_props as dict (JSON)
        if isinstance(all_props_raw, dict):
            all_props = all_props_raw
        else:
            # all_props as string - skip for now in NetExec (too complex for regex parsing)
            return False

        # Extract SID from all_props
        sid_raw = (all_props.get("objectid") or "").strip().strip('"')
        if not sid_raw:
            return False

        # Normalize sam (handle DOMAIN\\user format)
        sam = sam_raw.split("\\\\", 1)[1] if "\\\\" in sam_raw else sam_raw

        sid = sid_raw.upper()

        # Extract groups from the top level
        groups = user.get("groups", [])
        group_names = [g.strip().strip('"') for g in groups if g.strip()]

        # Create user data starting with all_props
        user_data = dict(all_props)  # Copy all BloodHound properties
        user_data.update({
            "sid": sid,
            "groups": groups,
            "group_names": group_names,
            "pwdlastset": _convert_timestamp(all_props.get("pwdlastset")),
            "lastlogon": _convert_timestamp(all_props.get("lastlogon")),
        })

        self.hv_users[sam] = user_data
        self.hv_sids[sid] = dict(user_data)
        self.hv_sids[sid]["sam"] = sam
        return True

    def _process_lazy_query_format(self, all_props):
        r"""Process the new lazy query format with \"all_props\" object"""
        sam_raw = (all_props.get("SamAccountName") or "").strip().strip('"').lower()
        all_props_raw = all_props.get("all_props", {})

        if not sam_raw or not all_props_raw:
            return False

        # Handle all_props as dict (JSON)
        if isinstance(all_props_raw, dict):
            all_props = all_props_raw
        else:
            # all_props as string - skip for now in NetExec (too complex for regex parsing)
            return False

        # Extract SID from all_props
        sid_raw = (all_props.get("objectid") or "").strip().strip('"')
        if not sid_raw:
            return False

        # Normalize sam (handle DOMAIN\user format)
        sam = sam_raw.split("\\", 1)[1] if "\\" in sam_raw else sam_raw

        sid = sid_raw.upper()

        # Create user data starting with all_props
        user_data = dict(all_props)  # Copy all BloodHound properties
        user_data.update({
            "sid": sid,
            "groups": [],
            "group_names": [],
            "pwdlastset": _convert_timestamp(all_props.get("pwdlastset")),
            "lastlogon": _convert_timestamp(all_props.get("lastlogon")),
        })

        self.hv_users[sam] = user_data
        self.hv_sids[sid] = dict(user_data)
        self.hv_sids[sid]["sam"] = sam
        return True

    def _process_traditional_format(self, user):
        """Process traditional format"""
        # Extract required fields with fallback names
        sam_raw = (user.get("SamAccountName") or user.get("samaccountname") or "").strip().strip('"').lower()
        sid_raw = (user.get("sid") or user.get("objectid") or "").strip().strip('"')

        if not sam_raw or not sid_raw:
            return False

        # Normalize sam (handle DOMAIN\user format)
        sam = sam_raw.split("\\", 1)[1] if "\\" in sam_raw else sam_raw

        sid = sid_raw.upper()

        # Create user data with core fields
        user_data = {
            "sid": sid,
            "groups": [],
            "group_names": [],
        }

        # Preserve ALL additional BloodHound attributes for future extensibility
        excluded_keys = {"samaccountname", "sid", "objectid", "groups", "group_names"}
        for key, value in user.items():
            if key.lower() not in excluded_keys:
                user_data[key.lower()] = value

        self.hv_users[sam] = user_data
        self.hv_sids[sid] = dict(user_data)
        self.hv_sids[sid]["sam"] = sam
        return True

    def _load_csv(self) -> bool:
        #         """Load from CSV format - Supports both Legacy and BHCE"""
        with open(self.path, encoding="utf-8-sig") as f:  # Handle BOM
            reader = csv.DictReader(f)
            if not self._has_fields(reader.fieldnames):
                return False

            for row in reader:
                self._process_user_data(row)

        self.loaded = True
        return True

    def is_high_value(self, username: str) -> bool:
        #         """Check if a username is high-value"""
        if not self.loaded:
            return False
        return username.lower() in self.hv_users

    def is_tier0(self, username: str) -> bool:
        """Check if a username is Tier 0 (simplified version for compatibility)"""
        is_tier0, _ = self.check_tier0(username)
        return is_tier0

    def check_tier0(self, runas: str) -> tuple[bool, list[str]]:
        """
        Return (True, reasons) if the given RunAs value belongs to Tier 0 groups.
        Enhanced to include AdminSDHolder detection via admincount=1
        Supports both Legacy and BHCE formats
        """
        if not runas or not self.loaded:
            return False, []

        val = runas.strip()
        user_data = None

        # Look up user data from BloodHound
        if val.upper().startswith("S-1-5-"):
            user_data = self.hv_sids.get(val)
        else:
            # NETBIOS\sam or just sam
            sam = val.split("\\", 1)[1].lower() if "\\" in val else val.lower()
            user_data = self.hv_users.get(sam)

        if not user_data:
            return False, []

        tier0_reasons = []

        # Check 1: BHCE-specific isTierZero flag or system_tags
        bhce_tier0_detected = False
        if self.format_type == "bhce" and user_data.get("istierzero"):
            bhce_tier0_detected = True

        system_tags = user_data.get("system_tags", "")
        if system_tags and "admin_tier_0" in system_tags:
            bhce_tier0_detected = True

        if bhce_tier0_detected:
            tier0_reasons.append("BHCE Tier 0 attribute")

        # Check 3: AdminSDHolder protection (admincount=1) - works for both formats
        admincount = user_data.get("admincount")
        if admincount and str(admincount).lower() in ("1", "true"):
            tier0_reasons.append("AdminSDHolder")

        # Check 4: Group membership via SIDs (language independent) - mainly for Legacy format
        group_sids = user_data.get("groups", [])  # This contains the actual SIDs
        group_names = user_data.get("group_names", [])  # This contains display names

        # Well-known Tier 0 SIDs for direct SID-based detection
        TIER0_SIDS = {
            "S-1-5-32-544": "Administrators",  # Local Administrators
            "S-1-5-21-{domain}-512": "Domain Admins",  # Domain Admins (domain-relative)
            "S-1-5-21-{domain}-516": "Domain Controllers",  # Domain Controllers
            "S-1-5-21-{domain}-518": "Schema Admins",  # Schema Admins
            "S-1-5-21-{domain}-519": "Enterprise Admins",  # Enterprise Admins
            "S-1-5-21-{domain}-526": "Key Admins",  # Key Admins (Windows Server 2016+)
            "S-1-5-21-{domain}-527": "Enterprise Key Admins",  # Enterprise Key Admins (Windows Server 2016+)
            "S-1-5-21-{domain}-500": "Administrator",  # Built-in Administrator account
            # Additional AdminSDHolder protected groups (lower privilege but still Tier 0)
            "S-1-5-32-551": "Backup Operators",  # Backup Operators
            "S-1-5-32-549": "Server Operators",  # Server Operators
            "S-1-5-32-548": "Account Operators",  # Account Operators
            "S-1-5-32-550": "Print Operators",  # Print Operators
        }

        # Create a mapping of SID to display name for output
        sid_to_name = {}
        if len(group_sids) == len(group_names):
            sid_to_name = dict(zip(group_sids, group_names, strict=False))

        matching_tier0_groups = []

        for group_sid in group_sids:
            group_sid_upper = group_sid.upper()

            # Check against well-known Tier 0 SIDs
            for tier0_sid_pattern, default_name in TIER0_SIDS.items():
                if tier0_sid_pattern.startswith("S-1-5-21-{domain}"):
                    # Domain-relative SID - extract the pattern
                    # e.g., S-1-5-21-{domain}-512 matches S-1-5-21-1234567890-1234567890-1234567890-512
                    rid = tier0_sid_pattern.split("-")[-1]  # Get the RID (512, 519, etc.)
                    if group_sid_upper.startswith("S-1-5-21-") and group_sid_upper.endswith(f"-{rid}"):
                        # Use the display name from BloodHound if available, otherwise use default
                        display_name = sid_to_name.get(group_sid, default_name)
                        matching_tier0_groups.append(display_name)
                        break
                elif group_sid_upper == tier0_sid_pattern.upper():
                    # Exact SID match (builtin groups like Administrators)
                    display_name = sid_to_name.get(group_sid, default_name)
                    matching_tier0_groups.append(display_name)
                    break

        if matching_tier0_groups:
            tier0_reasons.append("TIER0 Group Membership")

        return len(tier0_reasons) > 0, tier0_reasons

    def analyze_password_age(self, username, task_date):
        """Simple password analysis for DPAPI dump viability"""
        if not username or not task_date or not self.loaded:
            return "UNKNOWN", "Insufficient data for password age analysis"

        val = username.strip()
        user_data = None

        # Look up user data
        if val.upper().startswith("S-1-5-"):
            user_data = self.hv_sids.get(val)
        else:
            sam = val.split("\\", 1)[1].lower() if "\\" in val else val.lower()
            user_data = self.hv_users.get(sam)

        if not user_data:
            return "UNKNOWN", "User not found in BloodHound data"

        # For NetExec, enhanced password analysis with proper date comparison
        pwdlastset = user_data.get("pwdlastset")
        if not pwdlastset:
            return "UNKNOWN", "Password change date not available in BloodHound data"

        try:
            # Parse task date (format: 2025-09-18T23:04:37.3089851)
            task_dt = datetime.fromisoformat(task_date.replace("Z", "+00:00"))
            if task_dt.tzinfo is None:
                task_dt = task_dt.replace(tzinfo=timezone.utc)

            # Compare dates
            if task_dt < pwdlastset:
                return "BAD", "Password changed AFTER task creation, Password could be stale"
            else:
                return "GOOD", "Password changed BEFORE task creation, password is valid!"
        except (ValueError, TypeError) as e:
            return "UNKNOWN", f"Date parsing error: {e}"

    def get_user_data(self, username):
        """Get full user data for a username"""
        if not self.loaded:
            return None
        return self.hv_users.get(username.lower())


def parse_task_xml(xml_content):
    """Parse Windows Task Scheduler XML content."""
    result = {"runas": None, "author": None, "date": None, "command": None, "arguments": None, "logon_type": None, "enabled": None}

    if not xml_content:
        return result

    try:
        # Handle encoding declaration issues by removing XML declaration if present
        if xml_content.startswith(b"<?xml"):
            # Find the end of the XML declaration
            declaration_end = xml_content.find(b"?>")
            if declaration_end != -1:
                xml_content = xml_content[declaration_end + 2 :].lstrip()

        root = ET.fromstring(xml_content)

        # Use wildcard namespace approach to find elements
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1]  # Get tag name without namespace

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
        # If XML parsing fails, return empty result
        pass

    return result


def looks_like_domain_user(runas: str) -> bool:
    """Check if a RunAs value looks like a domain user"""
    if not runas:
        return False

    runas_lower = runas.lower().strip()

    # Skip system accounts early
    if any(runas_lower.startswith(prefix) for prefix in KNOWN_SYSTEM_ACCOUNTS) or runas_lower.endswith("$"):
        return False

    # Check for explicitly domain-qualified users (most common case)
    if "\\" in runas_lower:
        return True

    # Check for UPN format (user@domain.com)
    if "@" in runas_lower and "." in runas_lower:
        return True

    # In domain environments, these local accounts are often domain admin equivalents
    return runas_lower in KNOWN_ADMIN_ACCOUNTS


class NXCModule:
    """
    TaskHound - Windows Privileged Scheduled Task Discovery Tool

    Module by 0xr0BIT (original TaskHound) - Adapted for NetExec

    Enumerates Windows scheduled tasks over SMB and identifies tasks that:
    - Run in the context of privileged accounts (high-value users from BloodHound)
    - Store credentials (Password logon type vs S4U/Token)
    - Use domain accounts rather than system accounts
    """

    name = "taskhound"
    description = "Enumerate Windows scheduled tasks and identify privileged tasks with stored credentials"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        BH_DATA         Path to BloodHound CSV/JSON export with high-value users (SamAccountName, SID columns required)
        INCLUDE_MS      Include Microsoft scheduled tasks (WARNING: very slow, disabled by default)
        UNSAVED_CREDS   Show tasks without stored credentials (disabled by default)
        BACKUP_DIR      Directory to save raw XML task files for offline analysis
        SHOW_ALL        Show all tasks, not just domain user tasks (disabled by default)
        OUTPUT          Directory to save output files (supports multiple formats: plain,csv,json)
        OUTPUT_FORMATS  Comma-separated list of output formats: plain,csv,json (default: plain)

        Example:
        nxc smb 192.168.1.100 -u user -p pass -M taskhound
        nxc smb 192.168.1.100 -u user -p pass -M taskhound -o BH_DATA=/tmp/high_value_users.csv
        nxc smb 192.168.1.100 -u user -p pass -M taskhound -o INCLUDE_MS=true UNSAVED_CREDS=true
        nxc smb 192.168.1.100 -u user -p pass -M taskhound -o OUTPUT=/tmp/taskhound_results OUTPUT_FORMATS=csv,json
        """
        self.bh_data_path = module_options.get("BH_DATA")
        self.include_ms = module_options.get("INCLUDE_MS", "").lower() in ("true", "yes", "1")
        self.show_unsaved_creds = module_options.get("UNSAVED_CREDS", "").lower() in ("true", "yes", "1")
        self.backup_dir = module_options.get("BACKUP_DIR")
        self.show_all = module_options.get("SHOW_ALL", "").lower() in ("true", "yes", "1")
        self.output_dir = module_options.get("OUTPUT")
        self.output_formats = [f.strip().lower() for f in module_options.get("OUTPUT_FORMATS", "plain").split(",")]

        # Initialize high-value loader
        self.hv_loader = None
        if self.bh_data_path:
            self.hv_loader = HighValueLoader(self.bh_data_path)
            if not self.hv_loader.load():
                context.log.fail(f"Failed to load BloodHound data from {self.bh_data_path}")
                self.hv_loader = None
            else:
                context.log.success(f"Loaded {len(self.hv_loader.hv_users)} high-value users from BloodHound export ({self.hv_loader.format_type} format)")

    def on_admin_login(self, context, connection):
        """Execute TaskHound enumeration on admin login"""
        if not connection.admin_privs:
            context.log.fail("Administrative privileges required for task enumeration")
            return

        context.log.display("Starting scheduled task enumeration...")

        if not self.include_ms:
            context.log.info("Skipping \\Microsoft tasks for speed (use INCLUDE_MS=true to include)")
        else:
            context.log.info("Including \\Microsoft tasks (this may be slow!)")

        try:
            # Crawl tasks using SMB connection
            tasks = self._crawl_tasks(connection, context)

            if not tasks:
                context.log.fail("No scheduled tasks found or accessible")
                return

            context.log.success(f"Found {len(tasks)} scheduled task files")

            # Process and analyze tasks
            results = self._process_tasks(tasks, context, connection.host)

            # Display results
            self._display_results(results, context)

            # Save backup if requested
            if self.backup_dir:
                self._save_backup(tasks, context, connection.host)

            # Save output files if requested
            if self.output_dir:
                self._save_output_files(results, context, connection.host)

        except Exception as e:
            context.log.fail(f"Error during task enumeration: {e}")
            if context.log.debug:
                context.log.exception(f"TaskHound error: {e}")

    def _crawl_tasks(self, connection, context) -> list[tuple[str, bytes]]:
        """Crawl scheduled tasks directory and collect XML files"""
        results = []

        def recurse(cur_path: str):
            try:
                # List directory contents
                files = connection.conn.listPath(DEFAULT_SHARE, cur_path + "\\*")

                for file_info in files:
                    name = file_info.get_longname()
                    if name in (".", ".."):
                        continue

                    full_path = cur_path + "\\" + name

                    if file_info.is_directory():
                        # Skip Microsoft subtree unless explicitly requested
                        if not self.include_ms and name.lower() == "microsoft" and cur_path.lower().endswith("windows\\system32\\tasks"):
                            context.log.info("Skipping \\Microsoft directory")
                            continue
                        # Recurse into subdirectory
                        recurse(full_path)
                    else:
                        # Read task XML file
                        try:
                            buff = io.BytesIO()
                            connection.conn.getFile(DEFAULT_SHARE, full_path, buff.write)
                            xml_data = buff.getvalue()

                            # Normalize path (remove leading backslash)
                            rel_path = full_path[1:] if full_path.startswith("\\") else full_path
                            results.append((rel_path, xml_data))

                        except Exception as e:
                            context.log.debug(f"Failed to read {full_path}: {e}")

            except Exception as e:
                context.log.debug(f"Error listing {cur_path}: {e}")

        try:
            recurse(TASK_ROOT_PATH)
        except Exception as e:
            context.log.fail(f"Error crawling tasks directory: {e}")

        return results

    def _process_tasks(self, tasks: list[tuple[str, bytes]], context, hostname: str) -> list[dict]:
        #         """Process task XML files and extract relevant information"""
        results = []

        for rel_path, xml_data in tasks:
            try:
                # Parse task XML
                meta = parse_task_xml(xml_data)

                # Skip tasks without RunAs user (early validation)
                runas = meta.get("runas")
                if not runas:
                    continue

                # Build base task data
                task_data = self._build_task_data(meta, hostname, rel_path)

                # Apply BloodHound analysis if available
                if self.hv_loader:
                    self._apply_bloodhound_analysis(task_data)

                # Apply filtering rules
                if self._should_exclude_task(task_data):
                    continue

                results.append(task_data)

            except Exception as e:
                context.log.debug(f"Error processing task {rel_path}: {e}")

        return results

    def _build_task_data(self, meta: dict, hostname: str, rel_path: str) -> dict:
        # Build base task data structure
        # Determine credential storage status
        logon_type = (meta.get("logon_type") or "").strip().lower()
        has_stored_creds = logon_type == "password" or logon_type not in NO_CREDS_LOGON_TYPES

        return {
            "host": hostname,
            "path": rel_path,
            "runas": meta.get("runas"),
            "command": meta.get("command"),
            "arguments": meta.get("arguments"),
            "author": meta.get("author"),
            "date": meta.get("date"),
            "logon_type": meta.get("logon_type"),
            "enabled": meta.get("enabled"),
            "is_domain_user": looks_like_domain_user(meta.get("runas", "")),
            "has_stored_creds": has_stored_creds,
            "is_high_value": False,
            "is_tier0": False,
            "password_analysis": None,
        }

    def _apply_bloodhound_analysis(self, task_data: dict) -> None:
        #         """Apply BloodHound analysis to task data"""
        runas = task_data["runas"]
        if not runas:
            return

        # Extract username (remove domain prefix for lookup)
        username = runas.split("\\")[-1]
        task_data["is_high_value"] = self.hv_loader.is_high_value(username)

        # Check Tier 0 status
        is_tier0, tier0_reasons = self.hv_loader.check_tier0(runas)
        task_data["is_tier0"] = is_tier0
        task_data["tier0_reasons"] = tier0_reasons

        # Add password analysis for tasks with stored credentials
        if task_data["has_stored_creds"]:
            risk_level, pwd_analysis = self.hv_loader.analyze_password_age(runas, task_data["date"])
            if risk_level != "UNKNOWN":
                task_data["password_analysis"] = pwd_analysis

    def _should_exclude_task(self, task_data: dict) -> bool:
        # Determine if task should be excluded based on filtering rules
        # Filter non-domain users (unless show_all is enabled)
        if not self.show_all and not task_data["is_domain_user"]:
            return True

        # Filter tasks without stored credentials (unless show_unsaved_creds is enabled)
        return bool(not self.show_unsaved_creds and not task_data["has_stored_creds"])

    def _save_output_files(self, results: list[dict], context, hostname: str):
        # Save results to output files in specified formats
        from pathlib import Path
        from datetime import datetime

        try:
            # Create output directory if it doesn't exist
            output_path = Path(self.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Generate timestamp for unique filenames
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"taskhound_{hostname}_{timestamp}"

            # Save in requested formats
            for fmt in self.output_formats:
                if fmt == "plain":
                    self._save_plain_text(results, output_path, base_filename, context, hostname)
                elif fmt == "csv":
                    self._save_csv(results, output_path, base_filename, context)
                elif fmt == "json":
                    self._save_json(results, output_path, base_filename, context)
                else:
                    context.log.warning(f"Unknown output format: {fmt}")

        except Exception as e:
            context.log.fail(f"Error saving output files: {e}")

    def _save_plain_text(self, results: list[dict], output_path, base_filename: str, context, hostname: str):
        """Save results in plain text format (similar to console output)"""
        from datetime import datetime

        filename = output_path / f"{base_filename}.txt"

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"TaskHound Results for {hostname}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Found {len(results)} interesting scheduled tasks\n")
                f.write("=" * 80 + "\n\n")

                for result in results:
                    # Determine tier status
                    tier_prefix = ""
                    if result.get("is_tier0"):
                        tier_prefix = "[TIER-0] "
                    elif result.get("is_high_value"):
                        tier_prefix = "[PRIV] "

                    f.write(f"        {tier_prefix}{result['path']}\n")
                    f.write(f"        Enabled : {result.get('enabled', 'N/A')}\n")
                    f.write(f"        RunAs   : {result.get('runas', 'N/A')}\n")

                    # Build command string
                    command = result.get("command", "")
                    arguments = result.get("arguments", "")
                    what = f"{command} {arguments}".strip() if arguments else command
                    f.write(f"        What    : {what or 'N/A'}\n")

                    f.write(f"        Author  : {result.get('author', 'N/A')}\n")
                    f.write(f"        Date    : {result.get('date', 'N/A')}\n")

                    # Add tier 0 reasons if applicable
                    if result.get("is_tier0") and result.get("tier0_reasons"):
                        f.write(f"        Reason  : {'; '.join(result['tier0_reasons'])}\n")

                    # Add password analysis if available
                    if result.get("password_analysis"):
                        f.write(f"        Password Analysis : {result['password_analysis']}\n")
                        f.write("        Next Step: Try DPAPI Dump / Task Manipulation\n")

                    f.write("\n")

            context.log.success(f"Plain text results saved to: {filename}")

        except Exception as e:
            context.log.fail(f"Error saving plain text file: {e}")

    def _save_csv(self, results: list[dict], output_path, base_filename: str, context):
        #         """Save results in CSV format"""
        import csv

        filename = output_path / f"{base_filename}.csv"

        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                if not results:
                    f.write("No tasks found\n")
                    return

                # Define CSV columns
                fieldnames = ["host", "path", "enabled", "runas", "command", "arguments", "author", "date", "logon_type", "is_domain_user", "is_high_value", "is_tier0", "tier0_reasons", "has_stored_creds", "password_analysis"]

                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for result in results:
                    # Prepare row data
                    row = {}
                    for field in fieldnames:
                        if field == "tier0_reasons" and result.get(field):
                            row[field] = "; ".join(result[field])
                        else:
                            row[field] = result.get(field, "")
                    writer.writerow(row)

            context.log.success(f"CSV results saved to: {filename}")

        except Exception as e:
            context.log.fail(f"Error saving CSV file: {e}")

    def _save_json(self, results: list[dict], output_path, base_filename: str, context):
        #         """Save results in JSON format"""
        import json
        from datetime import datetime

        filename = output_path / f"{base_filename}.json"

        try:
            # Prepare JSON data with metadata
            json_data = {"metadata": {"tool": "TaskHound", "version": "1.0", "generated": datetime.now().isoformat(), "host": results[0].get("host") if results else None, "task_count": len(results)}, "tasks": results}

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, default=str)

            context.log.success(f"JSON results saved to: {filename}")

        except Exception as e:
            context.log.fail(f"Error saving JSON file: {e}")

    def _display_results(self, results: list[dict], context):
        #         """Display enumeration results"""
        if not results:
            context.log.fail("No interesting scheduled tasks found")
            return

        # Count privileged tasks
        high_value_count = sum(1 for r in results if r["is_high_value"] and r["has_stored_creds"])
        tier0_count = sum(1 for r in results if r["is_tier0"] and r["has_stored_creds"])

        context.log.success(f"Found {len(results)} interesting scheduled tasks")
        if self.hv_loader:
            context.log.success(f"Found {high_value_count} HIGH-VALUE tasks with stored credentials")
            if tier0_count > 0:
                context.log.success(f"Found {tier0_count} TIER 0 tasks with stored credentials")

        # Sort results: TIER 0 first, then HIGH-VALUE, then normal tasks
        def sort_key(task):
            if task["is_tier0"] and task["has_stored_creds"]:
                return (0, task["path"])  # TIER 0 tasks first
            elif task["is_high_value"] and task["has_stored_creds"]:
                return (1, task["path"])  # HIGH-VALUE tasks second
            else:
                return (2, task["path"])  # Normal tasks last

        results.sort(key=sort_key)

        # Display individual tasks
        for row in results:
            self._display_task(row, context)

    def _display_task(self, row: dict, context):
        #         """Display individual task information in the new format"""
        path = row["path"]
        runas = row["runas"]
        command = row["command"] or ""
        arguments = row["arguments"] or ""
        author = row["author"] or "N/A"
        date = row["date"] or "N/A"
        enabled = row["enabled"] or "N/A"

        # Determine task type and priority
        is_privileged = row["is_high_value"] and row["has_stored_creds"]
        is_tier0_task = row["is_tier0"] and row["has_stored_creds"]

        if is_tier0_task:
            task_type = "[TIER-0]"
            log_method = context.log.highlight
        elif is_privileged:
            task_type = "[PRIV]"
            log_method = context.log.highlight
        else:
            task_type = "[TASK]"
            log_method = context.log.display

        # Build command line
        what = command
        if arguments:
            what += f" {arguments}"

        # Display task with new format
        log_method(f"\n                                                   {task_type} {path}")

        # Format enabled status
        enabled_display = enabled.capitalize() if enabled and enabled.lower() in ["true", "false"] else enabled
        log_method(f"        Enabled : {enabled_display}")

        log_method(f"        RunAs   : {runas}")
        log_method(f"        What    : {what}")
        log_method(f"        Author  : {author}")
        log_method(f"        Date    : {date}")

        # Display reason for privileged tasks
        if is_tier0_task:
            tier0_reasons = row.get("tier0_reasons", [])
            if tier0_reasons:
                reason = "; ".join(tier0_reasons)
                log_method(f"        Reason  : {reason}")
            else:
                log_method("        Reason  : Tier 0 user with stored credentials")
        elif is_privileged:
            log_method("        Reason  : High-value user with stored credentials")

        # Display password analysis if available
        password_analysis = row.get("password_analysis")
        if password_analysis:
            log_method(f"        Password Analysis : {password_analysis}")

        # Display next step for privileged tasks with stored creds
        if (is_tier0_task or is_privileged) and row["has_stored_creds"]:
            log_method("        Next Step: Try DPAPI Dump / Task Manipulation")

    def _save_backup(self, tasks: list[tuple[str, bytes]], context, hostname: str):
        #         """Save raw XML files for offline analysis"""
        try:
            backup_path = Path(self.backup_dir) / hostname
            backup_path.mkdir(parents=True, exist_ok=True)

            saved_count = 0
            for rel_path, xml_data in tasks:
                # Create full file path
                file_path = backup_path / rel_path.replace("\\", "/")
                file_path.parent.mkdir(parents=True, exist_ok=True)

                # Save XML content
                file_path.write_bytes(xml_data)
                saved_count += 1

            context.log.success(f"Saved {saved_count} task XML files to {backup_path}")

        except Exception as e:
            context.log.fail(f"Error saving backup files: {e}")
