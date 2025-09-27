#!/usr/bin/env python3

import io
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from nxc.helpers.misc import CATEGORY


class HighValueLoader:
    """Load and query high-value users from BloodHound export (CSV or JSON)"""

    def __init__(self, path: str):
        self.path = path
        self.hv_users: dict[str, dict[str, Any]] = {}
        self.hv_sids: dict[str, dict[str, Any]] = {}
        self.loaded = False

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
        """Load from JSON format"""
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            sam = item.get("samaccountname") or item.get("SamAccountName")
            sid = item.get("sid") or item.get("SID") or item.get("objectid")

            if sam and sid:
                sam = sam.split("\\")[-1].lower()  # Remove domain prefix
                self.hv_users[sam] = {"sid": sid}
                self.hv_sids[sid] = {"sam": sam}

        self.loaded = True
        return True

    def _load_csv(self) -> bool:
        """Load from CSV format"""
        with open(self.path, encoding="utf-8-sig") as f:  # Handle BOM
            reader = csv.DictReader(f)

            for row in reader:
                # Find SamAccountName column (case-insensitive)
                sam = None
                sid = None
                for key, value in row.items():
                    if key.lower() in ("samaccountname", "sam"):
                        sam = value
                    elif key.lower() in ("sid", "objectid"):
                        sid = value

                if sam and sid:
                    sam = sam.split("\\")[-1].lower()  # Remove domain prefix
                    self.hv_users[sam] = {"sid": sid}
                    self.hv_sids[sid] = {"sam": sam}

        self.loaded = True
        return True

    def is_high_value(self, username: str) -> bool:
        """Check if a username is high-value"""
        if not self.loaded:
            return False
        return username.lower() in self.hv_users


def parse_task_xml(xml_content):
    """Parse Windows Task Scheduler XML content."""
    result = {"runas": None, "author": None, "date": None, "command": None, "arguments": None, "logon_type": None}

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

    except ET.ParseError:
        # If XML parsing fails, return empty result
        pass

    return result


def looks_like_domain_user(runas: str) -> bool:
    """Check if a RunAs value looks like a domain user"""
    if not runas:
        return False
    runas = runas.lower()
    has_domain_separator = "\\" in runas
    not_nt_account = not runas.startswith("nt ")
    not_builtin_account = not runas.startswith("builtin\\")
    not_computer_account = not runas.endswith("$")  # Computer accounts
    return has_domain_separator and not_nt_account and not_builtin_account and not_computer_account


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

        Example:
        nxc smb 192.168.1.100 -u user -p pass -M taskhound
        nxc smb 192.168.1.100 -u user -p pass -M taskhound -o BH_DATA=/tmp/high_value_users.csv
        nxc smb 192.168.1.100 -u user -p pass -M taskhound -o INCLUDE_MS=true UNSAVED_CREDS=true
        """
        self.bh_data_path = module_options.get("BH_DATA")
        self.include_ms = module_options.get("INCLUDE_MS", "").lower() in ("true", "yes", "1")
        self.show_unsaved_creds = module_options.get("UNSAVED_CREDS", "").lower() in ("true", "yes", "1")
        self.backup_dir = module_options.get("BACKUP_DIR")
        self.show_all = module_options.get("SHOW_ALL", "").lower() in ("true", "yes", "1")

        # Initialize high-value loader
        self.hv_loader = None
        if self.bh_data_path:
            self.hv_loader = HighValueLoader(self.bh_data_path)
            if not self.hv_loader.load():
                context.log.fail(f"Failed to load BloodHound data from {self.bh_data_path}")
                self.hv_loader = None
            else:
                context.log.success(f"Loaded {len(self.hv_loader.hv_users)} high-value users from BloodHound export")

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

        except Exception as e:
            context.log.fail(f"Error during task enumeration: {e}")
            if context.log.debug:
                context.log.exception(f"TaskHound error: {e}")

    def _crawl_tasks(self, connection, context) -> list[tuple[str, bytes]]:
        """Crawl scheduled tasks directory and collect XML files"""
        results = []
        share = "C$"
        task_root = "\\Windows\\System32\\Tasks"

        def recurse(cur_path: str):
            try:
                # List directory contents
                files = connection.conn.listPath(share, cur_path + "\\*")

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
                            connection.conn.getFile(share, full_path, buff.write)
                            xml_data = buff.getvalue()

                            # Normalize path (remove leading backslash)
                            rel_path = full_path[1:] if full_path.startswith("\\") else full_path
                            results.append((rel_path, xml_data))

                        except Exception as e:
                            context.log.debug(f"Failed to read {full_path}: {e}")

            except Exception as e:
                context.log.debug(f"Error listing {cur_path}: {e}")

        try:
            recurse(task_root)
        except Exception as e:
            context.log.fail(f"Error crawling tasks directory: {e}")

        return results

    def _process_tasks(self, tasks: list[tuple[str, bytes]], context, hostname: str) -> list[dict]:
        """Process task XML files and extract relevant information"""
        results = []

        for rel_path, xml_data in tasks:
            try:
                # Parse task XML
                meta = parse_task_xml(xml_data)

                if not meta.get("runas"):
                    continue

                # Build result row
                row = {
                    "host": hostname,
                    "path": rel_path,
                    "runas": meta.get("runas"),
                    "command": meta.get("command"),
                    "arguments": meta.get("arguments"),
                    "author": meta.get("author"),
                    "date": meta.get("date"),
                    "logon_type": meta.get("logon_type"),
                    "is_domain_user": looks_like_domain_user(meta.get("runas", "")),
                    "is_high_value": False,
                    "has_stored_creds": False,
                }

                # Determine if credentials are stored
                logon_type = (meta.get("logon_type") or "").strip().lower()
                if logon_type == "password":
                    row["has_stored_creds"] = True
                elif logon_type in ("interactive", "interactivetoken", "s4u"):
                    row["has_stored_creds"] = False
                else:
                    # Unknown logon type, assume stored creds for safety
                    row["has_stored_creds"] = True

                # Check if high-value user
                if self.hv_loader and row["runas"]:
                    username = row["runas"].split("\\")[-1]  # Remove domain prefix
                    row["is_high_value"] = self.hv_loader.is_high_value(username)

                # Apply filtering
                if not self.show_all and not row["is_domain_user"]:
                    continue

                if not self.show_unsaved_creds and not row["has_stored_creds"]:
                    continue

                results.append(row)

            except Exception as e:
                context.log.debug(f"Error processing task {rel_path}: {e}")

        return results

    def _display_results(self, results: list[dict], context):
        """Display enumeration results"""
        if not results:
            context.log.fail("No interesting scheduled tasks found")
            return

        # Count privileged tasks
        high_value_count = sum(1 for r in results if r["is_high_value"] and r["has_stored_creds"])

        context.log.success(f"Found {len(results)} interesting scheduled tasks")
        if self.hv_loader:
            context.log.success(f"Found {high_value_count} HIGH-VALUE tasks with stored credentials")

        # Display individual tasks
        for row in results:
            self._display_task(row, context)

    def _display_task(self, row: dict, context):
        """Display individual task information"""
        path = row["path"]
        runas = row["runas"]
        command = row["command"] or ""
        arguments = row["arguments"] or ""
        author = row["author"] or "N/A"
        date = row["date"] or "N/A"

        # Determine task type
        is_privileged = row["is_high_value"] and row["has_stored_creds"]
        task_type = "[HIGH-VALUE]" if is_privileged else "[TASK]"

        # Build command line
        full_command = command
        if arguments:
            full_command += f" {arguments}"

        # Display task header with proper alignment
        if is_privileged:
            context.log.highlight(f"\n                                        [HIGH-VALUE] {path}")
            context.log.highlight(f"RunAs    : {runas}")
            context.log.highlight(f"Command  : {full_command}")
            context.log.highlight(f"Author   : {author}")
            context.log.highlight(f"Date     : {date}")
            if row["has_stored_creds"]:
                context.log.highlight("Creds    : STORED (Password logon)")
            else:
                context.log.highlight("Creds    : NOT STORED (Token/S4U logon)")
            context.log.highlight("Reason   : High-value user with stored credentials")
        else:
            context.log.display(f"\n                                          {task_type} {path}")
            context.log.display(f"RunAs    : {runas}")
            context.log.display(f"Command  : {full_command}")
            context.log.display(f"Author   : {author}")
            context.log.display(f"Date     : {date}")
            if row["has_stored_creds"]:
                context.log.display("Creds    : STORED (Password logon)")
            else:
                context.log.display("Creds    : NOT STORED (Token/S4U logon)")

    def _save_backup(self, tasks: list[tuple[str, bytes]], context, hostname: str):
        """Save raw XML files for offline analysis"""
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
