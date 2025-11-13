import xml.etree.ElementTree as ET
from impacket.smbconnection import SMBConnection
from nxc.helpers.misc import CATEGORY

SYSTEM32_PREFIXES = [
    r"C:\Windows\System32",
    r"%SystemRoot%\System32",
    r"%WinDir%\System32",
    r"\SystemRoot\System32",
]

class NXCModule:
    name = "sch_task_enum"
    description = "Enumerate scheduled tasks via SMB; print actions (Exec/Handler) and triggers; supports filters and single-task targeting"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        Module used to enumerate scheduled tasks on a target system

        ROOT             Root path of the task store (default: C:\\Windows\\System32\\Tasks)
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o ROOT="C:\\Windows\\Tasks"

        SUMMARY_ONLY     Show only summary lines (Actions count, ExecOutsideSystem32 count) without detailed action output
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o SUMMARY_ONLY=true

        ONLY_NON_SYSTEM32
                         Display only tasks with at least one Exec action outside System32
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o ONLY_NON_SYSTEM32=true

        EXCLUDE_PREFIX   Exclude tasks under a given prefix (relative under ROOT, e.g., "Microsoft\\Windows")
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o EXCLUDE_PREFIX="Microsoft\\Windows"

        TASKNAME         Target a single task (relative path under ROOT)
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o TASKNAME="connect_bot"
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o TASKNAME="Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker"

        MAX_FILES        Limit the number of task files parsed (default: 5000)
                         nxc smb 192.168.56.11 -u robb.stark -p sexywolfy -M sch_task_enum -o MAX_FILES=100
        """

        # Root path of task store
        self.root = module_options.get("ROOT", "C:\\Windows\\System32\\Tasks")
        # Only display tasks with at least one Exec outside System32
        self.only_non_system32 = str(module_options.get("ONLY_NON_SYSTEM32", "false")).lower() in ("1", "true", "yes")
        # Show only summary lines, suppress detailed printing
        self.summary_only = str(module_options.get("SUMMARY_ONLY", "false")).lower() in ("1", "true", "yes")
        # Exclude tasks under a given prefix (relative under ROOT, e.g., "Microsoft\\Windows")
        self.exclude_prefix = module_options.get("EXCLUDE_PREFIX", "")
        # Single task path relative to ROOT (e.g., "connect_bot" or "Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker")
        self.taskname = module_options.get("TASKNAME", "")
        # Safety throttle
        self.max_files = int(module_options.get("MAX_FILES", "5000"))

    def on_login(self, context, connection):
        try:
            smb = SMBConnection(connection.host, connection.host, sess_port=connection.port)
            if connection.kerberos:
                smb.kerberosLogin(connection.username, "", connection.domain, "", "", lmhash=connection.lmhash, nthash=connection.nthash)
            else:
                smb.login(connection.username, connection.password, connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)
            share, rel_root = self._split_abs_path(self.root)
            if not share:
                context.log.fail(f"[-] Invalid ROOT path: {self.root}")
                return

            # Single task mode
            if self.taskname:
                target_rel = rel_root + ("\\" if not self.taskname.startswith("\\") else "") + self.taskname
                displayed = self._process_task(context, smb, share, target_rel)
                if not displayed:
                    context.log.highlight(f"[!] No output for task: {target_rel}")
                return
            files = self._walk_recursive(context, smb, share, rel_root)
            if not files:
                context.log.highlight("[!] No task files found.")
                return

            context.log.highlight(f"[+] Found {len(files)} task file(s). Parsing XML...")
            count, shown = 0, 0
            exclude_base = (rel_root + "\\" + self.exclude_prefix).lower() if self.exclude_prefix else None

            for rel_file in files:
                if count >= self.max_files:
                    context.log.highlight(f"[!] Reached MAX_FILES={self.max_files} limit, stopping.")
                    break
                count += 1

                if exclude_base and rel_file.lower().startswith(exclude_base):
                    continue

                if self._process_task(context, smb, share, rel_file):
                    shown += 1

            context.log.highlight(f"[+] Completed. Parsed {count} file(s), displayed {shown} task(s).")

        except Exception as e:
            context.log.fail(f"[-] Task enumeration failed: {str(e)}")

    # ---- Processing ---------------------------------------------------------

    def _process_task(self, context, smb, share, rel_file):
        xml_bytes = self._read_file(context, smb, share, rel_file)
        if xml_bytes is None:
            return False

        info = self._parse_task_xml(context, xml_bytes, rel_file)
        if info is None:
            return False

        # Count exec actions outside System32
        outside_count = sum(
            1 for act in info['actions']
            if act['type'] == 'Exec' and self._is_outside_system32(act['command'], act['normalized_command'])
        )

        if self.only_non_system32 and outside_count == 0:
            return False

        self._print_task(context, rel_file, info, outside_count)
        return True

    # ---- SMB helpers --------------------------------------------------------

    def _split_abs_path(self, abs_path):
        """
        Convert absolute path (e.g., C:\\Windows\\System32\\Tasks) to (share='C$', rel='\\Windows\\System32\\Tasks').
        """
        if not abs_path or len(abs_path) < 3 or abs_path[1] != ":":
            return None, None
        drive = abs_path[0].upper()
        share = f"{drive}$"
        rel = abs_path[2:].replace("/", "\\")
        if not rel.startswith("\\"):
            rel = "\\" + rel
        return share, rel

    def _walk_recursive(self, context, smb, share, start_rel):
        """
        Recursively list all files beneath start_rel within the given share.
        """
        results, stack = [], [start_rel]
        while stack:
            current = stack.pop()
            try:
                for f in smb.listPath(share, current + "\\*"):
                    name = f.get_longname() if hasattr(f, "get_longname") else f.get_name()
                    if name in (".", ".."):
                        continue
                    rel_child = (current + "\\" + name).replace("\\\\", "\\")
                    if f.is_directory():
                        stack.append(rel_child)
                    else:
                        results.append(rel_child)
            except Exception as e:
                context.log.fail(f"[-] SMB list failed at {current}: {str(e)}")
        return results

    def _read_file(self, context, smb, share, rel_path):
        """
        Read file via SMB using getFile streaming.
        """
        data = b""
        try:
            def collect(chunk):
                nonlocal data
                data += chunk
            smb.getFile(share, rel_path, collect)
            return data
        except Exception as e:
            context.log.fail(f"[-] Failed to read {rel_path}: {str(e)}")
            return None

    # ---- Task parsing -------------------------------------------------------

    def _parse_task_xml(self, context, xml_bytes, rel_path):
        """
        Parse Task Scheduler XML with namespace-aware selection.
        Extract:
          - RegistrationInfo (Author)
          - Principals (UserId, RunLevel)
          - Actions: Exec (Command, Arguments), ComHandler (ClassId), CustomHandler (text)
          - Triggers: type, repetition interval, start/end
        """
        try:
            text = xml_bytes.decode("utf-8", errors="ignore")
            root = ET.fromstring(text)
        except Exception as e:
            context.log.fail(f"[-] XML parse error in {rel_path}: {str(e)}")
            return None

        ns_uri = root.tag[root.tag.find("{")+1:root.tag.find("}")] if "{" in root.tag else None

        def fnd(elem, tag):
            return elem.find(f"{{{ns_uri}}}{tag}") if ns_uri else elem.find(tag)

        def fal(elem, tag):
            return elem.findall(f"{{{ns_uri}}}{tag}") if ns_uri else elem.findall(tag)

        # Author
        author = None
        reg = fnd(root, "RegistrationInfo") or fnd(root, ".//RegistrationInfo")
        if reg is None:
            reg = fnd(root, "RegistrationInfo")
        if reg is not None:
            a = fnd(reg, "Author")
            author = a.text.strip() if (a is not None and a.text) else None

        # Principal
        user_id, run_level = None, None
        principals = fnd(root, "Principals") or fnd(root, ".//Principals")
        if principals is not None:
            principal = fnd(principals, "Principal")
            if principal is not None:
                uid = fnd(principal, "UserId")
                rl = fnd(principal, "RunLevel")
                user_id = uid.text.strip() if (uid is not None and uid.text) else None
                run_level = rl.text.strip() if (rl is not None and rl.text) else None

        actions = []
        actions_node = fnd(root, "Actions") or fnd(root, ".//Actions")
        if actions_node is not None:
            # Exec
            for exec_action in fal(actions_node, "Exec"):
                cmd = fnd(exec_action, "Command")
                args = fnd(exec_action, "Arguments")
                command = cmd.text.strip() if (cmd is not None and cmd.text) else None
                arguments = args.text.strip() if (args is not None and args.text) else None
                normalized_command = self._normalize_env_paths(command) if command else None
                actions.append({
                    "type": "Exec",
                    "command": command,
                    "normalized_command": normalized_command,
                    "arguments": arguments,
                })
            # ComHandler
            for com_action in fal(actions_node, "ComHandler"):
                clsid = fnd(com_action, "ClassId")
                clsid_text = clsid.text.strip() if (clsid is not None and clsid.text) else None
                actions.append({
                    "type": "ComHandler",
                    "command": f"COMHandler ClassId={clsid_text or 'N/A'}",
                    "normalized_command": None,
                    "arguments": None,
                })
            # CustomHandler
            for custom_action in fal(actions_node, "CustomHandler"):
                raw = (custom_action.text or "").strip() or "N/A"
                actions.append({
                    "type": "CustomHandler",
                    "command": f"CustomHandler {raw}",
                    "normalized_command": None,
                    "arguments": None,
                })

        # Triggers
        triggers = []
        triggers_node = fnd(root, "Triggers") or fnd(root, ".//Triggers")
        if triggers_node is not None:
            for trig in list(triggers_node):
                t_type = trig.tag.split("}")[-1]  # strip namespace
                interval = None
                start = None
                end = None
                repetition = fnd(trig, "Repetition")
                if repetition is not None:
                    intr = fnd(repetition, "Interval")
                    fnd(repetition, "Duration")
                    fnd(repetition, "StopAtDurationEnd")
                    interval = (intr.text.strip() if (intr is not None and intr.text) else None) or None
                startb = fnd(trig, "StartBoundary")
                endb = fnd(trig, "EndBoundary")
                if startb is not None and startb.text:
                    start = startb.text.strip()
                if endb is not None and endb.text:
                    end = endb.text.strip()
                triggers.append({
                    "type": t_type,
                    "interval": interval,  # e.g., PT1M
                    "start": start,
                    "end": end,
                })

        return {
            "author": author,
            "user_id": user_id,
            "run_level": run_level,
            "actions": actions,
            "triggers": triggers,
        }

    # ---- Path normalization and checks -------------------------------------

    def _normalize_env_paths(self, path):
        """
        Normalize common environment variables and slashes to enable System32 checks.
        """
        if path is None:
            return None
        p = path.strip().strip('"')
        replacements = {
            "%SystemRoot%": r"C:\Windows",
            "%WinDir%": r"C:\Windows",
            "%ProgramFiles%": r"C:\Program Files",
            "%ProgramFiles(x86)%": r"C:\Program Files (x86)",
        }
        for k, v in replacements.items():
            p = p.replace(k, v)
        return p.replace("/", "\\")

    def _is_outside_system32(self, raw_cmd, norm_cmd):
        """
        Determine if the executable path is outside System32, using raw and normalized forms.
        Bare filenames (e.g., cmd.exe) are treated as outside to be conservative.
        """
        candidates = []
        if raw_cmd:
            candidates.append(raw_cmd.strip().strip('"').replace("/", "\\"))
        if norm_cmd:
            candidates.append(norm_cmd.strip().replace("/", "\\"))

        for c in candidates:
            exe = c.split(" ")[0]  # consider only the executable
            # No path components: treat as outside
            if "\\" not in exe and ":" not in exe and not exe.lower().startswith(r"\systemroot"):
                return True
            for prefix in SYSTEM32_PREFIXES:
                pref = prefix.lower()
                if exe.lower().startswith(pref + "\\") or exe.lower() == pref:
                    return False
        return True

    # ---- Output -------------------------------------------------------------

    def _print_task(self, context, rel_path, info, outside_count):
        """
        Print summary line and (unless summary_only) full action + trigger details.
        """
        total_actions = len(info['actions'])
        context.log.highlight(f"[+] Task: {rel_path} (Actions={total_actions}, ExecOutsideSystem32={outside_count})")
        context.log.highlight(f"    Author: {info['author'] or 'N/A'}")
        context.log.highlight(f"    Principal: {info['user_id'] or 'N/A'}")
        context.log.highlight(f"    RunLevel: {info['run_level'] or 'N/A'}")

        # Triggers summary (types and intervals)
        if info.get("triggers"):
            # Build concise trigger strings like "TimeTrigger (PT1M), LogonTrigger"
            parts = []
            for t in info["triggers"]:
                label = t["type"]
                if t.get("interval"):
                    label += f" ({t['interval']})"
                parts.append(label)
            context.log.highlight(f"    Triggers: {', '.join(parts)}")

        if self.summary_only:
            return

        if total_actions == 0:
            context.log.highlight("    Actions: None")
            return

        for idx, act in enumerate(info['actions'], 1):
            if act['type'] == "Exec":
                out_of_sys32 = self._is_outside_system32(act['command'], act['normalized_command'])
                status = "OUTSIDE_SYSTEM32" if out_of_sys32 else "SYSTEM32"
                context.log.highlight(f"    Action[{idx}] Exec [{status}]")
                context.log.highlight(f"        Command (raw): {act['command'] or 'N/A'}")
                context.log.highlight(f"        Command (normalized): {act['normalized_command'] or 'N/A'}")
                context.log.highlight(f"        Arguments: {act['arguments'] or 'N/A'}")
            elif act['type'] == "ComHandler":
                context.log.highlight(f"    Action[{idx}] ComHandler")
                context.log.highlight(f"        {act['command']}")
            else:
                context.log.highlight(f"    Action[{idx}] CustomHandler")
                context.log.highlight(f"        {act['command']}")
