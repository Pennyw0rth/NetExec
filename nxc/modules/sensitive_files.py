
import os
from nxc.helpers.misc import CATEGORY

SKIP_SHARES = {"ADMIN$", "IPC$", "print$", "NETLOGON", "SYSVOL"}

DEFAULT_EXTENSIONS = [
    ".kdbx", ".pfx", ".p12", ".pem", ".key", ".ppk",
    ".ovpn", ".config", ".conf", ".cfg", ".xml",
    ".ini", ".env", ".rdp", ".id_rsa", ".vnc",
]


class NXCModule:
    """
    Crawl all readable SMB shares and flag files with sensitive extensions.
    Author: Char0n1507
    """

    name = "sensitive_files"
    description = "Find files with sensitive extensions across all readable SMB shares"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        EXTENSIONS   Comma-separated extensions to hunt (default: built-in list)
        MAX_DEPTH    Recursion depth (default: 5)
        OUTPUT       Save results to file path (optional)
        SHARE        Only scan a specific share (optional)
        """
        if "EXTENSIONS" in module_options:
            self.extensions = [e.strip().lower() for e in module_options["EXTENSIONS"].split(",")]
        else:
            self.extensions = DEFAULT_EXTENSIONS

        self.max_depth = int(module_options.get("MAX_DEPTH", 5))
        self.output_file = module_options.get("OUTPUT", None)
        self.target_share = module_options.get("SHARE", None)
        self.findings = []

    def on_admin_login(self, context, connection):
        self._run(context, connection)

    def on_login(self, context, connection):
        self._run(context, connection)

    def _run(self, context, connection):
        host = connection.host
        self.findings = []

        try:
            shares = connection.conn.listShares()
        except Exception as e:
            context.log.fail(f"Could not list shares: {e}")
            return

        for share in shares:
            share_name = share["shi1_netname"].rstrip("\x00")

            if self.target_share and share_name.lower() != self.target_share.lower():
                continue

            if share_name in SKIP_SHARES:
                continue

            context.log.display(f"Scanning share: {share_name}")
            try:
                self._crawl(context, connection, share_name, "", 0)
            except Exception as e:
                context.log.warning(f"Could not access {share_name}: {e}")

        if self.findings:
            context.log.success(f"Found {len(self.findings)} sensitive file(s) on {host}:")
            for f in self.findings:
                context.log.highlight(f)

            if self.output_file:
                try:
                    with open(self.output_file, "a") as out:
                        out.write(f"\n[{host}]\n")
                        for f in self.findings:
                            out.write(f + "\n")
                    context.log.success(f"Results saved to {self.output_file}")
                except Exception as e:
                    context.log.warning(f"Could not write output file: {e}")
        else:
            context.log.info(f"No sensitive files found on {host}")

    def _crawl(self, context, connection, share, path, depth):
        if depth > self.max_depth:
            return

        try:
            entries = connection.conn.listPath(share, path + "\\*")
        except Exception:
            return

        for entry in entries:
            filename = entry.get_longname()
            if filename in (".", ".."):
                continue

            full_path = f"{path}\\{filename}" if path else f"\\{filename}"

            if entry.is_directory():
                self._crawl(context, connection, share, full_path, depth + 1)
            else:
                _, ext = os.path.splitext(filename.lower())
                if ext in self.extensions:
                    finding = f"\\\\{connection.host}\\{share}{full_path}"
                    self.findings.append(finding)
                    context.log.highlight(f"[{share}] {full_path}")
