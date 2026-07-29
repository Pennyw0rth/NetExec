import os
import json
import tempfile
from nxc.helpers.misc import CATEGORY
from nxc.paths import DATA_PATH

SKIP_SHARES = {"ADMIN$", "IPC$", "print$", "NETLOGON", "SYSVOL"}
DEFAULT_EXTENSIONS_FILE = os.path.join(DATA_PATH, "sensitive_extensions.txt")
_CONFIG_FILE = os.path.join(tempfile.gettempdir(), ".nxc_sensitive_files_config.json")


def load_extensions_from_file(filepath):
    extensions = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    extensions.append(line)
    except FileNotFoundError:
        pass
    return extensions


def _write_config(cfg):
    with open(_CONFIG_FILE, "w") as f:
        json.dump(cfg, f)


def _read_config():
    try:
        with open(_CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"extensions": None, "max_depth": 5, "output_dir": None, "target_share": None}


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

    def __init__(self):
        self.findings = []

    def options(self, context, module_options):
        """
        EXTENSIONS   (not set) = built-in list | /path/to/file.txt | .ext1,.ext2
        MAX_DEPTH    Recursion depth (default: 5)
        OUTPUT_DIR   Directory to save per-host result files
        SHARE        Only scan a specific share
        """
        cfg = {}

        if "EXTENSIONS" not in module_options:
            cfg["extensions"] = None
        else:
            ext_val = module_options["EXTENSIONS"].strip("'\" ")
            if os.path.isfile(ext_val):
                cfg["extensions"] = load_extensions_from_file(ext_val)
            else:
                cfg["extensions"] = [e.strip().lower() for e in ext_val.split(",")]

        cfg["max_depth"] = int(module_options.get("MAX_DEPTH", 5))
        cfg["output_dir"] = module_options.get("OUTPUT_DIR", None)
        cfg["target_share"] = module_options.get("SHARE", None)

        _write_config(cfg)

    def on_admin_login(self, context, connection):
        self._run(context, connection)

    def on_login(self, context, connection):
        self._run(context, connection)

    def _run(self, context, connection):
        host = connection.host
        self.findings = []

        cfg = _read_config()
        extensions = cfg["extensions"] if cfg["extensions"] is not None else load_extensions_from_file(DEFAULT_EXTENSIONS_FILE)
        max_depth = cfg["max_depth"]
        output_dir = cfg["output_dir"]
        target_share = cfg["target_share"]

        try:
            shares = connection.conn.listShares()
        except Exception as e:
            context.log.fail(f"Could not list shares: {e}")
            return

        for share in shares:
            share_name = share["shi1_netname"].rstrip("\x00")
            if target_share and share_name.lower() != target_share.lower():
                continue
            if share_name in SKIP_SHARES:
                continue
            context.log.display(f"Scanning share: {share_name}")
            try:
                self._crawl(context, connection, share_name, "", 0, extensions, max_depth)
            except Exception as e:
                context.log.warning(f"Could not access {share_name}: {e}")

        if self.findings:
            context.log.success(f"Found {len(self.findings)} sensitive file(s) on {host}:")
            for f in self.findings:
                context.log.highlight(f)
            if output_dir:
                try:
                    os.makedirs(output_dir, exist_ok=True)
                    out_path = os.path.join(output_dir, f"{host}.txt")
                    with open(out_path, "a") as out:
                        for f in self.findings:
                            out.write(f + "\n")
                    context.log.success(f"Results saved to {out_path}")
                except Exception as e:
                    context.log.warning(f"Could not write output: {e}")
        else:
            context.log.info(f"No sensitive files found on {host}")

    def _crawl(self, context, connection, share, path, depth, extensions, max_depth):
        if depth > max_depth:
            return
        try:
            list_path = path + r"\*" if path else r"\*"
            entries = connection.conn.listPath(share, list_path)
        except Exception as crawl_err:
            context.log.debug(f"listPath error on {share}{path}: {crawl_err}")
            return
        for entry in entries:
            filename = entry.get_longname()
            if filename in (".", ".."):
                continue
            full_path = f"{path}\\{filename}" if path else f"\\{filename}"
            if entry.is_directory():
                self._crawl(context, connection, share, full_path, depth + 1, extensions, max_depth)
            else:
                _, ext = os.path.splitext(filename.lower())
                if ext and ext in set(extensions):
                    finding = f"\\\\{connection.host}\\{share}{full_path}"
                    self.findings.append(finding)
                    context.log.highlight(f"[{share}] {full_path}")
