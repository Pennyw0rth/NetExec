import paramiko
import os
import re
import uuid
import logging
import time

from nxc.config import process_secret
from nxc.connection import connection, highlight
from nxc.logger import NXCAdapter
from paramiko.ssh_exception import (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
)

# regex to extract allowed auth methods from errors
AUTH_METHODS_REGEX = re.compile(r"allowed types: \[(.*?)\]")

class ssh(connection):
    def __init__(self, args, db, host):
        self.protocol = "SSH"
        self.remote_version = "Unknown SSH Version"
        self.server_os_platform = "Linux"
        self.shell_access = False
        self.admin_privs = False
        self.uac = ""
        self.password_auth_supported = True
        self.auth_methods_cache = {}         # auth methods cache per host
        self.cached_key = None               # cache key_file
        super().__init__(args, db, host)

    def proto_flow(self):
        self.logger.debug("Kicking off proto_flow")
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            if self.remote_version == "Unknown SSH Version":
                self.conn.close()
                return
            # only check password auth if no key_file
            if not hasattr(self.args, "key_file") or not self.args.key_file:
                self.check_password_auth()
            if self.login():
                if hasattr(self.args, "module") and self.args.module:
                    self.load_modules()
                    self.logger.debug("Calling modules")
                    self.call_modules()
                else:
                    self.logger.debug("Calling command arguments")
                    self.call_cmd_args()
                self.conn.close()

    def proto_logger(self):
        logging.getLogger("paramiko").disabled = True
        logging.getLogger("paramiko.transport").disabled = True
        self.logger = NXCAdapter(
            extra={
                "protocol": "SSH",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        self.logger.display(
            self.remote_version if self.remote_version != "Unknown SSH Version" 
            else f"{self.remote_version}, skipping..."
        )

    def enum_host_info(self):
        if self.conn._transport.remote_version:
            self.remote_version = self.conn._transport.remote_version
        self.logger.debug(f"Remote version: {self.remote_version}")
        self.db.add_host(self.host, self.port, self.remote_version)

    def check_password_auth(self):
        """Check if password authentication is supported by directly attempting a connection."""
        cache_key = f"{self.host}:{self.port}"
        if cache_key in self.auth_methods_cache:
            self.password_auth_supported = "password" in self.auth_methods_cache[cache_key]
            self.logger.debug(f"Using cached auth methods: {self.auth_methods_cache[cache_key]}")
            self.logger.debug(f"Password authentication supported (cached): {self.password_auth_supported}")
            return self.password_auth_supported

        self.logger.debug("Checking if password authentication is supported")
        self.password_auth_supported = False

        try:
            test_client = paramiko.SSHClient()
            test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                # Connect with empty pw to force AuthenticationException
                test_client.connect(
                    hostname=self.host,
                    port=self.port,
                    username="test_user",
                    password="",
                    timeout=min(3, self.args.ssh_timeout),
                    look_for_keys=False,
                    allow_agent=False
                )
                self.logger.debug("Empty password authentication succeeded unexpectedly")
            except AuthenticationException as e:
                error_msg = str(e)
                self.logger.debug(f"Authentication exception: {error_msg}")
                if "allowed types" in error_msg.lower():
                    match = AUTH_METHODS_REGEX.search(error_msg)
                    if match:
                        auth_methods = [m.strip("'") for m in match.group(1).split(", ")]
                        self.logger.debug(f"Server reports auth methods: {auth_methods}")
                        self.auth_methods_cache[cache_key] = auth_methods
                        if "password" in auth_methods:
                            self.logger.debug("Server reports password auth is supported, verifying...")
                            self.password_auth_supported = self._verify_password_auth()
                        else:
                            self.logger.debug(f"Password authentication not supported. Allowed methods: {auth_methods}")
                    else:
                        self.logger.debug(f"Could not parse allowed authentication methods from: {error_msg}")
                else:
                    self.logger.debug("Could not determine allowed authentication methods")
            except Exception as e:
                self.logger.debug(f"Error during auth method check: {e!s}")
            finally:
                test_client.close()
        except Exception as e:
            self.logger.debug(f"Error setting up SSH connection for auth method check: {e!s}")
        self.logger.debug(f"Final determination: Password authentication supported: {self.password_auth_supported}")
        return self.password_auth_supported

    def _verify_password_auth(self):
        """Helper function to verify if password authentication is actually enabled."""
        try:
            temp_client = paramiko.SSHClient()
            temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            temp_client.connect(
                hostname=self.host,
                port=self.port,
                username="dummy_user",
                password="dummy_password",
                timeout=min(3, self.args.ssh_timeout),
                look_for_keys=False,
                allow_agent=False
            )
            temp_client.close()
            self.logger.debug("Empty password auth unexpectedly succeeded, marking as enabled")
            return True  # unlikely
        except AuthenticationException as e:
            error_msg = str(e).lower()
            self.logger.debug(f"Password auth dummy attempt exception: {error_msg}")
            # if we get an error like "Permission denied (publickey)" or "no authentication methods available," password auth is off.
            if ("permission denied (publickey)" in error_msg or 
                "no authentication methods available" in error_msg or
                "not allowed" in error_msg or
                "no existing session" in error_msg):
                return False
            return True
        except Exception as e:
            self.logger.debug(f"Error in _verify_password_auth: {e!s}")
            return False

    def create_conn_obj(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.conn.connect(
                self.host,
                port=self.port,
                timeout=min(3, self.args.ssh_timeout),
                look_for_keys=False,
                allow_agent=False
            )
        except (AuthenticationException, SSHException):
            return True
        except (NoValidConnectionsError, OSError):
            return False
        return True

    def plaintext_login(self, username, password, private_key=""):
        self.username = username
        self.password = password
        using_key_auth = bool(self.args.key_file or private_key)
        
        # if password auth is not supported and we're not using key auth, skip login
        if not using_key_auth and not self.password_auth_supported:
            self.logger.fail("Password auth not supported")
            return False
            
        try:
            if using_key_auth:
                self.logger.debug(f"Attempting key authentication for {self.host} with username: {username}")
                # cache key contents
                if self.args.key_file and self.cached_key is None:
                    with open(self.args.key_file) as f:
                        self.cached_key = f.read().rstrip("\n")
                self.conn.connect(
                    self.host,
                    port=self.port,
                    username=username,
                    passphrase=password if password != "" else None,
                    pkey=private_key,
                    key_filename=self.args.key_file,
                    timeout=self.args.ssh_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=self.args.ssh_timeout,
                )
                cred_id = self.db.add_credential("key", username, password, key=self.cached_key)
            else:
                self.logger.debug(f"Attempting password authentication for {self.host} with username: {username}")
                self.conn.connect(
                    self.host,
                    port=self.port,
                    username=username,
                    password=password,
                    timeout=self.args.ssh_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=self.args.ssh_timeout,
                )
                cred_id = self.db.add_credential("plaintext", username, password)

            self.check_shell(cred_id)
            secret = process_secret(self.password) if not self.args.key_file else f"{process_secret(self.password)} (keyfile: {self.args.key_file})"
            display_shell_access = f"{self.uac}{self.server_os_platform}{' - Shell access!' if self.shell_access else ''}"
            self.logger.success(f"{self.username}:{process_secret(secret)} {self.mark_pwned()} {highlight(display_shell_access)}")
            return True
        except AuthenticationException as e:
            error_msg = str(e)
            self.logger.debug(f"Authentication exception: {error_msg}")
            if "Private key file is encrypted" in error_msg:
                self.logger.fail(f"{username} - Could not load private key (encrypted key requires passphrase)")
            else:
                if using_key_auth:
                    self.logger.fail(f"{username} - Key authentication failed")
                else:
                    self.logger.fail(f"{username}:{process_secret(password)}")
            return False
        except SSHException as e:
            error_msg = str(e).lower()
            self.logger.debug(f"SSH Exception: {error_msg}")
            if (not using_key_auth and 
                ("no authentication methods available" in error_msg or 
                 "not allowed" in error_msg or
                 "authentication method not supported" in error_msg or
                 "no more authentication methods" in error_msg or
                 "permission denied" in error_msg)):
                self.logger.debug("Detected password authentication is disabled based on error message")
                self.password_auth_supported = False
                self.logger.fail("Password auth not supported")
            elif "Invalid key" in error_msg:
                self.logger.fail(f"{username} - Invalid or encrypted private key")
            elif "Error reading SSH protocol banner" in error_msg:
                self.logger.error(f"Internal Paramiko error: {e}")
            else:
                if using_key_auth:
                    self.logger.fail(f"{username} - SSH error with key authentication: {e}")
                else:
                    self.logger.fail(f"{username}:{process_secret(password)} SSH error: {e}")
            return False
        except Exception as e:
            self.logger.debug(f"Exception during login: {e!s}")
            if using_key_auth:
                self.logger.fail(f"{username} - Error with key authentication: {e}")
            else:
                self.logger.fail(f"{username}:{process_secret(password)} Error: {e}")
            return False

    def check_shell(self, cred_id):
        host_id = self.db.get_hosts(self.host)[0].id
        
        # Use a single connection for both checks instead of two separate ones
        # This reduces the number of round trips to the server
        try:
            # Try Linux commands first (most common)
            _, stdout, _ = self.conn.exec_command("id && echo '---SEPARATOR---' && whoami /priv")
            output = stdout.read().decode(self.args.codec, errors="ignore")
            
            # Split the output by our separator
            parts = output.split("---SEPARATOR---")
            linux_output = parts[0].strip() if len(parts) > 0 else ""
            windows_output = parts[1].strip() if len(parts) > 1 else ""
            
            if linux_output:
                self.server_os_platform = "Linux"
                self.logger.debug(f"Linux detected for user: {linux_output}")
                self.shell_access = True
                self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)
                self.check_linux_priv()
                if self.admin_privs:
                    self.logger.debug(f"User {self.username} logged in successfully and is root!")
                    if self.args.key_file:
                        self.db.add_admin_user("key", self.username, self.password, host_id=host_id, cred_id=cred_id)
                    else:
                        self.db.add_admin_user("plaintext", self.username, self.password, host_id=host_id, cred_id=cred_id)
                return
            
            if windows_output:
                self.server_os_platform = "Windows"
                self.logger.debug("Windows detected")
                self.shell_access = True
                self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)
                self.check_windows_priv(windows_output)
                if self.admin_privs:
                    self.logger.debug(f"User {self.username} logged in successfully and is admin!")
                    if self.args.key_file:
                        self.db.add_admin_user("key", self.username, self.password, host_id=host_id, cred_id=cred_id)
                    else:
                        self.db.add_admin_user("plaintext", self.username, self.password, host_id=host_id, cred_id=cred_id)
                return
        except Exception as e:
            self.logger.debug(f"Error during shell check: {e!s}")
            
        # If we get here, no shell access
        self.shell_access = False
        self.logger.debug(f"User: {self.username} can't get a basic shell")
        self.server_os_platform = "Network Devices"
        self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)

    def check_windows_priv(self, stdout):
        if "SeDebugPrivilege" in stdout:
            self.admin_privs = True
        elif "SeUndockPrivilege" in stdout:
            self.admin_privs = True
            self.uac = "with UAC - "

    def check_linux_priv(self):
        if self.args.sudo_check:
            self.check_linux_priv_sudo()
            return
        self.logger.info("Determined user is root via `id; sudo -ln` command")
        _, stdout, _ = self.conn.exec_command("id; sudo -ln 2>&1")
        stdout = stdout.read().decode(self.args.codec, errors="ignore")
        admin_flag = {
            "(root)": [True, None],
            "NOPASSWD: ALL": [True, None],
            "(ALL : ALL) ALL": [True, None],
            "(sudo)": [False, f"Current user: '{self.username}' was in 'sudo' group, please try '--sudo-check' to check if user can run sudo shell"]
        }
        for keyword in admin_flag:
            match = re.findall(re.escape(keyword), stdout)
            if match:
                self.logger.info(f"User: '{self.username}' matched keyword: {match[0]}")
                self.admin_privs = admin_flag[match[0]][0]
                if not self.admin_privs:
                    tips = admin_flag[match[0]][1]
                else:
                    break
        if not self.admin_privs and "tips" in locals():
            self.logger.display(tips)
        return

    def check_linux_priv_sudo(self):
        if not self.password:
            self.logger.error("Check admin with sudo does not support using a private key")
            return
        method = self.args.sudo_check_method if self.args.sudo_check_method else "sudo-stdin"
        self.logger.info(f"Doing sudo check with method: {method}")
        if method == "sudo-stdin":
            _, stdout, _ = self.conn.exec_command("sudo --help")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
            if "stdin" in stdout:
                shadow_backup = f"/tmp/{uuid.uuid4()}"
                self.conn.exec_command(f"echo {self.password} | sudo -S cp /etc/shadow {shadow_backup} >/dev/null 2>&1 &")
                self.conn.exec_command(f"echo {self.password} | sudo -S chmod 777 {shadow_backup} >/dev/null 2>&1 &")
                tries = 1
                while True:
                    self.logger.info(f"Checking {shadow_backup} existence (try {tries})")
                    _, _, stderr = self.conn.exec_command(f"ls {shadow_backup}")
                    if tries >= self.args.get_output_tries:
                        self.logger.info(f"{shadow_backup} not found; pipe may be hanging.")
                        break
                    if stderr.read().decode("utf-8"):
                        time.sleep(2)
                        tries += 1
                    else:
                        self.logger.info(f"{shadow_backup} exists")
                        self.admin_privs = True
                        break
                self.logger.info(f"Removing temporary file {shadow_backup}")
                self.conn.exec_command(f"echo {self.password} | sudo -S rm -rf {shadow_backup}")
            else:
                self.logger.error("Sudo does not support stdin mode; sudo-check failed")
                return
        else:
            _, stdout, _ = self.conn.exec_command("mkfifo --help")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
            if "Create named pipes" in stdout:
                self.logger.info("mkfifo available")
                pipe_stdin = f"/tmp/systemd-{uuid.uuid4()}"
                pipe_stdout = f"/tmp/systemd-{uuid.uuid4()}"
                shadow_backup = f"/tmp/{uuid.uuid4()}"
                self.conn.exec_command(f"mkfifo {pipe_stdin}; tail -f {pipe_stdin} | /bin/sh 2>&1 > {pipe_stdout} >/dev/null 2>&1 &")
                self.conn.exec_command(f"echo 'script -qc /bin/sh /dev/null' > {pipe_stdin}")
                self.conn.exec_command(f"echo 'sudo -s' > {pipe_stdin} && echo '{self.password}' > {pipe_stdin}")
                tries = 1
                self.logger.info(f"Attempting to copy /etc/shadow to {shadow_backup}")
                while True:
                    self.logger.info(f"Checking {shadow_backup} existence (try {tries})")
                    _, _, stderr = self.conn.exec_command(f"ls {shadow_backup}")
                    if tries >= self.args.get_output_tries:
                        self.logger.info(f"{shadow_backup} not found; pipe may be hanging.")
                        break
                    if stderr.read().decode("utf-8"):
                        time.sleep(2)
                        self.conn.exec_command(f"echo 'cp /etc/shadow {shadow_backup} && chmod 777 {shadow_backup}' > {pipe_stdin}")
                        tries += 1
                    else:
                        self.logger.info(f"{shadow_backup} exists")
                        self.admin_privs = True
                        break
                self.logger.info(f"Removing temporary files {shadow_backup}, {pipe_stdin}, {pipe_stdout}")
                self.conn.exec_command(f"echo 'rm -rf {shadow_backup}' > {pipe_stdin} && rm -rf {pipe_stdin} {pipe_stdout}")
            else:
                self.logger.error("mkfifo unavailable; sudo-check failed")
                return

    def put_file_single(self, sftp_conn, src, dst):
        self.logger.display(f'Copying "{src}" to "{dst}"')
        try:
            sftp_conn.put(src, dst)
            self.logger.success(f'Created file "{src}" on "{dst}"')
        except Exception as e:
            self.logger.fail(f'Error writing file to "{dst}": {e}')

    def put_file(self):
        sftp_conn = self.conn.open_sftp()
        for src, dest in self.args.put_file:
            self.put_file_single(sftp_conn, src, dest)
        sftp_conn.close()

    def get_file_single(self, sftp_conn, remote_path, download_path):
        self.logger.display(f'Copying "{remote_path}" to "{download_path}"')
        try:
            sftp_conn.get(remote_path, download_path)
            self.logger.success(f'File "{remote_path}" downloaded to "{download_path}"')
        except Exception as e:
            self.logger.fail(f'Error getting file "{remote_path}": {e}')
            if os.path.getsize(download_path) == 0:
                os.remove(download_path)

    def get_file(self):
        sftp_conn = self.conn.open_sftp()
        for src, dest in self.args.get_file:
            self.get_file_single(sftp_conn, src, dest)
        sftp_conn.close()

    def execute(self, payload=None, get_output=False):
        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True
                
        try:
            # use a timeout to prevent hanging for command execution
            _, stdout, _ = self.conn.exec_command(
                f"{payload} 2>&1", 
                timeout=self.args.ssh_timeout
            )
            
            start_time = time.time()
            stdout_data = ""
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    stdout_data += stdout.channel.recv(1024).decode(self.args.codec, errors="ignore")
                
                if time.time() - start_time > self.args.ssh_timeout:
                    self.logger.debug("Command execution timed out")
                    break
                    
                time.sleep(0.1)
                
            if stdout.channel.recv_ready():
                stdout_data += stdout.channel.recv(1024).decode(self.args.codec, errors="ignore")
                
        except Exception as e:
            self.logger.fail(f"Execute command failed, error: {e!s}")
            return False
        else:
            self.logger.success("Executed command")
            if get_output and stdout_data:
                for line in stdout_data.replace("\r\n", "\n").rstrip("\n").split("\n"):
                    self.logger.highlight(line.strip("\n"))
            return stdout_data