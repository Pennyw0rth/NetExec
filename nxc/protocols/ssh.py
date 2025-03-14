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
from itertools import starmap

# precompiled regex for parsing allowed SSH auth types
AUTH_METHODS_REGEX = re.compile(r"allowed types: \[(.*?)\]")

class ssh(connection):
    """
    SSH protocol implementation for NetExec.
    Handles SSH connections, authentication, and command execution.
    """
    def __init__(self, args, db, host):
        self.protocol = "SSH"
        self.remote_version = "Unknown SSH Version"
        self.server_os_platform = "[Linux]"
        self.shell_access = False
        self.admin_privs = False
        self.uac = ""
        self.password_auth_supported = True
        self.auth_methods_cache = {}
        self.cached_key = None
        super().__init__(args, db, host)

    # ╔══════════════════════════════════════════════════════════╗
    # ║      Connection and Authentication Flow                  ║
    # ╚══════════════════════════════════════════════════════════╝
    def proto_flow(self):
        """Main protocol flow: connect, authenticate, and execute commands."""
        self.logger.debug("Kicking off proto_flow")
        self.proto_logger()
        
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            
            if self.remote_version == "Unknown SSH Version":
                self.conn.close()
                return
                
            # skip password auth check if using key authentication
            if hasattr(self.args, "key_file") and self.args.key_file:
                self.logger.debug("Key file provided, skipping password auth check")
                
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
        """Set up the protocol-specific logger."""
        logging.getLogger("paramiko").disabled = True
        logging.getLogger("paramiko.transport").disabled = True
        
        # custom logger
        self.logger = NXCAdapter(extra={
            "protocol": "SSH",
            "host": self.host,
            "port": self.port,
            "hostname": self.hostname,
        })

    def create_conn_obj(self):
        """
        Create the initial SSH connection object.
        Returns True if the server is reachable, False otherwise.
        """
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
            # auth failed but connection succeeded
            return True
        except (NoValidConnectionsError, OSError):
            # connection failed
            return False
        return True

    def login(self):
        """Override the parent login method to provide better debug messages for key-based authentication"""
        if hasattr(self.args, "key_file") and self.args.key_file:
            self.logger.debug(f"Trying to authenticate using key file: {self.args.key_file}")
            
            # for key-based auth, we'll handle the login process here instead of calling the parent method
            if self.args.no_bruteforce:
                if self.args.username and (self.args.password or self.args.key_file) and self.plaintext_login(self.args.username, self.args.password):
                    return True
                return False
            
            # grab creds from credential store
            return any(starmap(self.plaintext_login, self.get_credentials()))
        else:
            return super().login()

    def get_credentials(self):
        """Get credentials from various sources in the args namespace."""
        if hasattr(self.args, "username") and self.args.username:
            # Handle case where username/password might be lists
            username = self.args.username[0] if isinstance(self.args.username, list) else self.args.username
            password = ""
            if hasattr(self.args, "password"):
                password = self.args.password[0] if isinstance(self.args.password, list) else self.args.password
            yield username, password
            
        if hasattr(self.args, "credential_file") and self.args.credential_file:
            with open(self.args.credential_file) as cred_file:
                for line in cred_file:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            username, password = line.split(":", 1)
                            yield username, password
                        except ValueError:
                            self.logger.debug(f"Invalid line in credential file: {line}")
                            
        if hasattr(self.args, "username_file") and self.args.username_file:
            with open(self.args.username_file) as user_file:
                for username in user_file:
                    username = username.strip()
                    if username and not username.startswith("#"):
                        password = ""
                        if hasattr(self.args, "password"):
                            password = self.args.password[0] if isinstance(self.args.password, list) else self.args.password
                        yield username, password

    def plaintext_login(self, username, password, private_key=""):
        """
        Attempt to authenticate with the provided credentials.
        
        Args:
        ----
            username: The username to authenticate with
            password: The password to authenticate with (or key passphrase)
            private_key: Optional private key object for key-based auth
            
        Returns:
        -------
            bool: True if authentication succeeded, False otherwise
        """
        self.username = username
        self.password = password
        using_key_auth = bool(self.args.key_file or private_key)
        cache_key = f"{self.host}:{self.port}"
        
        # log auth attempt type
        if using_key_auth:
            self.logger.debug(f"Attempting key authentication for {self.host} with username: {username}")
        else:
            self.logger.debug(f"Attempting password authentication for {self.host} with username: {username}")
            
            # check cache for known allowed auth methods
            if cache_key in self.auth_methods_cache and "password" not in self.auth_methods_cache[cache_key]:
                self.logger.debug("Skipping password auth - known unsupported from cache")
                self.logger.fail("Password auth not supported")
                return False

        try:
            # key auth
            if using_key_auth:
                self.conn.connect(
                    self.host,
                    port=self.port,
                    username=username,
                    passphrase=password if password != "" else None,
                    pkey=private_key if private_key else None,
                    key_filename=self.args.key_file,
                    timeout=self.args.ssh_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=self.args.ssh_timeout,
                )
                
                if self.args.key_file and not self.cached_key:
                    try:
                        with open(self.args.key_file) as f:
                            self.cached_key = f.read().rstrip("\n")
                    except Exception as e:
                        self.logger.debug(f"Error reading key file for database: {e}")
                        self.cached_key = "Unable to read key file"
                
                cred_id = self.db.add_credential("key", username, password, key=self.cached_key)
            else:
                # connect with password auth
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

            # auth success -> check shell access
            self.check_shell(cred_id)
            
            # log success
            if using_key_auth:
                # show keyFile name instead of password for key auth
                key_filename = self.args.key_file.split("/")[-1] if self.args.key_file else "private_key"
                # Indicate if the key required a passphrase
                secret = f"{key_filename}" if password else f"{key_filename}"
            else:
                secret = process_secret(self.password)
                
            display_shell_access = f"{self.uac}{self.server_os_platform}"
            self.logger.success(f"{self.username}:{secret} {self.mark_pwned()} {highlight(display_shell_access)}")
            return True
            
        except AuthenticationException as e:
            # auth failed
            error_msg = str(e).lower()
            self.logger.debug(f"Authentication exception: {error_msg}")
            
            # extract allowed auth methods - works with OpenSSH format
            if "allowed types" in error_msg:
                match = AUTH_METHODS_REGEX.search(error_msg)
                if match:
                    auth_methods = [m.strip("'") for m in match.group(1).split(", ")]
                    self.logger.debug(f"Server reports auth methods: {auth_methods}")
                    self.auth_methods_cache[cache_key] = auth_methods
                    
                    # validate password auth is available, otherwise fail
                    if not using_key_auth and "password" not in auth_methods:
                        self.logger.fail("Password auth not supported")
                        return False
            
            # generic pattern matching for common authentication errors across SSH implementations
            if any(phrase in error_msg for phrase in ["encrypted", "passphrase required", "need passphrase"]):
                self.logger.fail("Key passphrase required")
            elif any(phrase in error_msg for phrase in ["permission denied", "auth fail", "authentication failed"]) and not using_key_auth:
                # Check if this might be a publickey-only server
                if "publickey" in error_msg or self.remote_version.lower().startswith("ssh-2.0-openssh"):
                    self.auth_methods_cache[cache_key] = ["publickey"]
                    self.logger.fail("Password auth not supported")
                else:
                    self.logger.fail(f"{username}:{process_secret(password)}")
            else:
                # generic auth failure
                if using_key_auth:
                    self.logger.fail(f"{username} - Key authentication failed")
                else:
                    self.logger.fail(f"{username}:{process_secret(password)}")
            return False
            
        except SSHException as e:
            # SSH protocol error
            error_msg = str(e).lower()
            self.logger.debug(f"SSH Exception: {error_msg}")
            
            # generic pattern matching
            if not using_key_auth and any(phrase in error_msg for phrase in [
                "no authentication methods", 
                "not allowed", 
                "authentication method not supported", 
                "no more authentication methods", 
                "permission denied"
            ]):
                self.logger.debug("Detected password authentication is disabled based on error message")
                self.auth_methods_cache[cache_key] = ["publickey"]
                self.logger.fail("Password auth not supported")
            elif any(phrase in error_msg for phrase in ["invalid key", "bad passphrase", "wrong passphrase", "cannot decrypt"]):
                self.logger.fail("Invalid passphrase")
            elif "error reading ssh protocol banner" in error_msg:
                self.logger.error(f"Internal Paramiko error: {e}")
            else:
                # generic SSH error with more context
                if using_key_auth:
                    self.logger.debug(f"Unhandled SSH exception during key auth: {error_msg}")
                    self.logger.fail(f"{username} - SSH error with key authentication: {e}")
                else:
                    self.logger.debug(f"Unhandled SSH exception during password auth: {error_msg}")
                    self.logger.fail(f"{username}:{process_secret(password)} SSH error: {e}")
            return False
            
        except Exception as e:
            error_str = str(e)
            self.logger.debug(f"Exception during login: {error_str}")
            
            # Handle specific key validation errors with more generic patterns
            if using_key_auth and any(phrase in error_str.lower() for phrase in ["q must be exactly", "key validation", "invalid key format"]):
                self.logger.fail("Valid key passphrase but ownership validation failed", color="magenta")
            elif using_key_auth:
                self.logger.debug(f"Unhandled exception during key auth: {error_str}")
                self.logger.fail(f"{username} - Error with key authentication: {e}")
            else:
                self.logger.debug(f"Unhandled exception during password auth: {error_str}")
                self.logger.fail(f"{username}:{process_secret(password)} Error: {e}")
            return False

    # Add a custom method to handle the parent class's login process
    def _plaintext_login_wrapper(self, username, password):
        """
        Wrapper for plaintext_login that's called by the parent class's login method.
        This ensures we don't log duplicate messages.
        """
        # Skip the debug message since the parent already logged it
        return self.plaintext_login(username, password)

    # ╔══════════════════════════════════════════════════════════╗
    # ║      Host Information                                    ║
    # ╚══════════════════════════════════════════════════════════╝
    def enum_host_info(self):
        """Enumerate basic host information from the SSH connection."""
        if self.conn._transport.remote_version:
            self.remote_version = self.conn._transport.remote_version
        self.logger.debug(f"Remote version: {self.remote_version}")
        self.db.add_host(self.host, self.port, self.remote_version)

    def print_host_info(self):
        """Display host information to the user."""
        self.logger.display(
            self.remote_version if self.remote_version != "Unknown SSH Version" 
            else f"{self.remote_version}, skipping..."
        )

    # ╔══════════════════════════════════════════════════════════╗
    # ║      Shell Access and Privileges                         ║
    # ╚══════════════════════════════════════════════════════════╝
    def check_shell(self, cred_id):
        """
        Check if we have shell access and determine the OS type.
        Also checks for administrative privileges.
        """
        host_id = self.db.get_hosts(self.host)[0].id
        
        try:
            # Execute both Linux and Windows commands in one go to minimize round trips
            _, stdout, _ = self.conn.exec_command("id && echo '---SEPARATOR---' && whoami /priv")
            output = stdout.read().decode(self.args.codec, errors="ignore")
            
            # Split the output to check for Linux and Windows responses
            parts = output.split("---SEPARATOR---")
            linux_output = parts[0].strip() if len(parts) > 0 else ""
            windows_output = parts[1].strip() if len(parts) > 1 else ""
            
            # Linux
            if linux_output:
                self.server_os_platform = "[Linux]"
                self.logger.debug(f"Linux detected for user: {linux_output}")
                self.shell_access = True
                self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)
                self.check_linux_priv()
                
                if self.admin_privs:
                    self.logger.debug(f"User {self.username} logged in successfully and is a superuser!")
                    auth_type = "key" if self.args.key_file else "plaintext"
                    self.db.add_admin_user(auth_type, self.username, self.password, 
                                           host_id=host_id, cred_id=cred_id)
                return
            
            # Windows
            if windows_output:
                self.server_os_platform = "[Windows]"
                self.logger.debug("Windows detected")
                self.shell_access = True
                self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)
                self.check_windows_priv(windows_output)
                
                if self.admin_privs:
                    self.logger.debug(f"User {self.username} logged in successfully and is admin!")
                    auth_type = "key" if self.args.key_file else "plaintext"
                    self.db.add_admin_user(auth_type, self.username, self.password, 
                                           host_id=host_id, cred_id=cred_id)
                return
        except Exception as e:
            self.logger.debug(f"Error during shell check: {e!s}")
            
        # If we get here, no shell access
        self.shell_access = False
        self.logger.debug(f"User: {self.username} cannot obtain a basic shell")
        self.server_os_platform = "Network Devices"
        self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)

    def check_windows_priv(self, stdout):
        """Check for Windows admin privileges."""
        if "SeDebugPrivilege" in stdout or "SeUndockPrivilege" in stdout:
            self.admin_privs = True
            if "SeUndockPrivilege" in stdout:
                self.uac = "with UAC - "

    def check_linux_priv(self):
        """Check for Linux superuser privileges."""
        if self.args.sudo_check:
            self.check_linux_priv_sudo()
            return
            
        self.logger.info(f"Checking superuser privileges for user '{self.username}' via `id; sudo -ln`")
        _, stdout, _ = self.conn.exec_command("id; sudo -ln 2>&1")
        stdout = stdout.read().decode(self.args.codec, errors="ignore")
        
        # define privilege indicators
        admin_flag = {
            "(root)": [True, None],
            "NOPASSWD: ALL": [True, None],
            "(ALL : ALL) ALL": [True, None],
            "(sudo)": [False, f"User '{self.username}' in 'sudo' group; try '--sudo-check' for shell access"]
        }
        
        # check each privilege indicator
        found_match = False
        for keyword, (flag, tip) in admin_flag.items():
            if re.search(re.escape(keyword), stdout):
                self.logger.info(f"User '{self.username}' matched keyword: {keyword}")
                self.admin_privs = flag
                found_match = True
                if not flag and tip:
                    self.logger.display(tip)
                break
                
        # If no matches were found, user is not a superuser
        if not found_match:
            self.admin_privs = False
            self.logger.info(f"User '{self.username}' does not have superuser privileges")

    def check_linux_priv_sudo(self):
        """Check for sudo privileges on Linux by attempting to use sudo."""
        if not self.password:
            self.logger.error("Sudo check does not support key authentication")
            return
            
        # determine which sudo check method to use
        method = self.args.sudo_check_method if self.args.sudo_check_method else "sudo-stdin"
        self.logger.info(f"Performing sudo check with method: {method}")
        
        if method == "sudo-stdin":
            # check if sudo supports stdin input
            _, stdout, _ = self.conn.exec_command("sudo --help")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
            
            if "stdin" in stdout:
                # create a temporary file to check if sudo works
                shadow_backup = f"/tmp/{uuid.uuid4()}"
                self.conn.exec_command(f"echo {self.password} | sudo -S cp /etc/shadow {shadow_backup} >/dev/null 2>&1 &")
                self.conn.exec_command(f"echo {self.password} | sudo -S chmod 777 {shadow_backup} >/dev/null 2>&1 &")
                
                # check if the file was created (indicates sudo worked)
                tries = 1
                while tries < self.args.get_output_tries:
                    self.logger.info(f"Checking existence of {shadow_backup} (try {tries})")
                    _, _, stderr = self.conn.exec_command(f"ls {shadow_backup}")
                    
                    if stderr.read().decode("utf-8"):
                        # file doesn't exist yet, wait and try again
                        time.sleep(2)
                        tries += 1
                    else:
                        # file exists, sudo worked
                        self.logger.info(f"{shadow_backup} exists")
                        self.admin_privs = True
                        break
                        
                # delete temp file
                self.logger.info(f"Removing temporary file {shadow_backup}")
                self.conn.exec_command(f"echo {self.password} | sudo -S rm -rf {shadow_backup}")
            else:
                self.logger.error("Sudo does not support stdin mode; sudo-check failed")
        else:
            # use mkfifo method as an alternative
            _, stdout, _ = self.conn.exec_command("mkfifo --help")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
            
            if "Create named pipes" in stdout:
                self.logger.info("mkfifo available")
                
                # create named pipes for communication
                pipe_stdin = f"/tmp/systemd-{uuid.uuid4()}"
                pipe_stdout = f"/tmp/systemd-{uuid.uuid4()}"
                shadow_backup = f"/tmp/{uuid.uuid4()}"
                
                # set up the pipes
                self.conn.exec_command(f"mkfifo {pipe_stdin}; tail -f {pipe_stdin} | /bin/sh 2>&1 > {pipe_stdout} >/dev/null 2>&1 &")
                self.conn.exec_command(f"echo 'script -qc /bin/sh /dev/null' > {pipe_stdin}")
                self.conn.exec_command(f"echo 'sudo -s' > {pipe_stdin} && echo '{self.password}' > {pipe_stdin}")
                
                # check if sudo worked
                tries = 1
                while tries < self.args.get_output_tries:
                    self.logger.info(f"Checking {shadow_backup} existence (try {tries})")
                    _, _, stderr = self.conn.exec_command(f"ls {shadow_backup}")
                    
                    if stderr.read().decode("utf-8"):
                        # file doesn't exist yet, try to create it
                        time.sleep(2)
                        self.conn.exec_command(f"echo 'cp /etc/shadow {shadow_backup} && chmod 777 {shadow_backup}' > {pipe_stdin}")
                        tries += 1
                    else:
                        # file exists, sudo worked
                        self.logger.info(f"{shadow_backup} exists")
                        self.admin_privs = True
                        break
                        
                # delete temp files
                self.logger.info(f"Removing temporary files {shadow_backup}, {pipe_stdin}, {pipe_stdout}")
                self.conn.exec_command(f"echo 'rm -rf {shadow_backup}' > {pipe_stdin} && rm -rf {pipe_stdin} {pipe_stdout}")
            else:
                self.logger.error("mkfifo unavailable; sudo-check failed")

    # ╔══════════════════════════════════════════════════════════╗
    # ║      File Transfers                                      ║
    # ╚══════════════════════════════════════════════════════════╝
    def put_file(self):
        """Upload files to the remote host."""
        sftp_conn = self.conn.open_sftp()
        for src, dest in self.args.put_file:
            self.put_file_single(sftp_conn, src, dest)
        sftp_conn.close()

    def put_file_single(self, sftp_conn, src, dst):
        """Upload a single file to the remote host."""
        self.logger.display(f'Copying "{src}" to "{dst}"')
        try:
            sftp_conn.put(src, dst)
            self.logger.success(f'Created file "{src}" on "{dst}"')
        except Exception as e:
            self.logger.fail(f'Error writing file to "{dst}": {e}')

    def get_file(self):
        """Download files from the remote host."""
        sftp_conn = self.conn.open_sftp()
        for src, dest in self.args.get_file:
            self.get_file_single(sftp_conn, src, dest)
        sftp_conn.close()

    def get_file_single(self, sftp_conn, remote_path, download_path):
        """Download a single file from the remote host."""
        self.logger.display(f'Copying "{remote_path}" to "{download_path}"')
        try:
            sftp_conn.get(remote_path, download_path)
            self.logger.success(f'File "{remote_path}" downloaded to "{download_path}"')
        except Exception as e:
            self.logger.fail(f'Error getting file "{remote_path}": {e}')
            if os.path.getsize(download_path) == 0:
                os.remove(download_path)

    # ╔══════════════════════════════════════════════════════════╗
    # ║      Command Execution Methods                           ║
    # ╚══════════════════════════════════════════════════════════╝
    def execute(self, payload=None, get_output=False):
        """
        Execute a command on the remote host.
        
        Args:
        ----
            payload: The command to execute
            get_output: Whether to capture and return the output
            
        Returns:
        -------
            str: Command output if get_output is True, otherwise None
        """
        # Determine the command to execute
        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True
                
        try:
            # execute command with timeout to avoid hanging
            _, stdout, _ = self.conn.exec_command(f"{payload} 2>&1", timeout=self.args.ssh_timeout)
            
            # read output incrementally with timeout
            start_time = time.time()
            stdout_data = ""
            
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    stdout_data += stdout.channel.recv(1024).decode(self.args.codec, errors="ignore")
                    
                # check for timeout
                if time.time() - start_time > self.args.ssh_timeout:
                    self.logger.debug("Command execution timed out")
                    break
                    
                time.sleep(0.1)
                
            # get any remaining data
            if stdout.channel.recv_ready():
                stdout_data += stdout.channel.recv(1024).decode(self.args.codec, errors="ignore")
                
        except Exception as e:
            self.logger.fail(f"Execute command failed, error: {e!s}")
            return False
        else:
            self.logger.success("Executed command")
            
            # display output if requested
            if get_output and stdout_data:
                for line in stdout_data.replace("\r\n", "\n").rstrip("\n").split("\n"):
                    self.logger.highlight(line.strip("\n"))
                    
            return stdout_data