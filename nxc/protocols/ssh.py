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


class ssh(connection):
    def __init__(self, args, db, host):
        self.protocol = "SSH"
        self.remote_version = "Unknown SSH Version"
        self.server_os_platform = "Linux"
        self.shell_access = False
        self.admin_privs = False
        self.uac = ""
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
        self.logger.display(self.remote_version if self.remote_version != "Unknown SSH Version" else f"{self.remote_version}, skipping...")

    def enum_host_info(self):
        if self.conn._transport.remote_version:
            self.remote_version = self.conn._transport.remote_version
        self.logger.debug(f"Remote version: {self.remote_version}")
        self.db.add_host(self.host, self.port, self.remote_version)

    def create_conn_obj(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.conn.connect(self.host, port=self.port, timeout=self.args.ssh_timeout, look_for_keys=False, allow_agent=False)
        except AuthenticationException:
            return True
        except SSHException:
            return True
        except NoValidConnectionsError:
            return False
        except OSError:
            return False

    def plaintext_login(self, username, password, private_key=""):
        self.username = username
        self.password = password
        try:
            if self.args.key_file or private_key:
                self.logger.debug(f"Logging {self.host} with username: {username}, keyfile: {self.args.key_file}")
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
                # If we get the private key from the file, we need to load it into the database
                if self.args.key_file:
                    with open(self.args.key_file) as f:
                        private_key = f.read().rstrip("\n")
                cred_id = self.db.add_credential("key", username, password, key=private_key)
            else:
                self.logger.debug(f"Logging {self.host} with username: {self.username}, password: {self.password}")
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
            if "Private key file is encrypted" in str(e):
                self.logger.fail(f"{username}:{process_secret(password)} Could not load private key, error: {e}")
            else:
                self.logger.fail(f"{username}:{process_secret(password)}")
        except SSHException as e:
            if "Invalid key" in str(e):
                self.logger.fail(f"{username}:{process_secret(password)} Could not decrypt private key, invalid password")
            elif "Error reading SSH protocol banner" in str(e):
                self.logger.error(f"Internal Paramiko error for {username}:{process_secret(password)}, {e}")
            else:
                self.logger.exception(e)
        except Exception as e:
            self.logger.exception(e)
            self.conn.close()
        return False

    def check_shell(self, cred_id):
        host_id = self.db.get_hosts(self.host)[0].id

        # Some IOT devices will not raise exception in self.conn._transport.auth_password / self.conn._transport.auth_publickey
        # Check Linux
        stdout = self.conn.exec_command("id")[1].read().decode(self.args.codec, errors="ignore")
        if stdout:
            self.server_os_platform = "Linux"
            self.logger.debug(f"Linux detected for user: {stdout}")
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

        # Check Windows
        stdout = self.conn.exec_command("whoami /priv")[1].read().decode(self.args.codec, errors="ignore")
        if stdout:
            self.server_os_platform = "Windows"
            self.logger.debug("Windows detected")
            self.shell_access = True
            self.db.add_loggedin_relation(cred_id, host_id, shell=self.shell_access)
            self.check_windows_priv(stdout)
            if self.admin_privs:
                self.logger.debug(f"User {self.username} logged in successfully and is admin!")
                if self.args.key_file:
                    self.db.add_admin_user("key", self.username, self.password, host_id=host_id, cred_id=cred_id)
                else:
                    self.db.add_admin_user("plaintext", self.username, self.password, host_id=host_id, cred_id=cred_id)
            return

        # No shell access
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

        # we could add in another method to check by piping in the password to sudo
        # but that might be too much of an opsec concern - maybe add in a flag to do more checks?
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

        if self.args.sudo_check_method:
            method = self.args.sudo_check_method
            self.logger.info(f"Doing sudo check with method: {method}")

        if method == "sudo-stdin":
            _, stdout, _ = self.conn.exec_command("sudo --help")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
            # Read sudo help docs and find "stdin"
            if "stdin" in stdout:
                shadow_backup = f"/tmp/{uuid.uuid4()}"
                # sudo support stdin password
                self.conn.exec_command(f"echo {self.password} | sudo -S cp /etc/shadow {shadow_backup} >/dev/null 2>&1 &")
                self.conn.exec_command(f"echo {self.password} | sudo -S chmod 777 {shadow_backup} >/dev/null 2>&1 &")
                tries = 1
                while True:
                    self.logger.info(f"Checking {shadow_backup} if it existed")
                    _, _, stderr = self.conn.exec_command(f"ls {shadow_backup}")
                    if tries >= self.args.get_output_tries:
                        self.logger.info(f"The file {shadow_backup} does not exist, the pipe may be hanging. Increase the number of tries with the option '--get-output-tries' or change other method with '--sudo-check-method'. If it's still failing, maybe sudo shell does not work with the current user")
                        break
                    if stderr.read().decode("utf-8"):
                        time.sleep(2)
                        tries += 1
                    else:
                        self.logger.info(f"{shadow_backup} existed")
                        self.admin_privs = True
                        break
                self.logger.info(f"Remove up temporary files {shadow_backup}")
                self.conn.exec_command(f"echo {self.password} | sudo -S rm -rf {shadow_backup}")
            else:
                self.logger.error("Command: 'sudo' not support stdin mode, running command with 'sudo' failed")
                return
        else:
            _, stdout, _ = self.conn.exec_command("mkfifo --help")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
            # check if user can execute mkfifo
            if "Create named pipes" in stdout:
                self.logger.info("Command: 'mkfifo' available")
                pipe_stdin = f"/tmp/systemd-{uuid.uuid4()}"
                pipe_stdout = f"/tmp/systemd-{uuid.uuid4()}"
                shadow_backup = f"/tmp/{uuid.uuid4()}"
                self.conn.exec_command(f"mkfifo {pipe_stdin}; tail -f {pipe_stdin} | /bin/sh 2>&1 > {pipe_stdout} >/dev/null 2>&1 &")
                # 'script -qc /bin/sh /dev/null' means "upgrade" the shell, like reverse shell from netcat
                self.conn.exec_command(f"echo 'script -qc /bin/sh /dev/null' > {pipe_stdin}")
                self.conn.exec_command(f"echo 'sudo -s' > {pipe_stdin} && echo '{self.password}' > {pipe_stdin}")
                # Sometime the pipe will hanging(only happen with paramiko)
                # Can't get "whoami" or "id" result in pipe_stdout, maybe something wrong using pipe with paramiko
                # But one thing I can confirm, is the command was executed even can't get result from pipe_stdout
                tries = 1
                self.logger.info(f"Copy /etc/shadow to {shadow_backup} if pass the sudo auth")
                while True:
                    self.logger.info(f"Checking {shadow_backup} if it existed")
                    _, _, stderr = self.conn.exec_command(f"ls {shadow_backup}")
                    if tries >= self.args.get_output_tries:
                        self.logger.info(f"The file {shadow_backup} does not exist, the pipe may be hanging. Increase the number of tries with the option '--get-output-tries' or change other method with '--sudo-check-method'. If it's still failing, maybe sudo shell does not work with the current user")
                        break

                    if stderr.read().decode("utf-8"):
                        time.sleep(2)
                        self.conn.exec_command(f"echo 'cp /etc/shadow {shadow_backup} && chmod 777 {shadow_backup}' > {pipe_stdin}")
                        tries += 1
                    else:
                        self.logger.info(f"{shadow_backup} existed")
                        self.admin_privs = True
                        break
                self.logger.info(f"Remove up temporary files {shadow_backup} {pipe_stdin} {pipe_stdout}")
                self.conn.exec_command(f"echo 'rm -rf  {shadow_backup}' > {pipe_stdin} && rm -rf {pipe_stdin} {pipe_stdout}")
            else:
                self.logger.error("Command: 'mkfifo' unavailable, running command with 'sudo' failed")
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
            self.logger.success(f'File "{remote_path}" was downloaded to "{download_path}"')
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
            _, stdout, _ = self.conn.exec_command(f"{payload} 2>&1")
            stdout = stdout.read().decode(self.args.codec, errors="ignore")
        except Exception as e:
            self.logger.fail(f"Execute command failed, error: {e!s}")
            return False
        else:
            self.logger.success("Executed command")
            if get_output:
                for line in stdout.replace("\r\n", "\n").rstrip("\n").split("\n"):
                    self.logger.highlight(line.strip("\n"))
            return stdout
