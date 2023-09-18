#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import paramiko, re, uuid, logging, time, sys

from io import StringIO
from nxc.config import process_secret
from nxc.connection import *
from nxc.logger import NXCAdapter
from paramiko.ssh_exception import (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
)

class ssh(connection):
    def __init__(self, args, db, host):
        self.protocol = "SSH"
        self.remote_version = ""
        self.server_os_platform = "Linux"
        self.user_principal = "root"
        super().__init__(args, db, host)
    
    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            if not self.remote_version:
                self.conn.close()
                return
            if self.login():
                if hasattr(self.args, "module") and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()
                self.conn.close()

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "SSH",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        self.logger.display(self.remote_version if self.remote_version else "Unknown SSH version, skipping...")
        return True

    def enum_host_info(self):
        self.remote_version = self.conn._transport.remote_version
        self.logger.debug(f'Remote version: {self.remote_version if self.remote_version else "Unknown SSH Version"}')
        self.db.add_host(self.host, self.args.port, self.remote_version if self.remote_version else "Unknown SSH Version")

    def create_conn_obj(self):
        logging.getLogger("paramiko").disabled = True
        logging.getLogger("paramiko.transport").disabled = True
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.conn.connect(self.host, port=self.args.port, timeout=self.args.ssh_timeout)
        except AuthenticationException:
            return True
        except SSHException:
            return True
        except NoValidConnectionsError:
            return False
        except socket.error:
            return False

    def check_if_admin(self):
        self.admin_privs = False

        if self.args.sudo_check:
            self.check_if_admin_sudo()
            return

        # we could add in another method to check by piping in the password to sudo
        # but that might be too much of an opsec concern - maybe add in a flag to do more checks?
        self.logger.info(f"Determined user is root via `id && sudo -ln` command")
        stdin, stdout, stderr = self.conn.exec_command("id && sudo -ln 2>&1")
        stdout = stdout.read().decode("utf-8", errors="ignore")
        admin_Flag = {
            "(root)": [True, None], 
            "NOPASSWD: ALL": [True, None],
            "(ALL : ALL) ALL": [True, None],
            "(sudo)": [False, f'Current user: "{self.username}" was in "sudo" group, please try "--sudo-check" to check if user can run sudo shell'],
        }
        for keyword in admin_Flag.keys():
            match = re.findall(re.escape(keyword), stdout)
            if match:
                self.logger.info(f'User: "{self.username}" matched keyword: {match[0]}')
                self.admin_privs = admin_Flag[match[0]][0]
                if self.admin_privs:
                    #break
                    break
                else:
                    # Continue find admin flag
                    tips = admin_Flag[match[0]][1]
                    continue
        if not self.admin_privs and "tips" in locals():
            self.logger.display(tips)
        return

    def check_if_admin_sudo(self):
        if not self.password:
            self.logger.error("Check admin with sudo not support private key.")
            return
        
        if self.args.sudo_check_method:
            method = self.args.sudo_check_method
            self.logger.info(f"Doing sudo check with method: {method}")
           
        if method == "sudo-stdin":
            stdin, stdout, stderr = self.conn.exec_command("sudo --help")
            stdout = stdout.read().decode("utf-8", errors="ignore")
            if "stdin" in stdout:
                shadow_Backup = f'/tmp/{uuid.uuid4()}'
                # sudo support stdin password
                stdin, stdout, stderr = self.conn.exec_command(f"echo {self.password} | sudo -S cp /etc/shadow {shadow_Backup} >/dev/null 2>&1 &")
                stdin, stdout, stderr = self.conn.exec_command(f"echo {self.password} | sudo -S chmod 777 {shadow_Backup} >/dev/null 2>&1 &")
                tries = 1
                while True:
                    self.logger.info(f"Checking {shadow_Backup} if it existed")
                    stdin, stdout, stderr = self.conn.exec_command(f'ls {shadow_Backup}')
                    if tries >= self.args.get_output_tries:
                        self.logger.info(f'{shadow_Backup} not existed, maybe the pipe has been hanged over, please increase the number of tries with the option "--get-output-tries" or change other method with "--sudo-check-method". If it\'s still failing maybe sudo shell is not working with current user')
                        break
                    if stderr.read().decode('utf-8'):
                        time.sleep(2)
                        tries +=1
                    else:
                        self.logger.info(f"{shadow_Backup} existed")
                        self.admin_privs = True
                        break
                self.logger.info(f"Remove up temporary files")
                stdin, stdout, stderr = self.conn.exec_command(f"rm -rf {shadow_Backup}")
            else:
                self.logger.error("Command: 'sudo' not support stdin mode, running command with 'sudo' failed")
                return
        else:
            stdin, stdout, stderr = self.conn.exec_command("mkfifo --help")
            stdout = stdout.read().decode("utf-8", errors="ignore")
            # check if user can execute mkfifo
            if "Create named pipes" in stdout:
                self.logger.info("Command: 'mkfifo' available")
                pipe_stdin = f'/tmp/systemd-{uuid.uuid4()}'
                pipe_stdout = f'/tmp/systemd-{uuid.uuid4()}'
                shadow_Backup = f'/tmp/{uuid.uuid4()}'
                stdin, stdout, stderr = self.conn.exec_command(f"mkfifo {pipe_stdin}; tail -f {pipe_stdin} | /bin/sh 2>&1 > {pipe_stdout} >/dev/null 2>&1 &")
                # 'script -qc /bin/sh /dev/null' means "upgrade" the shell, like reverse shell from netcat
                stdin, stdout, stderr = self.conn.exec_command(f"echo 'script -qc /bin/sh /dev/null' > {pipe_stdin}")
                stdin, stdout, stderr = self.conn.exec_command(f"echo 'sudo -s' > {pipe_stdin} && echo '{self.password}' > {pipe_stdin}")
                # Sometime the pipe will hanging(only happen with paramiko)
                # Can't get "whoami" or "id" result in pipe_stdout, maybe something wrong using pipe with paramiko
                # But one thing I can confirm, is the command was executed even can't get result from pipe_stdout
                tries = 1
                self.logger.info(f"Copy /etc/shadow to {shadow_Backup} if pass the sudo auth")
                while True:
                    self.logger.info(f"Checking {shadow_Backup} if it existed")
                    stdin, stdout, stderr = self.conn.exec_command(f'ls {shadow_Backup}')
                    if tries >= self.args.get_output_tries:
                        self.logger.info(f'{shadow_Backup} not existed, maybe the pipe has been hanged over, please increase the number of tries with the option "--get-output-tries" or change other method with "--sudo-check-method". If it\'s still failing maybe sudo shell is not working with current user')
                        break

                    if stderr.read().decode('utf-8'):
                        time.sleep(2)
                        stdin, stdout, stderr = self.conn.exec_command(f"echo 'cp /etc/shadow {shadow_Backup} && chmod 777 {shadow_Backup}' > {pipe_stdin}")
                        tries += 1
                    else:
                        self.logger.info(f"{shadow_Backup} existed")
                        self.admin_privs = True
                        break
                self.logger.info(f"Remove up temporary files")
                stdin, stdout, stderr = self.conn.exec_command(f"rm -rf {shadow_Backup} {pipe_stdin} {pipe_stdout}")
            else:
                self.logger.error("Command: 'mkfifo' unavailable, running command with 'sudo' failed")
                return

    def plaintext_login(self, username, password, private_key=None):
        self.username = username
        self.password = password
        pkey = ""
        stdout = None
        stderr = None
        cred_id = self.db.add_credential("plaintext", username, password)
        try:
            if self.args.key_file or private_key:
                self.logger.debug(f"Logging in with key")
                if private_key:
                    pkey = paramiko.RSAKey.from_private_key(StringIO(private_key))
                else:
                    pkey = paramiko.RSAKey.from_private_key_file(self.args.key_file)

                password = f"(keydata: {private_key})" if private_key else f"(keyfile: {self.args.key_file})"
                self.conn._transport.auth_publickey(username, pkey)
                if private_key:
                    cred_id = self.db.add_credential(
                        "key",
                        username,
                        "",
                        key=private_key,
                    )
                else:
                    with open(self.args.key_file, "r") as f:
                        key_data = f.read()
                    cred_id = self.db.add_credential(
                        "key",
                        username,
                        "",
                        key=key_data,
                    )
            else:
                self.logger.debug(f"Logging {self.host} with username: {self.username}, password: {self.password}")
                self.conn._transport.auth_password(username, password, fallback=True)

            # Some IOT devices will not raise exception in self.conn._transport.auth_password / self.conn._transport.auth_publickey
            stdin, stdout, stderr = self.conn.exec_command("id")
            stdout = stdout.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password) if not pkey else password} {e}")
            self.conn.close()
            return False
        else:
            shell_access = False
            host_id = self.db.get_hosts(self.host)[0].id

            if not stdout:
                stdin, stdout, stderr = self.conn.exec_command("whoami /priv")
                stdout = stdout.read().decode("utf-8", errors="ignore")
                self.server_os_platform = "Windows"
                self.user_principal = "admin"
                if "SeDebugPrivilege" in stdout:
                    self.admin_privs = True
                elif "SeUndockPrivilege" in stdout:
                    self.admin_privs = True
                    self.user_principal = "admin (UAC)"
                else:
                    # non admin (low priv)
                    self.user_principal = "admin (low priv)"

            if not stdout:
                self.logger.debug(f"User: {self.username} can't get a basic shell")
                self.server_os_platform = "Network Devices"
                shell_access = False
            else:
                shell_access = True

            if shell_access and self.server_os_platform == "Linux":
                self.check_if_admin()
                if self.admin_privs:
                    self.logger.debug(f"User {username} logged in successfully and is root!")
                    if self.args.key_file:
                        self.db.add_admin_user("key", username, password, host_id=host_id, cred_id=cred_id)
                    else:
                        self.db.add_admin_user(
                            "plaintext",
                            username,
                            password,
                            host_id=host_id,
                            cred_id=cred_id,
                        )

            self.db.add_loggedin_relation(cred_id, host_id, shell=shell_access)

            if self.args.key_file:
                password = f"(keyfile: {self.args.key_file})"

            display_shell_access = f'Shell access! {f"({self.user_principal})" if self.admin_privs else f"(non {self.user_principal})"}' if shell_access else ""
            self.logger.success(f"{username}:{process_secret(password)} {highlight(display_shell_access)} {highlight(self.server_os_platform)} {self.mark_pwned()}")
            
            return True
    
    def execute(self, payload=None, get_output=False):
        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True
        try:
            stdin, stdout, stderr = self.conn.exec_command(f"{payload} 2>&1")
        except AttributeError:
            return ""
        if get_output:
            self.logger.success("Executed command")
            if get_output:
                for line in stdout:
                    self.logger.highlight(line.strip())
                return stdout
