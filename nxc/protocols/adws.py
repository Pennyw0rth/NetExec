"""
Original Research by Logan Goins @logangoins
https://github.com/logangoins/SOAPy

Blogs:
https://www.ibm.com/think/x-force/stealthy-enumeration-of-active-directory-environments-through-adws

https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws
"""

import socket
from errno import EHOSTUNREACH, ETIMEDOUT, ENETUNREACH

from nxc.connection import connection
from nxc.logger import NXCAdapter

from nxc.protocols.adws.adws_conn import ADWSConnection, ADWSError


class adws(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.hostname = ""
        self.adws_connection = None
        self.lmhash = ""
        self.nthash = ""
        self.baseDN = ""
        self.admin_privs = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "ADWS",
                "host": self.host,
                "port": self.args.port,
                "hostname": self.hostname,
            }
        )

    def create_conn_obj(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.args.adws_timeout)
            sock.connect((self.host, self.args.port))
            sock.close()
        except OSError as e:
            if e.errno in (EHOSTUNREACH, ENETUNREACH, ETIMEDOUT) or "timed out" in str(e):
                self.logger.info(f"Error connecting to ADWS on {self.host}:{self.args.port}: {e}")
            else:
                self.logger.error(f"Error connecting to ADWS on {self.host}:{self.args.port}: {e}")
            return False

        if self.args.domain:
            self.domain = self.args.domain

        if not self.domain:
            try:
                fqdn, _, _ = socket.gethostbyaddr(self.host)
                self.hostname = fqdn.split(".")[0].upper()
                if "." in fqdn:
                    self.domain = ".".join(fqdn.split(".")[1:])
            except socket.herror:
                self.hostname = self.host

        if not self.hostname:
            self.hostname = self.host

        return True

    def print_host_info(self):
        self.logger.extra["protocol"] = "ADWS"
        self.logger.extra["port"] = self.args.port
        self.logger.extra["hostname"] = self.hostname
        domain_str = self.domain if self.domain else "unknown"
        self.logger.display(f"(name:{self.hostname}) (domain:{domain_str})")

    def plaintext_login(self, domain, username, password):
        self.username = username
        self.password = password
        self.domain = domain

        if self.args.domain:
            self.domain = self.args.domain
        if not self.domain:
            self.domain = self.hostname

        try:
            self.adws_connection = ADWSConnection(
                self.host, self.domain, port=self.args.port, timeout=self.args.adws_timeout
            )
            self.adws_connection.login(username=username, password=password, resource="Enumeration")
            self.baseDN = self.adws_connection.base_dn
            self.logger.success(f"{self.domain}\\{username}:{password}")
            self.db.add_credential("plaintext", domain, username, password)
            self.db.add_host(self.host, self.hostname, self.domain, self.server_os, "Yes")
            return True
        except Exception as e:
            self.logger.fail(f"{self.domain}\\{username}:{password} {e}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.username = username
        self.domain = domain

        if self.args.domain:
            self.domain = self.args.domain
        if not self.domain:
            self.domain = self.hostname

        nthash = ntlm_hash.split(":")[-1] if ":" in ntlm_hash else ntlm_hash
        self.nthash = nthash

        try:
            self.adws_connection = ADWSConnection(
                self.host, self.domain, port=self.args.port, timeout=self.args.adws_timeout
            )
            self.adws_connection.login(username=username, nt_hash=nthash, resource="Enumeration")
            self.baseDN = self.adws_connection.base_dn
            self.logger.success(f"{self.domain}\\{username}:{nthash}")
            self.db.add_credential("hash", domain, username, nthash)
            self.db.add_host(self.host, self.hostname, self.domain, self.server_os, "Yes")
            return True
        except Exception as e:
            self.logger.fail(f"{self.domain}\\{username}:{nthash} {e}")
            return False

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.username = username
        self.password = password
        self.domain = domain
        self.kdcHost = kdcHost

        if self.args.domain:
            self.domain = self.args.domain
        if not self.domain:
            self.domain = self.hostname

        nthash = ""
        if ntlm_hash:
            nthash = ntlm_hash.split(":")[-1] if ":" in ntlm_hash else ntlm_hash

        try:
            self.adws_connection = ADWSConnection(
                self.host, self.domain, port=self.args.port, timeout=self.args.adws_timeout
            )
            self.adws_connection.login(
                username=username, password=password, nt_hash=nthash,
                use_kerberos=True, kdc_host=kdcHost, resource="Enumeration",
            )
            self.baseDN = self.adws_connection.base_dn
            cred = f"{self.domain}\\{username}"
            if password:
                cred += f":{password}"
            elif nthash:
                cred += f":{nthash}"
            self.logger.success(cred)
            self.db.add_credential("plaintext" if password else "hash", domain, username, password or nthash)
            self.db.add_host(self.host, self.hostname, self.domain, self.server_os, "Yes")
            return True
        except Exception as e:
            self.logger.fail(f"{self.domain}\\{username} Kerberos auth failed: {e}")
            return False

    # -----------------------------------------------------------------------
    # Enumeration methods — auto-dispatched by call_cmd_args via proto_args
    # -----------------------------------------------------------------------

    def _adws_enum(self, query, attributes, label="objects"):
        if not self.adws_connection:
            return []
        basedn = self.args.base_dn if self.args.base_dn else self.baseDN
        try:
            return self.adws_connection.enumerate(query, attributes, basedn=basedn)
        except ADWSError as e:
            self.logger.fail(f"ADWS query failed: {e}")
            return []
        except Exception as e:
            self.logger.fail(f"Enumeration error: {e}")
            return []

    def users(self):
        results = self._adws_enum(
            "(sAMAccountType=805306368)",
            ["sAMAccountName", "description", "badPwdCount", "pwdLastSet"],
            "users",
        )
        if not results:
            return

        self.logger.display(f"Enumerated {len(results):d} domain users: {self.domain}")
        self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<9}{'-Description-':<60}")
        for user in results:
            sam = user.get("sAMAccountName", "")
            desc = user.get("description", "")
            bad = user.get("badPwdCount", "")
            pwd_last_set = user.get("pwdLastSet", "")
            if pwd_last_set:
                pwd_last_set = "<never>" if pwd_last_set == "0" else pwd_last_set
            self.logger.highlight(f"{sam:<30}{pwd_last_set:<20}{bad:<9}{desc:<60}")

    def computers(self):
        results = self._adws_enum(
            "(sAMAccountType=805306369)",
            ["sAMAccountName"],
            "computers",
        )
        if not results:
            return

        self.logger.display(f"Total records returned: {len(results)}")
        for obj in results:
            self.logger.highlight(obj.get("sAMAccountName", ""))

    def groups(self):
        if self.args.groups:
            query = f"(&(objectCategory=group)(cn={self.args.groups}))"
            results = self._adws_enum(
                query,
                ["sAMAccountName", "distinguishedName", "cn", "objectClass", "member"],
                "group members",
            )
            if not results:
                self.logger.fail(f"Group '{self.args.groups}' not found")
                return

            members = results[0].get("member", [])
            if isinstance(members, str):
                members = [members]
            if not members:
                self.logger.fail(f"Group '{self.args.groups}' has no members")
                return
            for m in members:
                if "CN=" in m:
                    m = m.split(",")[0].split("CN=")[-1]
                self.logger.highlight(m)
        else:
            results = self._adws_enum(
                "(objectCategory=group)",
                ["cn", "member", "description"],
                "groups",
            )
            if not results:
                return

            self.logger.display(f"Total of records returned {len(results)}")
            self.logger.highlight(f"{'-Group-':<40} {'-Members-':<9} {'-Description-':<60}")
            for obj in results:
                cn = obj.get("cn", "")
                desc = obj.get("description", "")
                members = obj.get("member", [])
                if isinstance(members, str):
                    members = [members]
                self.logger.highlight(f"{cn:<40} {len(members):<9} {desc}")

    def dc_list(self):
        results = self._adws_enum(
            "(&(objectCategory=computer)(primaryGroupID=516))",
            ["dNSHostName"],
            "domain controllers",
        )
        if not results:
            return

        for obj in results:
            dns = obj.get("dNSHostName", "")
            if dns:
                try:
                    ip = socket.gethostbyname(dns)
                    self.logger.highlight(f"{dns} = {ip}")
                except socket.gaierror:
                    self.logger.highlight(dns)

    def admin_count(self):
        results = self._adws_enum(
            "(&(adminCount=1)(objectClass=user))",
            ["sAMAccountName"],
            "adminCount=1 accounts",
        )
        if not results:
            self.logger.fail("No entries found!")
            return

        self.logger.debug(f"Total of records returned {len(results):d}")
        for obj in results:
            self.logger.highlight(obj.get("sAMAccountName", ""))

    def trusted_for_delegation(self):
        results = self._adws_enum(
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            ["sAMAccountName"],
            "trusted for delegation",
        )
        if not results:
            self.logger.fail("No entries found!")
            return

        self.logger.debug(f"Total of records returned {len(results):d}")
        for obj in results:
            self.logger.highlight(obj.get("sAMAccountName", ""))

    def find_delegation(self):
        query = (
            "(&(|(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(msDS-AllowedToDelegateTo=*)"
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        results = self._adws_enum(
            query,
            ["sAMAccountName", "userAccountControl", "objectCategory",
             "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
            "delegation",
        )
        if not results:
            self.logger.fail("No entries found!")
            return

        items = []
        for obj in results:
            sam = obj.get("sAMAccountName", "")
            uac = int(obj.get("userAccountControl", "0"))
            obj_type = obj.get("objectCategory", "")
            rights_to = []
            delegation = ""

            if uac & 524288 and not uac & 8192:
                delegation = "Unconstrained"
                rights_to = ["N/A"]
            elif uac & 16777216:
                delegation = "Constrained w/ Protocol Transition"
                rights_to = obj.get("msDS-AllowedToDelegateTo", [])
                if isinstance(rights_to, str):
                    rights_to = [rights_to]
            elif obj.get("msDS-AllowedToDelegateTo"):
                delegation = "Constrained"
                rights_to = obj.get("msDS-AllowedToDelegateTo", [])
                if isinstance(rights_to, str):
                    rights_to = [rights_to]

            if obj.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
                if delegation:
                    items.append([sam, obj_type, delegation, ", ".join(str(x) for x in rights_to)])
                delegation = "Resource Based Constrained"
                rights_to = ["N/A"]

            if delegation:
                items.append([sam, obj_type, delegation, ", ".join(str(x) for x in rights_to)])

        if items:
            header = ["AccountName", "AccountType", "DelegationType", "DelegationRightsTo"]
            col_len = []
            for i, col in enumerate(header):
                max_row = max(len(str(row[i])) for row in items) if items else 0
                col_len.append(max(max_row, len(col)))
            fmt = " ".join(f"{{{n}:{w}s}}" for n, w in enumerate(col_len))
            self.logger.highlight(fmt.format(*header))
            self.logger.highlight(" ".join("-" * c for c in col_len))
            for row in items:
                if "CN=" in row[1]:
                    row[1] = row[1].split(",")[0].split("CN=")[-1]
                self.logger.highlight(fmt.format(*row))

    def password_not_required(self):
        results = self._adws_enum(
            "(userAccountControl:1.2.840.113556.1.4.803:=32)",
            ["sAMAccountName", "userAccountControl"],
            "PASSWD_NOTREQD accounts",
        )
        if not results:
            self.logger.fail("No entries found!")
            return

        self.logger.debug(f"Total of records returned {len(results):d}")
        for obj in results:
            uac = int(obj.get("userAccountControl", "0"))
            status = "disabled" if uac & 2 else "enabled"
            self.logger.highlight(f"User: {obj.get('sAMAccountName', '')} Status: {status}")

    def get_sid(self):
        results = self._adws_enum(
            "(objectClass=domain)",
            ["objectSid"],
            "domain SID",
        )
        if results:
            sid = results[0].get("objectSid", "")
            self.logger.highlight(f"Domain SID {sid}")

    def active_users(self):
        results = self._adws_enum(
            "(sAMAccountType=805306368)",
            ["sAMAccountName", "description", "badPwdCount", "pwdLastSet", "userAccountControl"],
            "active users",
        )
        if not results:
            return

        active = [u for u in results if not (int(u.get("userAccountControl", "2")) & 2)]
        self.logger.display(f"Total records returned: {len(results)}, total {len(results) - len(active):d} user(s) disabled")
        self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<9}{'-Description-':<60}")
        for user in active:
            pwd_last_set = user.get("pwdLastSet", "")
            if pwd_last_set:
                pwd_last_set = "<never>" if pwd_last_set == "0" else pwd_last_set
            self.logger.highlight(f"{user.get('sAMAccountName', ''):<30}{pwd_last_set:<20}{user.get('badPwdCount', ''):<9}{user.get('description', '')}")

    def query(self):
        if not self.args.query:
            return

        ldap_filter = self.args.query[0]
        attrs = [a.strip() for a in self.args.query[1].split(",")]

        results = self._adws_enum(ldap_filter, attrs, "objects")
        if not results:
            return

        self.logger.display(f"Total of records returned {len(results)}")
        for obj in results:
            parts = [f"{k}: {v}" for k, v in obj.items()]
            self.logger.highlight("  |  ".join(parts))
