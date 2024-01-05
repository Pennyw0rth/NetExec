import random
from os.path import isfile
from threading import BoundedSemaphore
from functools import wraps
from time import sleep
from ipaddress import ip_address
from socket import AF_UNSPEC, SOCK_DGRAM, IPPROTO_IP, AI_CANONNAME, getaddrinfo

from nxc.config import pwned_label
from nxc.helpers.logger import highlight
from nxc.logger import nxc_logger, NXCAdapter
from nxc.context import Context
from nxc.protocols.ldap.laps import laps_search

from impacket.dcerpc.v5 import transport
import sys

sem = BoundedSemaphore(1)
global_failed_logins = 0
user_failed_logins = {}


def gethost_addrinfo(hostname):
    is_ipv6 = False
    is_link_local_ipv6 = False
    address_info = {"AF_INET6": "", "AF_INET": ""}

    for res in getaddrinfo(hostname, None, AF_UNSPEC, SOCK_DGRAM, IPPROTO_IP, AI_CANONNAME):
        af, _, _, canonname, sa = res
        address_info[af.name] = sa[0]

    # IPv4 preferred
    if address_info["AF_INET"]:
        host = address_info["AF_INET"]
    else:
        is_ipv6 = True
        host, is_link_local_ipv6 = (canonname, True) if ip_address(address_info["AF_INET6"]).is_link_local else (address_info["AF_INET6"], False)

    return host, is_ipv6, is_link_local_ipv6


def requires_admin(func):
    def _decorator(self, *args, **kwargs):
        if self.admin_privs is False:
            return None
        return func(self, *args, **kwargs)

    return wraps(func)(_decorator)


def dcom_FirewallChecker(iInterface, timeout):
    stringBindings = iInterface.get_cinstance().get_string_bindings()
    for strBinding in stringBindings:
        if strBinding["wTowerId"] == 7:
            if strBinding["aNetworkAddr"].find("[") >= 0:
                binding, _, bindingPort = strBinding["aNetworkAddr"].partition("[")
                bindingPort = "[" + bindingPort
            else:
                binding = strBinding["aNetworkAddr"]
                bindingPort = ""

            if binding.upper().find(iInterface.get_target().upper()) >= 0:
                stringBinding = "ncacn_ip_tcp:" + strBinding["aNetworkAddr"][:-1]
                break
            elif iInterface.is_fqdn() and binding.upper().find(iInterface.get_target().upper().partition(".")[0]) >= 0:
                stringBinding = f"ncacn_ip_tcp:{iInterface.get_target()}{bindingPort}"
    if "stringBinding" not in locals():
        return True, None
    try:
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_connect_timeout(timeout)
        rpctransport.connect()
        rpctransport.disconnect()
    except Exception as e:
        nxc_logger.debug(f"Exception while connecting to {stringBinding}: {e}")
        return False, stringBinding
    else:
        return True, stringBinding


class connection:
    def __init__(self, args, db, host):
        self.domain = None
        self.args = args
        self.db = db
        self.hostname = host
        self.port = self.args.port
        self.conn = None
        self.admin_privs = False
        self.password = ""
        self.username = ""
        self.kerberos = bool(self.args.kerberos or self.args.use_kcache or self.args.aesKey)
        self.aesKey = None if not self.args.aesKey else self.args.aesKey[0]
        self.kdcHost = None if not self.args.kdcHost else self.args.kdcHost
        self.use_kcache = None if not self.args.use_kcache else self.args.use_kcache
        self.failed_logins = 0
        self.local_ip = None
        self.logger = nxc_logger

        try:
            self.host, self.is_ipv6, self.is_link_local_ipv6 = gethost_addrinfo(self.hostname)
            if self.args.kerberos:
                self.host = self.hostname
            self.logger.info(f"Socket info: host={self.host}, hostname={self.hostname}, kerberos={self.kerberos}, ipv6={self.is_ipv6}, link-local ipv6={self.is_link_local_ipv6}")
        except Exception as e:
            self.logger.info(f"Error resolving hostname {self.hostname}: {e}")
            return

        if args.jitter:
            jitter = args.jitter
            if "-" in jitter:
                start, end = jitter.split("-")
                jitter = (int(start), int(end))
            else:
                jitter = (0, int(jitter))

            value = random.choice(range(jitter[0], jitter[1]))
            self.logger.debug(f"Doin' the jitterbug for {value} second(s)")
            sleep(value)

        try:
            self.proto_flow()
        except Exception as e:
            self.logger.exception(f"Exception while calling proto_flow() on target {self.host}: {e}")

    @staticmethod
    def proto_args(std_parser, module_parser):
        return

    def proto_logger(self):
        pass

    def enum_host_info(self):
        return

    def print_host_info(self):
        return

    def create_conn_obj(self):
        return

    def check_if_admin(self):
        return

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
        return

    def plaintext_login(self, domain, username, password):
        return

    def hash_login(self, domain, username, ntlm_hash):
        return

    def proto_flow(self):
        self.logger.debug("Kicking off proto_flow")
        self.proto_logger()
        if self.create_conn_obj():
            self.logger.debug("Created connection object")
            self.enum_host_info()
            if self.print_host_info() and (self.login() or (self.username == "" and self.password == "")):
                if hasattr(self.args, "module") and self.args.module:
                    self.logger.debug("Calling modules")
                    self.call_modules()
                else:
                    self.logger.debug("Calling command arguments")
                    self.call_cmd_args()

    def call_cmd_args(self):
        """Calls all the methods specified by the command line arguments

        Iterates over the attributes of an object (self.args)
        For each attribute, it checks if the object (self) has an attribute with the same name and if that attribute is callable (i.e., a function)
        If both conditions are met and the attribute value is not False or None,
        it calls the function and logs a debug message

        Parameters
        ----------
            self (object): The instance of the class.

        Returns
        -------
            None
        """
        for attr, value in vars(self.args).items():
            if hasattr(self, attr) and callable(getattr(self, attr)) and value is not False and value is not None:
                self.logger.debug(f"Calling {attr}()")
                getattr(self, attr)()

    def call_modules(self):
        """Calls modules and performs various actions based on the module's attributes.

        It iterates over the modules specified in the command line arguments.
        For each module, it loads the module and creates a context object, then calls functions based on the module's attributes.
        """
        for module in self.module:
            self.logger.debug(f"Loading module {module.name} - {module}")
            module_logger = NXCAdapter(
                extra={
                    "module_name": module.name.upper(),
                    "host": self.host,
                    "port": self.args.port,
                    "hostname": self.hostname,
                },
            )

            self.logger.debug(f"Loading context for module {module.name} - {module}")
            context = Context(self.db, module_logger, self.args)
            context.localip = self.local_ip

            if hasattr(module, "on_request") or hasattr(module, "has_response"):
                self.logger.debug(f"Module {module.name} has on_request or has_response methods")
                self.server.connection = self
                self.server.context.localip = self.local_ip

            if hasattr(module, "on_login"):
                self.logger.debug(f"Module {module.name} has on_login method")
                module.on_login(context, self)

            if self.admin_privs and hasattr(module, "on_admin_login"):
                self.logger.debug(f"Module {module.name} has on_admin_login method")
                module.on_admin_login(context, self)

            if (not hasattr(module, "on_request") and not hasattr(module, "has_response")) and hasattr(module, "on_shutdown"):
                self.logger.debug(f"Module {module.name} has on_shutdown method")
                module.on_shutdown(context, self)

    def inc_failed_login(self, username):
        global global_failed_logins
        global user_failed_logins

        if username not in user_failed_logins:
            user_failed_logins[username] = 0

        user_failed_logins[username] += 1
        global_failed_logins += 1
        self.failed_logins += 1

    def over_fail_limit(self, username):
        global global_failed_logins
        global user_failed_logins

        if global_failed_logins == self.args.gfail_limit:
            return True

        if self.failed_logins == self.args.fail_limit:
            return True

        if username in user_failed_logins and self.args.ufail_limit == user_failed_logins[username]:
            return True

        return False

    def query_db_creds(self):
        """Queries the database for credentials to be used for authentication.

        Valid cred_id values are:
            - a single cred_id
            - a range specified with a dash (ex. 1-5)
            - 'all' to select all credentials

        :return: domains[], usernames[], owned[], secrets[], cred_types[]
        """
        domains = []
        usernames = []
        owned = []
        secrets = []
        cred_types = []
        creds = []  # list of tuples (cred_id, domain, username, secret, cred_type, pillaged_from) coming from the database
        data = []  # Arbitrary data needed for the login, e.g. ssh_key

        for cred_id in self.args.cred_id:
            if cred_id.lower() == "all":
                creds = self.db.get_credentials()
            else:
                if not self.db.get_credentials(filter_term=int(cred_id)):
                    self.logger.error(f"Invalid database credential ID {cred_id}!")
                    continue
                creds.extend(self.db.get_credentials(filter_term=int(cred_id)))

        for cred in creds:
            c_id, domain, username, secret, cred_type, pillaged_from = cred
            domains.append(domain)
            usernames.append(username)
            owned.append(False)  # As these are likely valid we still want to test them if they are specified in the command line
            secrets.append(secret)
            cred_types.append(cred_type)

        if len(secrets) != len(data):
            data = [None] * len(secrets)

        return domains, usernames, owned, secrets, cred_types, data

    def parse_credentials(self):
        r"""Parse credentials from the command line or from a file specified.

        Usernames can be specified with a domain (domain\\username) or without (username).
        If the file contains domain\\username the domain specified will be overwritten by the one in the file.

        :return: domain[], username[], owned[], secret[], cred_type[]
        """
        domain = []
        username = []
        owned = []
        secret = []
        cred_type = []

        # Parse usernames
        for user in self.args.username:
            if isfile(user):
                with open(user) as user_file:
                    for line in user_file:
                        if "\\" in line:
                            domain_single, username_single = line.split("\\")
                        else:
                            domain_single = self.args.domain if hasattr(self.args, "domain") and self.args.domain else self.domain
                            username_single = line
                        domain.append(domain_single)
                        username.append(username_single.strip())
                        owned.append(False)
            else:
                if "\\" in user:
                    domain_single, username_single = user.split("\\")
                else:
                    domain_single = self.args.domain if hasattr(self.args, "domain") and self.args.domain else self.domain
                    username_single = user
                domain.append(domain_single)
                username.append(username_single)
                owned.append(False)

        # Parse passwords
        for password in self.args.password:
            if isfile(password):
                try:
                    with open(password, errors=("ignore" if self.args.ignore_pw_decoding else "strict")) as password_file:
                        for line in password_file:
                            secret.append(line.strip())
                            cred_type.append("plaintext")
                except UnicodeDecodeError as e:
                    self.logger.error(f"{type(e).__name__}: Could not decode password file. Make sure the file only contains UTF-8 characters.")
                    self.logger.error("You can ignore non UTF-8 characters with the option '--ignore-pw-decoding'")
                    sys.exit(1)
            else:
                secret.append(password)
                cred_type.append("plaintext")

        # Parse NTLM-hashes
        if hasattr(self.args, "hash") and self.args.hash:
            for ntlm_hash in self.args.hash:
                if isfile(ntlm_hash):
                    with open(ntlm_hash) as ntlm_hash_file:
                        for line in ntlm_hash_file:
                            secret.append(line.strip())
                            cred_type.append("hash")
                else:
                    secret.append(ntlm_hash)
                    cred_type.append("hash")

        # Parse AES keys
        if self.args.aesKey:
            for aesKey in self.args.aesKey:
                if isfile(aesKey):
                    with open(aesKey) as aesKey_file:
                        for line in aesKey_file:
                            secret.append(line.strip())
                            cred_type.append("aesKey")
                else:
                    secret.append(aesKey)
                    cred_type.append("aesKey")

        # Allow trying multiple users with a single password
        if len(username) > 1 and len(secret) == 1:
            secret = secret * len(username)
            cred_type = cred_type * len(username)
            self.args.no_bruteforce = True

        return domain, username, owned, secret, cred_type, [None] * len(secret)

    def try_credentials(self, domain, username, owned, secret, cred_type, data=None):
        """Try to login using the specified credentials and protocol.

        Possible login methods are:
            - plaintext (/kerberos)
            - NTLM-hash (/kerberos)
            - AES-key
        """
        if self.over_fail_limit(username):
            return False
        if self.args.continue_on_success and owned:
            return False
        if hasattr(self.args, "delegate") and self.args.delegate:
            self.args.kerberos = True
        with sem:
            if cred_type == "plaintext":
                if self.args.kerberos:
                    self.logger.debug("Trying to authenticate using Kerberos")
                    return self.kerberos_login(domain, username, secret, "", "", self.kdcHost, False)
                elif hasattr(self.args, "domain"):  # Some protocols don't use domain for login
                    self.logger.debug("Trying to authenticate using plaintext with domain")
                    return self.plaintext_login(domain, username, secret)
                elif self.args.protocol == "ssh":
                    self.logger.debug("Trying to authenticate using plaintext over SSH")
                    return self.plaintext_login(username, secret, data)
                else:
                    self.logger.debug("Trying to authenticate using plaintext")
                    return self.plaintext_login(username, secret)
            elif cred_type == "hash":
                if self.args.kerberos:
                    return self.kerberos_login(domain, username, "", secret, "", self.kdcHost, False)
                return self.hash_login(domain, username, secret)
            elif cred_type == "aesKey":
                return self.kerberos_login(domain, username, "", "", secret, self.kdcHost, False)

    def login(self):
        """Try to login using the credentials specified in the command line or in the database.

        :return: True if the login was successful and "--continue-on-success" was not specified, False otherwise.
        """
        # domain[n] always corresponds to username[n] and owned [n]
        domain = []
        username = []
        owned = []  # Determines whether we have found a valid credential for this user. Default: False
        # secret[n] always corresponds to cred_type[n]
        secret = []
        cred_type = []
        data = []  # Arbitrary data needed for the login, e.g. ssh_key

        if self.args.cred_id:
            db_domain, db_username, db_owned, db_secret, db_cred_type, db_data = self.query_db_creds()
            domain.extend(db_domain)
            username.extend(db_username)
            owned.extend(db_owned)
            secret.extend(db_secret)
            cred_type.extend(db_cred_type)
            data.extend(db_data)

        if self.args.username:
            parsed_domain, parsed_username, parsed_owned, parsed_secret, parsed_cred_type, parsed_data = self.parse_credentials()
            domain.extend(parsed_domain)
            username.extend(parsed_username)
            owned.extend(parsed_owned)
            secret.extend(parsed_secret)
            cred_type.extend(parsed_cred_type)
            data.extend(parsed_data)

        if self.args.use_kcache:
            self.logger.debug("Trying to authenticate using Kerberos cache")
            with sem:
                username = self.args.username[0] if len(self.args.username) else ""
                password = self.args.password[0] if len(self.args.password) else ""
                self.kerberos_login(self.domain, username, password, "", "", self.kdcHost, True)
                self.logger.info("Successfully authenticated using Kerberos cache")
                return True

        if hasattr(self.args, "laps") and self.args.laps:
            self.logger.debug("Trying to authenticate using LAPS")
            username[0], secret[0], domain[0], ntlm_hash = laps_search(self, username, secret, cred_type, domain)
            cred_type = ["plaintext"]
            if not (username[0] or secret[0] or domain[0]):
                return False

        if not self.args.no_bruteforce:
            for secr_index, secr in enumerate(secret):
                for user_index, user in enumerate(username):
                    if self.try_credentials(domain[user_index], user, owned[user_index], secr, cred_type[secr_index], data[secr_index]):
                        owned[user_index] = True
                        if not self.args.continue_on_success:
                            return True
        else:
            if len(username) != len(secret):
                self.logger.error("Number provided of usernames and passwords/hashes do not match!")
                return False
            for user_index, user in enumerate(username):
                if self.try_credentials(domain[user_index], user, owned[user_index], secret[user_index], cred_type[user_index], data[user_index]) and not self.args.continue_on_success:
                    owned[user_index] = True
                    if not self.args.continue_on_success:
                        return True

    def mark_pwned(self):
        return highlight(f"({pwned_label})" if self.admin_privs else "")
