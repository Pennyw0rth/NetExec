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
from nxc.credentials import credentials
from nxc.protocols.ldap.laps import laps_search

from impacket.dcerpc.v5 import transport
import sys
import contextlib

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
            if "ERROR_DEPENDENT_SERVICES_RUNNING" in str(e):
                self.logger.error(f"Exception while calling proto_flow() on target {self.host}: {e}")
            else:
                self.logger.exception(f"Exception while calling proto_flow() on target {self.host}: {e}")
        finally:
            self.logger.debug(f"Closing connection to: {host}")
            with contextlib.suppress(Exception):
                self.conn.close()

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
        if not self.create_conn_obj():
            self.logger.info(f"Failed to create connection object for target {self.host}, exiting...")
        else:
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

        :return: True if the login was successful, False otherwise.
        """

        creds = credentials(self.args, self.db)

        if self.args.use_kcache:
            self.logger.debug("Trying to authenticate using Kerberos cache")
            with sem:
                username = creds.usernames[0] if len(creds.usernames) else ""
                password = creds.passwords[0] if len(creds.passwords) else ""
                domain = creds.domains[0] if len(creds.domains) else ""
                if (self.kerberos_login(domain, username, password, "", "", self.kdcHost, True)):
                    self.logger.info("Successfully authenticated using Kerberos cache")
                    return True

        if hasattr(self.args, "laps") and self.args.laps:
            self.logger.debug("Trying to authenticate using LAPS")
            creds.usernames[0], creds.secrets[0], creds.domains[0], ntlm_hash = laps_search(self, username, secret, cred_type, domain)
            cred_type = ["plaintext"]
            if not (username[0] or secret[0] or domain[0]):
                return False

        owned = [False]* len(creds.usernames)  # Determines whether we have found a valid credential for this user. Default: False
        if not self.args.no_bruteforce:
            for secr_index, secr in enumerate(creds.secrets):
                for user_index, user in enumerate(creds.usernames):
                    if self.try_credentials(creds.domains[user_index], user, owned[user_index], secr, creds.cred_types[secr_index], creds.data[secr_index]):
                        owned[user_index] = True
                        if not self.args.continue_on_success:
                            return True
        else:
            if len(creds.usernames) != len(creds.secrets):
                self.logger.error("Number provided of usernames and passwords/hashes do not match!")
                return False
            for user_index, user in enumerate(creds.usernames):
                if self.try_credentials(creds.domains[user_index], user, owned[user_index], creds.secrets[user_index], creds.cred_types[user_index], creds.data[user_index]):
                    owned[user_index] = True
                    if not self.args.continue_on_success:
                        return True

        return True in owned

    def mark_pwned(self):
        return highlight(f"({pwned_label})" if self.admin_privs else "")
