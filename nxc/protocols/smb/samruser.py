# Stolen from Impacket

from datetime import datetime, timedelta

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.rpcrt import DCERPCException

from nxc.helpers.rpc import NXCRPCConnection


class UserSamrDump:
    def __init__(self, connection):
        self.logger = connection.logger
        self.connection = connection
        self.users = []
        self.dce = None

    def dump(self, requested_users=None, dump_path=None):
        try:
            self.dce = NXCRPCConnection(self.connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
        except Exception as e:
            self.logger.debug(f"Failed to connect to SAMR: {e}")
            return self.users

        try:
            self.fetch_users(requested_users, dump_path)
        except Exception as e:
            self.logger.debug(f"Connection failed: {e}")
        return self.users

    def fetch_users(self, requested_users, dump_path):
        users = []

        # Setup Connection
        resp = samr.hSamrConnect2(self.dce)
        if resp["ErrorCode"] != 0:
            raise Exception("Connect error")

        resp2 = samr.hSamrEnumerateDomainsInSamServer(
            self.dce,
            serverHandle=resp["ServerHandle"],
            enumerationContext=0,
            preferedMaximumLength=500,
        )
        if resp2["ErrorCode"] != 0:
            raise Exception("Connect error")

        domain_name = resp2["Buffer"]["Buffer"][0]["Name"]
        resp3 = samr.hSamrLookupDomainInSamServer(
            self.dce,
            serverHandle=resp["ServerHandle"],
            name=domain_name,
        )
        if resp3["ErrorCode"] != 0:
            raise Exception("Connect error")

        resp4 = samr.hSamrOpenDomain(
            self.dce,
            serverHandle=resp["ServerHandle"],
            desiredAccess=samr.MAXIMUM_ALLOWED,
            domainId=resp3["DomainId"],
        )
        if resp4["ErrorCode"] != 0:
            raise Exception("Connect error")

        self.__domains = resp2["Buffer"]["Buffer"]
        domain_handle = resp4["DomainHandle"]
        # End Setup

        if requested_users:
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
        else:
            users = self.query_display_users(domain_handle)

        self.logger.display(f"Enumerated {len(users)} local users: {domain_name}")
        if dump_path:
            self.logger.display(f"Writing {len(users)} local users to {dump_path}")
            with open(dump_path, "w+") as file:
                file.writelines(f"{user}\n" for user in users)
        self.dce.disconnect()

    def query_display_users(self, domain_handle):
        """Enumerate users via SamrQueryDisplayInformation in a single bulk call instead of per-user handle opens."""
        users = []
        self.logger.highlight(f"{'-Username-':<30}{'-Rid-':<8}{'-Full Name-':<25}{'-Description-':<60}")
        index = 0
        while True:
            try:
                resp = samr.hSamrQueryDisplayInformation(
                    self.dce,
                    domain_handle,
                    displayInformationClass=samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser,
                    index=index,
                    entryCount=0xffffffff,
                    preferedMaximumLength=0xffffffff,
                )
                more = False
            except DCERPCException as e:
                if "STATUS_MORE_ENTRIES" not in str(e):
                    self.logger.fail(f"QueryDisplayInformation error: {e}")
                    break
                resp = e.get_packet()
                more = True

            entries = resp["Buffer"]["UserInformation"]["Buffer"]
            for entry in entries:
                name = entry["AccountName"] or ""
                desc = entry["AdminComment"] or ""
                full = entry["FullName"] or ""
                rid = entry["Rid"]
                users.append(name)
                self.logger.highlight(f"{name:<30}{rid:<8}{full:<25}{desc}")

            if not more or not entries:
                break
            index = entries[-1]["Index"] + 1

        return users

    def get_user_info(self, domain_handle, user_ids):
        self.logger.debug(f"Getting user info for users: {user_ids}")
        self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8}{'-Description-':<60}")
        users = []

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
            last_pw_set = old_large_int_to_datetime(user_info["PasswordLastSet"])
            if last_pw_set == "1601-01-01 00:00:00":
                last_pw_set = "<never>"
            users.append(user_name)
            self.logger.highlight(f"{user_name:<30}{last_pw_set:<20}{bad_pwd_count:<8}{user_description} ")
            samr.hSamrCloseHandle(self.dce, open_user_resp["UserHandle"])
        return users


def old_large_int_to_datetime(large_int):
    combined = (large_int["HighPart"] << 32) | large_int["LowPart"]
    timestamp_seconds = combined / 10**7
    start_date = datetime(1601, 1, 1)
    return (start_date + timedelta(seconds=timestamp_seconds)).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
