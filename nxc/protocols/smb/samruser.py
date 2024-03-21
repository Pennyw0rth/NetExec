# Stolen from Impacket

from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.nt_errors import STATUS_MORE_ENTRIES
from datetime import datetime, timedelta


class UserSamrDump:
    KNOWN_PROTOCOLS = {
        "139/SMB": (r"ncacn_np:%s[\pipe\samr]", 139),
        "445/SMB": (r"ncacn_np:%s[\pipe\samr]", 445),
    }

    def __init__(self, connection):
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
        self.protocols = UserSamrDump.KNOWN_PROTOCOLS.keys()
        self.users = []
        self.rpc_transport = None
        self.dce = None

        if self.hash is not None:
            if self.hash.find(":") != -1:
                self.lmhash, self.nthash = self.hash.split(":")
            else:
                self.nthash = self.hash

        if self.password is None:
            self.password = ""

    def dump(self, requested_users=None):
        # Try all requested protocols until one works.
        for protocol in self.protocols:
            try:
                protodef = UserSamrDump.KNOWN_PROTOCOLS[protocol]
                port = protodef[1]
            except KeyError:
                self.logger.debug(f"Invalid Protocol: {protocol}")

            self.logger.debug(f"Trying protocol {protocol}")
            self.rpc_transport = transport.SMBTransport(self.addr, port, r"\samr", self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, doKerberos=self.doKerberos)

            try:
                self.fetch_users(requested_users)
                break
            except Exception as e:
                self.logger.debug(f"Connection with protocol {protocol} failed: {e}")
        return self.users

    def fetch_users(self, requested_users):
        self.dce = DCERPC_v5(self.rpc_transport)
        self.dce.connect()
        self.dce.bind(samr.MSRPC_UUID_SAMR)

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

        resp3 = samr.hSamrLookupDomainInSamServer(
            self.dce,
            serverHandle=resp["ServerHandle"],
            name=resp2["Buffer"]["Buffer"][0]["Name"],
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
        self.print_user_info(users)
        self.dce.disconnect()

    def get_user_info(self, domain_handle, user_ids):
        self.logger.debug(f"Getting user info for users: {user_ids}")
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
            users.append({"name": user_name, "description": user_description, "bad_pwd_count": bad_pwd_count, "last_pw_set": last_pw_set})

            samr.hSamrCloseHandle(self.dce, open_user_resp["UserHandle"])
        return users

    def print_user_info(self, users):
        self.logger.highlight(f"{'-Username-':<30}{'-Last PW Set-':<20}{'-BadPW-':<8}{'-Description-':<60}")
        for user in users:
            self.logger.debug(f"Full user info: {user}")
            self.logger.highlight(f"{user['name']:<30}{user['last_pw_set']:<20}{user['bad_pwd_count']:<8}{user['description']} ")


def old_large_int_to_datetime(large_int):
    combined = (large_int["HighPart"] << 32) | large_int["LowPart"]
    timestamp_seconds = combined / 10**7
    start_date = datetime(1601, 1, 1)
    return (start_date + timedelta(seconds=timestamp_seconds)).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
