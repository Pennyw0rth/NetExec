# Stolen from https://github.com/Wh1t3Fox/polenum

from impacket.dcerpc.v5 import samr
from nxc.logger import nxc_logger
from nxc.helpers.misc import convert, d2b
from nxc.helpers.rpc import NXCRPCConnection


class PassPolDump:
    def __init__(self, connection):
        self.logger = connection.logger
        self.connection = connection
        self.pass_pol = {}

    def dump(self):
        try:
            dce = NXCRPCConnection(self.connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
        except Exception as e:
            nxc_logger.debug(f"Failed to connect to SAMR: {e}")
            return self.pass_pol

        try:
            self.fetchList(dce)
        except Exception as e:
            nxc_logger.debug(f"Protocol failed: {e}")
        else:
            self.pretty_print()

        return self.pass_pol

    def fetchList(self, dce):
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

        re = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle=domainHandle,
            domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
        )
        self.__min_pass_len = re["Buffer"]["Password"]["MinPasswordLength"] or "None"
        self.__pass_hist_len = re["Buffer"]["Password"]["PasswordHistoryLength"] or "None"
        self.__max_pass_age = convert(
            int(re["Buffer"]["Password"]["MaxPasswordAge"]["LowPart"]),
            int(re["Buffer"]["Password"]["MaxPasswordAge"]["HighPart"]),
        )
        self.__min_pass_age = convert(
            int(re["Buffer"]["Password"]["MinPasswordAge"]["LowPart"]),
            int(re["Buffer"]["Password"]["MinPasswordAge"]["HighPart"]),
        )
        self.__pass_prop = d2b(re["Buffer"]["Password"]["PasswordProperties"])

        re = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle=domainHandle,
            domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
        )
        self.__rst_accnt_lock_counter = convert(0, re["Buffer"]["Lockout"]["LockoutObservationWindow"], lockout=True)
        self.__lock_accnt_dur = convert(0, re["Buffer"]["Lockout"]["LockoutDuration"], lockout=True)
        self.__accnt_lock_thres = re["Buffer"]["Lockout"]["LockoutThreshold"] or "None"

        re = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle=domainHandle,
            domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation,
        )
        self.__force_logoff_time = convert(
            re["Buffer"]["Logoff"]["ForceLogoff"]["LowPart"],
            re["Buffer"]["Logoff"]["ForceLogoff"]["HighPart"],
        )

        self.pass_pol = {
            "min_pass_len": self.__min_pass_len,
            "pass_hist_len": self.__pass_hist_len,
            "max_pass_age": self.__max_pass_age,
            "min_pass_age": self.__min_pass_age,
            "pass_prop": self.__pass_prop,
            "rst_accnt_lock_counter": self.__rst_accnt_lock_counter,
            "lock_accnt_dur": self.__lock_accnt_dur,
            "accnt_lock_thres": self.__accnt_lock_thres,
            "force_logoff_time": self.__force_logoff_time,
        }

        dce.disconnect()

    def pretty_print(self):
        PASSCOMPLEX = {
            5: "Domain Password Complex:",
            4: "Domain Password No Anon Change:",
            3: "Domain Password No Clear Change:",
            2: "Domain Password Lockout Admins:",
            1: "Domain Password Store Cleartext:",
            0: "Domain Refuse Password Change:",
        }

        nxc_logger.debug("Found domain(s):")
        for domain in self.__domains:
            nxc_logger.debug(f"{domain['Name']}")

        self.logger.success(f"Dumping password info for domain: {self.__domains[0]['Name']}")
        self.logger.highlight(f"Minimum password length: {self.__min_pass_len}")
        self.logger.highlight(f"Password history length: {self.__pass_hist_len}")
        self.logger.highlight(f"Maximum password age: {self.__max_pass_age}")
        self.logger.highlight("")
        self.logger.highlight(f"Password Complexity Flags: {self.__pass_prop or 'None'}")

        for i, a in enumerate(self.__pass_prop):
            self.logger.highlight(f"\t{PASSCOMPLEX[i]} {a!s}")

        self.logger.highlight("")
        self.logger.highlight(f"Minimum password age: {self.__min_pass_age}")
        self.logger.highlight(f"Reset Account Lockout Counter: {self.__rst_accnt_lock_counter}")
        self.logger.highlight(f"Locked Account Duration: {self.__lock_accnt_dur}")
        self.logger.highlight(f"Account Lockout Threshold: {self.__accnt_lock_thres}")
        self.logger.highlight(f"Forced Log off Time: {self.__force_logoff_time}")
