# Majorly stolen from https://gist.github.com/ropnop/7a41da7aabb8455d0898db362335e139
# Which in turn stole from Impacket :)
# Code refactored and added to by @mjhallenbeck (Marshall-Hallenbeck on GitHub)

import logging

from impacket.dcerpc.v5 import transport, lsat, lsad, samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.nmb import NetBIOSError
from impacket.smbconnection import SessionError
from nxc.logger import nxc_logger


class SamrFunc:
    def __init__(self, connection):
        self.logger = connection.logger
        self.addr = connection.host
        self.protocol = connection.args.port
        self.username = connection.username
        self.password = connection.password
        self.domain = connection.domain
        self.hash = connection.hash
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = connection.aesKey
        self.doKerberos = connection.kerberos
        self.kdcHost = connection.kdcHost

        if self.hash is not None:
            if self.hash.find(":") != -1:
                self.lmhash, self.nthash = self.hash.split(":")
            else:
                self.nthash = self.hash

        if self.password is None:
            self.password = ""

        self.samr_query = SAMRQuery(username=self.username, password=self.password, domain=self.domain, remote_name=self.addr, remote_host=self.host, kerberos=self.doKerberos, kdcHost=self.kdcHost, aesKey=self.aesKey)
        self.lsa_query = LSAQuery(username=self.username, password=self.password, domain=self.domain, remote_name=self.addr, remote_host=self.host, kdcHost=self.kdcHost, kerberos=self.doKerberos, aesKey=self.aesKey, logger=self.logger)

    def get_builtin_groups(self):
        domains = self.samr_query.get_domains()

        if "Builtin" not in domains:
            logging.error("No Builtin group to query locally on")
            return None

        domain_handle = self.samr_query.get_domain_handle("Builtin")
        return self.samr_query.get_domain_aliases(domain_handle)

    def get_custom_groups(self):
        domains = self.samr_query.get_domains()
        custom_groups = {}

        for domain in domains:
            if domain == "Builtin":
                continue
            domain_handle = self.samr_query.get_domain_handle(domain)
            custom_groups.update(self.samr_query.get_domain_aliases(domain_handle))
        return custom_groups

    def get_local_groups(self):
        builtin_groups = self.get_builtin_groups()
        custom_groups = self.get_custom_groups()
        return {**builtin_groups, **custom_groups}

    def get_local_users(self):
        pass

    def get_local_administrators(self):
        self.get_builtin_groups()
        if "Administrators" in self.groups:
            self.logger.success(f"Found Local Administrators group: RID {self.groups['Administrators']}")
        domain_handle = self.samr_query.get_domain_handle("Builtin")
        self.logger.debug("Querying group members")
        member_sids = self.samr_query.get_alias_members(domain_handle, self.groups["Administrators"])
        member_names = self.lsa_query.lookup_sids(member_sids)

        for sid, name in zip(member_sids, member_names):
            print(f"{name} - {sid}")


class SAMRQuery:
    def __init__(
        self,
        username="",
        password="",
        domain="",
        port=445,
        remote_name="",
        remote_host="",
        kerberos=None,
        kdcHost="",
        aesKey="",
    ):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = aesKey
        self.__port = port
        self.__remote_name = remote_name
        self.__remote_host = remote_host
        self.__kerberos = kerberos
        self.__kdcHost = kdcHost
        self.dce = self.get_dce()
        self.server_handle = self.get_server_handle()

    def get_transport(self):
        string_binding = rf"ncacn_np:{self.__port}[\pipe\samr]"
        nxc_logger.debug(f"Binding to {string_binding}")
        # using a direct SMBTransport instead of DCERPCTransportFactory since we need the filename to be '\samr'
        return transport.SMBTransport(
            self.__remote_name,
            self.__port,
            r"\samr",
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            doKerberos=self.__kerberos,
            kdcHost=self.__kdcHost,
        )

    def get_dce(self):
        rpc_transport = self.get_transport()
        rpc_transport.setRemoteHost(self.__remote_host)
        try:
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
        except NetBIOSError as e:
            logging.error(f"NetBIOSError on Connection: {e}")
            return None
        except SessionError as e:
            logging.error(f"SessionError on Connection: {e}")
            return None
        return dce

    def get_server_handle(self):
        if self.dce:
            try:
                resp = samr.hSamrConnect(self.dce)
            except samr.DCERPCException as e:
                nxc_logger.debug(f"Error while connecting with Samr: {e}")
                return None
            return resp["ServerHandle"]
        else:
            nxc_logger.debug("Error creating Samr handle")

    def get_domains(self):
        """Calls the hSamrEnumerateDomainsInSamServer() method directly with list comprehension and extracts the "Name" value from each element in the "Buffer" list."""
        domains = samr.hSamrEnumerateDomainsInSamServer(self.dce, self.server_handle)["Buffer"]["Buffer"]
        return [domain["Name"] for domain in domains]

    def get_domain_handle(self, domain_name):
        resp = samr.hSamrLookupDomainInSamServer(self.dce, self.server_handle, domain_name)
        resp = samr.hSamrOpenDomain(self.dce, serverHandle=self.server_handle, domainId=resp["DomainId"])
        return resp["DomainHandle"]

    def get_domain_aliases(self, domain_handle):
        """Use a dictionary comprehension to generate the aliases dictionary.

        Calls the hSamrEnumerateAliasesInDomain() method directly in the dictionary comprehension and extracts the "Name" and "RelativeId" values from each element in the "Buffer" list
        """
        return {alias["Name"]: alias["RelativeId"] for alias in samr.hSamrEnumerateAliasesInDomain(self.dce, domain_handle)["Buffer"]["Buffer"]}

    def get_alias_handle(self, domain_handle, alias_id):
        resp = samr.hSamrOpenAlias(self.dce, domain_handle, desiredAccess=MAXIMUM_ALLOWED, aliasId=alias_id)
        return resp["AliasHandle"]

    def get_alias_members(self, domain_handle, alias_id):
        """Calls the hSamrGetMembersInAlias() method directly with list comprehension and extracts the "SidPointer" value from each element in the "Sids" list."""
        alias_handle = self.get_alias_handle(domain_handle, alias_id)
        return [member["SidPointer"].formatCanonical() for member in samr.hSamrGetMembersInAlias(self.dce, alias_handle)["Members"]["Sids"]]


class LSAQuery:
    def __init__(self, username="", password="", domain="", port=445, remote_name="", remote_host="", kdcHost="", aesKey="", kerberos=None, logger=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = aesKey
        self.__port = port
        self.__remote_name = remote_name
        self.__remote_host = remote_host
        self.__kdcHost = kdcHost
        self.__kerberos = kerberos
        self.dce = self.get_dce()
        self.policy_handle = self.get_policy_handle()
        self.logger = logger

    def get_transport(self):
        string_binding = f"ncacn_np:{self.__remote_name}[\\pipe\\lsarpc]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_dport(self.__port)
        rpc_transport.setRemoteHost(self.__remote_host)
        if self.__kerberos:
            rpc_transport.set_kerberos(self.__kerberos, self.__kdcHost)
        if hasattr(rpc_transport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
        return rpc_transport

    def get_dce(self):
        rpc_transport = self.get_transport()
        try:
            dce = rpc_transport.get_dce_rpc()
            if self.__kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)
        except NetBIOSError as e:
            self.logger.fail(f"NetBIOSError on Connection: {e}")
            return None
        return dce

    def get_policy_handle(self):
        resp = lsad.hLsarOpenPolicy2(self.dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        return resp["PolicyHandle"]

    def lookup_sids(self, sids):
        """Use a list comprehension to generate the names list.

        It calls the hLsarLookupSids() method directly in the list comprehension and extracts the "Name" value from each element in the "Names" list.
        """
        return [translated_names["Name"] for translated_names in lsat.hLsarLookupSids(self.dce, self.policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)["TranslatedNames"]["Names"]]
