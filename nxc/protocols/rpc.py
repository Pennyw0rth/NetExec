import os
import contextlib

from impacket import ntlm
from impacket.uuid import uuidtup_to_bin
from impacket.krb5.ccache import CCache
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED
from impacket.dcerpc.v5 import transport, epm, samr, lsat, lsad, srvs, wkst
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_AUTHN_WINNT,
    RPC_C_AUTHN_GSS_NEGOTIATE,
    MSRPC_BIND,
    MSRPCBind,
    CtxItem,
    MSRPCHeader,
    SEC_TRAILER,
    MSRPCBindAck,
    DCERPCException,
)
from impacket.dcerpc.v5.samr import MSRPC_UUID_SAMR
from impacket.dcerpc.v5.lsat import MSRPC_UUID_LSAT
from impacket.dcerpc.v5.srvs import MSRPC_UUID_SRVS
from impacket.dcerpc.v5.wkst import MSRPC_UUID_WKST

from nxc.config import process_secret
from nxc.connection import connection
from nxc.helpers.ntlm_parser import parse_challenge
from nxc.logger import NXCAdapter

MSRPC_UUID_PORTMAP = uuidtup_to_bin(("E1AF8308-5D1F-11C9-91A4-08002B14A0FA", "3.0"))


class rpc(connection):
    def __init__(self, args, db, host):
        self.domain = ""
        self.targetDomain = ""
        self.hash = ""
        self.lmhash = ""
        self.nthash = ""
        self.server_os = None
        self.doKerberos = False
        self.samr_dce = None
        self.lsa_dce = None
        self.srvs_dce = None
        self.wkst_dce = None
        self.smb_conn = None  # SMB connection for SRVS/named pipe operations
        self.domain_handle = None
        self.builtin_handle = None
        self.server_handle = None
        self.policy_handle = None
        self.domain_sid = None
        self.machine_name = None
        self.protocol = "RPC"

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "RPC",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def disconnect(self):
        for dce in [self.samr_dce, self.lsa_dce, self.srvs_dce, self.wkst_dce]:
            if dce:
                with contextlib.suppress(Exception):
                    dce.disconnect()
        if self.smb_conn:
            with contextlib.suppress(Exception):
                self.smb_conn.close()

    def create_conn_obj(self):
        connection_target = f"ncacn_ip_tcp:{self.host}[{self.port!s}]"
        self.logger.debug(f"Creating RPC connection to {connection_target}")
        try:
            rpctransport = transport.DCERPCTransportFactory(connection_target)
            rpctransport.set_credentials("", "", "", "", "", "")
            rpctransport.setRemoteHost(self.host)
            rpctransport.set_connect_timeout(self.args.rpc_timeout)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
            dce.disconnect()
        except Exception as e:
            self.logger.debug(f"Error creating RPC connection: {e}")
            return False
        self.conn = rpctransport
        return True

    def enum_host_info(self):
        bind = MSRPCBind()
        item = CtxItem()
        item["AbstractSyntax"] = epm.MSRPC_UUID_PORTMAP
        item["TransferSyntax"] = uuidtup_to_bin(("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0"))
        item["ContextID"] = 0
        item["TransItems"] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet["type"] = MSRPC_BIND
        packet["pduData"] = bind.getData()
        packet["call_id"] = 1

        auth = ntlm.getNTLMSSPType1("", "", signingRequired=True, use_ntlmv2=True)
        sec_trailer = SEC_TRAILER()
        sec_trailer["auth_type"] = RPC_C_AUTHN_WINNT
        sec_trailer["auth_level"] = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
        sec_trailer["auth_ctx_id"] = 79231
        pad = (4 - (len(packet.get_packet()) % 4)) % 4
        if pad != 0:
            packet["pduData"] += b"\xFF" * pad
            sec_trailer["auth_pad_len"] = pad
        packet["sec_trailer"] = sec_trailer
        packet["auth_data"] = auth

        try:
            self.conn.connect()
            self.conn.send(packet.get_packet())
            buffer = self.conn.recv()
        except Exception:
            buffer = 0

        if buffer != 0:
            response = MSRPCHeader(buffer)
            bindResp = MSRPCBindAck(response.getData())
            ntlm_info = parse_challenge(bindResp["auth_data"])
            self.targetDomain = self.domain = ntlm_info["domain"]
            self.hostname = ntlm_info["hostname"]
            self.server_os = ntlm_info["os_version"]
            self.logger.extra["hostname"] = self.hostname
        else:
            self.hostname = self.host

        if self.args.local_auth:
            self.domain = self.hostname
        if self.args.domain:
            self.domain = self.args.domain

        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None

    def print_host_info(self):
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.targetDomain})")

    def check_if_admin(self):
        pass

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        lmhash = ""
        nthash = ""
        self.password = password
        self.username = username
        self.domain = domain
        self.create_conn_obj()

        if password == "" and ntlm_hash:
            if ":" in ntlm_hash:
                lmhash, nthash = ntlm_hash.split(":")
            else:
                nthash = ntlm_hash
            self.nthash = nthash
            self.lmhash = lmhash

        kerb_pass = next((s for s in [nthash, password, aesKey] if s), "")
        if useCache and kerb_pass == "":
            ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            username = ccache.credentials[0].header["client"].prettyPrint().decode().split("@")[0]
            self.username = username
        used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"

        try:
            string_binding = epm.hept_map(self.host, MSRPC_UUID_SAMR, protocol="ncacn_ip_tcp")
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(self.host)
            rpctransport.set_connect_timeout(self.args.rpc_timeout)
            rpctransport.set_credentials(username, password, domain, lmhash, nthash, self.aesKey)
            rpctransport.set_kerberos(True, kdcHost)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_SAMR)
            samr.hSamrConnect(dce)
            self.doKerberos = True
            self.logger.success(f"{domain}\\{username}{used_ccache} {self.mark_pwned()}")
            dce.disconnect()
            return True
        except Exception as e:
            error_msg = str(e)
            if "STATUS_LOGON_FAILURE" in error_msg or "SEC_E_LOGON_DENIED" in error_msg or "STATUS_ACCESS_DENIED" in error_msg:
                error_msg = "Authentication failed"
            elif "KDC_ERR" in error_msg:
                error_msg = error_msg.split(":")[-1].strip() if ":" in error_msg else error_msg
            elif "rpc_s_access_denied" in error_msg:
                error_msg = "Access denied"
            self.logger.fail(f"{domain}\\{username}{used_ccache} {error_msg}")
            return False

    def plaintext_login(self, domain, username, password):
        self.password = password
        self.username = username
        self.domain = domain
        try:
            string_binding = epm.hept_map(self.host, MSRPC_UUID_SAMR, protocol="ncacn_ip_tcp")
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(self.host)
            rpctransport.set_connect_timeout(self.args.rpc_timeout)
            rpctransport.set_credentials(username, password, domain, self.lmhash, self.nthash)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_SAMR)
            samr.hSamrConnect(dce)
            dce.disconnect()
            out = f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}"
            if username == "" and password == "":
                out += "(Default allow anonymous login)"
            self.logger.success(out)
            return True
        except Exception as e:
            error_msg = str(e)
            if "STATUS_LOGON_FAILURE" in error_msg or "SEC_E_LOGON_DENIED" in error_msg or "STATUS_ACCESS_DENIED" in error_msg:
                error_msg = "Authentication failed"
            elif "rpc_s_access_denied" in error_msg:
                error_msg = "Access denied"
            self.logger.fail(f"{domain}\\{username}:{process_secret(password)} {error_msg}")
            return False

    def hash_login(self, domain, username, ntlm_hash):
        self.username = username
        self.domain = domain
        if ":" in ntlm_hash:
            self.lmhash, self.nthash = ntlm_hash.split(":")
        else:
            self.nthash = ntlm_hash
        try:
            string_binding = epm.hept_map(self.host, MSRPC_UUID_SAMR, protocol="ncacn_ip_tcp")
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(self.host)
            rpctransport.set_connect_timeout(self.args.rpc_timeout)
            rpctransport.set_credentials(username, self.password, domain, self.lmhash, self.nthash)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_SAMR)
            samr.hSamrConnect(dce)
            dce.disconnect()
            out = f"{domain}\\{username}:{process_secret(self.nthash)} {self.mark_pwned()}"
            self.logger.success(out)
            return True
        except Exception as e:
            error_msg = str(e)
            if "STATUS_LOGON_FAILURE" in error_msg or "SEC_E_LOGON_DENIED" in error_msg or "STATUS_ACCESS_DENIED" in error_msg:
                error_msg = "Authentication failed"
            elif "rpc_s_access_denied" in error_msg:
                error_msg = "Access denied"
            self.logger.fail(f"{domain}\\{username}:{process_secret(self.nthash)} {error_msg}")
            return False

    def get_dce_rpc(self, interface_uuid, named_pipe=None, use_tcp=False):
        is_anonymous = not self.username and not self.password and not self.nthash
        
        if named_pipe and (is_anonymous or not use_tcp):
            string_binding = f"ncacn_np:{self.host}[\\pipe\\{named_pipe}]"
        else:
            try:
                string_binding = epm.hept_map(self.host, interface_uuid, protocol="ncacn_ip_tcp")
            except Exception:
                if named_pipe:
                    string_binding = f"ncacn_np:{self.host}[\\pipe\\{named_pipe}]"
                else:
                    raise
        
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.setRemoteHost(self.host)
        rpctransport.set_connect_timeout(self.args.rpc_timeout)
        rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)
        
        if self.doKerberos:
            rpctransport.set_kerberos(True, self.kdcHost)
        
        dce = rpctransport.get_dce_rpc()
        if self.doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        elif not is_anonymous:
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        
        dce.connect()
        dce.bind(interface_uuid)
        return dce

    def get_samr_dce(self):
        if not self.samr_dce:
            self.samr_dce = self.get_dce_rpc(MSRPC_UUID_SAMR, "samr", use_tcp=True)
        return self.samr_dce

    def get_samr_dce_np(self):
        """Get SAMR DCE over SMB transport (required for password operations)"""
        rpctransport = transport.SMBTransport(self.host, filename=r"\samr")
        rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)
        if self.doKerberos:
            rpctransport.set_kerberos(True, self.kdcHost)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(MSRPC_UUID_SAMR)
        return dce

    def get_lsa_dce(self):
        if not self.lsa_dce:
            self.lsa_dce = self.get_dce_rpc(MSRPC_UUID_LSAT, "lsarpc")
        return self.lsa_dce

    def get_smb_connection(self):
        if not self.smb_conn:
            self.smb_conn = SMBConnection(self.hostname or self.host, self.host, timeout=self.args.rpc_timeout)
            if self.doKerberos:
                self.smb_conn.kerberosLogin(
                    self.username,
                    self.password,
                    self.domain,
                    self.lmhash,
                    self.nthash,
                    self.aesKey,
                    self.kdcHost,
                )
            else:
                self.smb_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        return self.smb_conn

    def get_srvs_dce(self):
        if not self.srvs_dce:
            smb = self.get_smb_connection()
            rpctransport = transport.SMBTransport(self.host, filename=r"\srvsvc", smb_connection=smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(MSRPC_UUID_SRVS)
            self.srvs_dce = dce
        return self.srvs_dce

    def get_wkst_dce(self):
        if not self.wkst_dce:
            smb = self.get_smb_connection()
            rpctransport = transport.SMBTransport(self.host, filename=r"\wkssvc", smb_connection=smb)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(MSRPC_UUID_WKST)
            self.wkst_dce = dce
        return self.wkst_dce

    def open_samr_domain(self):
        if self.domain_handle:
            return self.domain_handle
        dce = self.get_samr_dce()
        resp = samr.hSamrConnect(dce)
        self.server_handle = resp["ServerHandle"]
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, self.server_handle)
        domains = resp["Buffer"]["Buffer"]
        for d in domains:
            if d["Name"].lower() != "builtin":
                self.machine_name = d["Name"]
                break
        resp = samr.hSamrLookupDomainInSamServer(dce, self.server_handle, self.machine_name)
        self.domain_sid = resp["DomainId"]
        resp = samr.hSamrOpenDomain(dce, self.server_handle, domainId=self.domain_sid)
        self.domain_handle = resp["DomainHandle"]
        return self.domain_handle

    def open_builtin_domain(self):
        if self.builtin_handle:
            return self.builtin_handle
        dce = self.get_samr_dce()
        if not self.server_handle:
            resp = samr.hSamrConnect(dce)
            self.server_handle = resp["ServerHandle"]
        resp = samr.hSamrLookupDomainInSamServer(dce, self.server_handle, "Builtin")
        builtin_sid = resp["DomainId"]
        resp = samr.hSamrOpenDomain(dce, self.server_handle, domainId=builtin_sid)
        self.builtin_handle = resp["DomainHandle"]
        return self.builtin_handle

    def server_info(self):
        """srvinfo"""
        self.logger.info("Querying server info (srvinfo)")
        try:
            dce = self.get_srvs_dce()
            resp = srvs.hNetrServerGetInfo(dce, 101)
            info = resp["InfoStruct"]["ServerInfo101"]
            self.logger.highlight(f"Server Name: {info['sv101_name']}")
            self.logger.highlight(f"Server Comment: {info['sv101_comment']}")
            self.logger.highlight(f"Server Version: {info['sv101_version_major']}.{info['sv101_version_minor']}")
            self.logger.highlight(f"Server Type: 0x{info['sv101_type']:x}")
        except Exception as e:
            self.logger.fail(f"srvinfo failed: {e}")

    def enum_domains(self):
        """enumdomains"""
        self.logger.info("Enumerating domains (enumdomains)")
        try:
            dce = self.get_samr_dce()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            self.logger.success(f"Found {len(domains)} domain(s)")
            for d in domains:
                self.logger.highlight(f"  {d['Name']}")
        except Exception as e:
            self.logger.fail(f"enumdomains failed: {e}")

    def enum_trusts(self):
        self.logger.info("Enumerating trusted domains (enumtrust)")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, MAXIMUM_ALLOWED)
            policy_handle = resp["PolicyHandle"]
            resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy_handle)
            trusts = resp["EnumerationBuffer"]["EnumerationBuffer"]
            if not trusts:
                self.logger.display("No trusted domains found")
                return
            self.logger.success(f"Found {len(trusts)} trusted domain(s)")
            direction_map = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
            type_map = {1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}
            for t in trusts:
                name = t["Name"]
                flat_name = t["FlatName"]
                sid = t["Sid"].formatCanonical() if t["Sid"] else "N/A"
                direction = direction_map.get(t["TrustDirection"], str(t["TrustDirection"]))
                trust_type = type_map.get(t["TrustType"], str(t["TrustType"]))
                attrs = t["TrustAttributes"]
                attr_flags = []
                if attrs & 0x1:
                    attr_flags.append("NON_TRANSITIVE")
                if attrs & 0x2:
                    attr_flags.append("UPLEVEL_ONLY")
                if attrs & 0x4:
                    attr_flags.append("QUARANTINED")
                if attrs & 0x8:
                    attr_flags.append("FOREST_TRANSITIVE")
                if attrs & 0x20:
                    attr_flags.append("WITHIN_FOREST")
                if attrs & 0x40:
                    attr_flags.append("TREAT_AS_EXTERNAL")
                attr_str = ",".join(attr_flags) if attr_flags else "NONE"
                self.logger.highlight(f"Domain: {name} ({flat_name})")
                self.logger.highlight(f"  SID: {sid}")
                self.logger.highlight(f"  Direction: {direction} | Type: {trust_type}")
                self.logger.highlight(f"  Attributes: {attr_str} (0x{attrs:x})")
        except Exception as e:
            if "STATUS_NO_MORE_ENTRIES" in str(e):
                self.logger.display("No trusted domains found")
            else:
                self.logger.fail(f"enumtrust failed: {e}")

    def domain_info(self):
        self.logger.info("Querying domain info (querydominfo)")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrQueryInformationDomain(dce, self.domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
            info = resp["Buffer"]["General"]
            self.logger.highlight(f"Domain: {self.machine_name}")
            self.logger.highlight(f"Total Users: {info['UserCount']}")
            self.logger.highlight(f"Total Groups: {info['GroupCount']}")
            self.logger.highlight(f"Total Aliases: {info['AliasCount']}")
            self.logger.highlight(f"Sequence: {info['Sequence']}")
            self.logger.highlight(f"Force Logoff: {info['ForceLogoff']}")
            self.logger.highlight(f"Domain Server State: {info['DomainServerState']}")
            self.logger.highlight(f"Server Role: {info['DomainServerRole']}")
            self.logger.highlight(f"Unknown3: {info['Unknown3']}")
        except Exception as e:
            self.logger.fail(f"querydominfo failed: {e}")

    def pass_pol(self):
        """getdompwinfo"""
        self.logger.info("Getting password policy (getdompwinfo)")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrQueryInformationDomain(dce, self.domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
            info = resp["Buffer"]["Password"]
            self.logger.highlight(f"Min password length: {info['MinPasswordLength']}")
            self.logger.highlight(f"Password history length: {info['PasswordHistoryLength']}")
            self.logger.highlight(f"Password properties: 0x{info['PasswordProperties']:08x}")
            resp = samr.hSamrQueryInformationDomain(dce, self.domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
            lock = resp["Buffer"]["Lockout"]
            self.logger.highlight(f"Lockout threshold: {lock['LockoutThreshold']}")
            self.logger.highlight(f"Lockout duration: {lock['LockoutDuration']}")
            self.logger.highlight(f"Lockout window: {lock['LockoutObservationWindow']}")
        except Exception as e:
            self.logger.fail(f"getdompwinfo failed: {e}")

    def users(self):
        """enumdomusers"""
        self.logger.info("Enumerating users (enumdomusers)")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            users_list = []
            enum_ctx = 0
            while True:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, self.domain_handle, samr.USER_NORMAL_ACCOUNT, enumerationContext=enum_ctx)
                except DCERPCException as e:
                    if "STATUS_MORE_ENTRIES" in str(e):
                        resp = e.get_packet()
                    else:
                        raise
                for user in resp["Buffer"]["Buffer"]:
                    users_list.append((user["RelativeId"], user["Name"]))
                enum_ctx = resp["EnumerationContext"]
                if resp["ErrorCode"] != 0x105:
                    break
            self.logger.success(f"Found {len(users_list)} user(s)")
            for rid, name in users_list:
                self.logger.highlight(f"user:[{name}] rid:[0x{rid:x}]")
                self.db.add_user(self.domain, name, rid=rid)
        except Exception as e:
            self.logger.fail(f"enumdomusers failed: {e}")
            self.logger.info("Try --rid-brute for anonymous enumeration")

    def querydispinfo(self):
        """querydispinfo"""
        self.logger.info("Query display info (querydispinfo)")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrQueryDisplayInformation(dce, self.domain_handle, samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
            entries = resp["Buffer"]["UserInformation"]["Buffer"]
            self.logger.success(f"Found {len(entries)} entries")
            for entry in entries:
                self.logger.highlight(f"index: {entry['Index']} RID: 0x{entry['Rid']:x} acb: 0x{entry['AccountControl']:08x} account: {entry['AccountName']} name: {entry['FullName']} desc: {entry['AdminComment']}")
        except Exception as e:
            self.logger.fail(f"querydispinfo failed: {e}")

    def groups(self):
        """enumdomgroups"""
        self.logger.info("Enumerating groups (enumdomgroups)")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrEnumerateGroupsInDomain(dce, self.domain_handle)
            groups = resp["Buffer"]["Buffer"]
            self.logger.success(f"Found {len(groups)} group(s)")
            for g in groups:
                self.logger.highlight(f"group:[{g['Name']}] rid:[0x{g['RelativeId']:x}]")
                self.db.add_group(self.domain, g["Name"], rid=g["RelativeId"])
        except Exception as e:
            self.logger.fail(f"enumdomgroups failed: {e}")

    def local_groups(self):
        """enumalsgroups builtin"""
        self.logger.info("Enumerating alias groups (enumalsgroups)")
        try:
            self.open_builtin_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrEnumerateAliasesInDomain(dce, self.builtin_handle)
            aliases = resp["Buffer"]["Buffer"]
            self.logger.success(f"Found {len(aliases)} alias(es)")
            for a in aliases:
                self.logger.highlight(f"group:[{a['Name']}] rid:[0x{a['RelativeId']:x}]")
        except Exception as e:
            self.logger.fail(f"enumalsgroups failed: {e}")

    def filetime_to_str(self, low, high):
        if low == 0 and high == 0:
            return "Never"
        if high == 0x7FFFFFFF and low == 0xFFFFFFFF:
            return "Never"
        if high == 0 and low == 0:
            return "Not Set"
        try:
            import datetime
            filetime = (high << 32) | low
            if filetime == 0 or filetime > 0x7FFFFFFFFFFFFFFF:
                return "Never"
            epoch_diff = 116444736000000000
            if filetime < epoch_diff:
                return "Never"
            timestamp = (filetime - epoch_diff) / 10000000
            return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return f"{high}:{low}"

    def uac_to_flags(self, uac):
        flags = []
        flag_map = {
            0x0001: "ACCOUNT_DISABLED",
            0x0002: "HOMEDIR_REQUIRED",
            0x0004: "PASSWORD_NOT_REQUIRED",
            0x0008: "TEMP_DUPLICATE_ACCOUNT",
            0x0010: "NORMAL_ACCOUNT",
            0x0020: "MNS_LOGON_ACCOUNT",
            0x0040: "INTERDOMAIN_TRUST_ACCOUNT",
            0x0080: "WORKSTATION_TRUST_ACCOUNT",
            0x0100: "SERVER_TRUST_ACCOUNT",
            0x0200: "DONT_EXPIRE_PASSWORD",
            0x0400: "ACCOUNT_AUTO_LOCKED",
            0x0800: "ENCRYPTED_TEXT_PWD_ALLOWED",
            0x1000: "SMARTCARD_REQUIRED",
            0x2000: "TRUSTED_FOR_DELEGATION",
            0x4000: "NOT_DELEGATED",
            0x8000: "USE_DES_KEY_ONLY",
            0x10000: "DONT_REQ_PREAUTH",
            0x20000: "PASSWORD_EXPIRED",
            0x40000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
            0x80000: "NO_AUTH_DATA_REQUIRED",
            0x100000: "PARTIAL_SECRETS_ACCOUNT",
        }
        for bit, name in flag_map.items():
            if uac & bit:
                flags.append(name)
        return flags

    def user(self):
        user_input = self.args.user
        self.logger.info(f"Querying user (queryuser {user_input})")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            if user_input.startswith("0x"):
                rid = int(user_input, 16)
            elif user_input.isdigit():
                rid = int(user_input)
            else:
                resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [user_input])
                rid = resp["RelativeIds"]["Element"][0]["Data"]
            resp = samr.hSamrOpenUser(dce, self.domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
            info = resp["Buffer"]["All"]
            uac = info["UserAccountControl"]
            uac_flags = self.uac_to_flags(uac)
            self.logger.highlight(f"User Name: {info['UserName']}")
            self.logger.highlight(f"Full Name: {info['FullName']}")
            self.logger.highlight(f"Home Directory: {info['HomeDirectory']}")
            self.logger.highlight(f"Home Drive: {info['HomeDirectoryDrive']}")
            self.logger.highlight(f"Logon Script: {info['ScriptPath']}")
            self.logger.highlight(f"Profile Path: {info['ProfilePath']}")
            self.logger.highlight(f"Description: {info['AdminComment']}")
            self.logger.highlight(f"Workstations: {info['WorkStations']}")
            self.logger.highlight(f"User Comment: {info['UserComment']}")
            self.logger.highlight(f"Parameters: {info['Parameters']}")
            self.logger.highlight(f"Country Code: {info['CountryCode']}")
            self.logger.highlight(f"Code Page: {info['CodePage']}")
            self.logger.highlight(f"Last Logon: {self.filetime_to_str(info['LastLogon']['LowPart'], info['LastLogon']['HighPart'])}")
            self.logger.highlight(f"Last Logoff: {self.filetime_to_str(info['LastLogoff']['LowPart'], info['LastLogoff']['HighPart'])}")
            self.logger.highlight(f"Account Expires: {self.filetime_to_str(info['AccountExpires']['LowPart'], info['AccountExpires']['HighPart'])}")
            self.logger.highlight(f"Password Last Set: {self.filetime_to_str(info['PasswordLastSet']['LowPart'], info['PasswordLastSet']['HighPart'])}")
            self.logger.highlight(f"Password Can Change: {self.filetime_to_str(info['PasswordCanChange']['LowPart'], info['PasswordCanChange']['HighPart'])}")
            self.logger.highlight(f"Password Must Change: {self.filetime_to_str(info['PasswordMustChange']['LowPart'], info['PasswordMustChange']['HighPart'])}")
            self.logger.highlight(f"User RID: 0x{rid:x} ({rid})")
            self.logger.highlight(f"Primary Group RID: 0x{info['PrimaryGroupId']:x} ({info['PrimaryGroupId']})")
            self.logger.highlight(f"Account Control: 0x{uac:08x} ({', '.join(uac_flags) if uac_flags else 'NONE'})")
            self.logger.highlight(f"Bad Password Count: {info['BadPasswordCount']}")
            self.logger.highlight(f"Logon Count: {info['LogonCount']}")
            try:
                logon_hours = info["LogonHours"]["LogonHours"]
                if logon_hours:
                    hours_hex = "".join(f"{b:02x}" for b in logon_hours)
                    self.logger.highlight(f"Logon Hours: {hours_hex}")
            except Exception:
                pass
            samr.hSamrCloseHandle(dce, user_handle)
        except Exception as e:
            self.logger.fail(f"queryuser failed: {e}")

    def group(self):
        """querygroup"""
        group_input = self.args.group
        self.logger.info(f"Querying group (querygroup {group_input})")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            if group_input.startswith("0x"):
                rid = int(group_input, 16)
            elif group_input.isdigit():
                rid = int(group_input)
            else:
                resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [group_input])
                rid = resp["RelativeIds"]["Element"][0]["Data"]
            resp = samr.hSamrOpenGroup(dce, self.domain_handle, MAXIMUM_ALLOWED, rid)
            group_handle = resp["GroupHandle"]
            resp = samr.hSamrQueryInformationGroup(dce, group_handle, samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
            info = resp["Buffer"]["General"]
            self.logger.highlight(f"Group Name: {info['Name']}")
            self.logger.highlight(f"Description: {info['AdminComment']}")
            self.logger.highlight(f"Group Attribute: {info['Attributes']}")
            self.logger.highlight(f"Num Members: {info['MemberCount']}")
            resp = samr.hSamrGetMembersInGroup(dce, group_handle)
            members = resp["Members"]["Members"]
            if members:
                rids = [str(m["Data"]) for m in members]
                self.logger.highlight(f"Member RIDs: {', '.join(rids)}")
            samr.hSamrCloseHandle(dce, group_handle)
        except Exception as e:
            self.logger.fail(f"querygroup failed: {e}")

    def user_pass_pol(self):
        """getusrdompwinfo"""
        rid_input = self.args.user_pass_pol
        self.logger.info(f"Getting user password info (getusrdompwinfo {rid_input})")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            if rid_input.startswith("0x"):
                rid = int(rid_input, 16)
            elif rid_input.isdigit():
                rid = int(rid_input)
            else:
                resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [rid_input])
                rid = resp["RelativeIds"]["Element"][0]["Data"]
            resp = samr.hSamrOpenUser(dce, self.domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
            info = resp["Buffer"]["All"]
            self.logger.highlight(f"Password last set: {info['PasswordLastSet']['LowPart']}")
            self.logger.highlight(f"Password can change: {info['PasswordCanChange']['LowPart']}")
            self.logger.highlight(f"Password must change: {info['PasswordMustChange']['LowPart']}")
            self.logger.highlight(f"Bad password count: {info['BadPasswordCount']}")
            samr.hSamrCloseHandle(dce, user_handle)
        except Exception as e:
            self.logger.fail(f"getusrdompwinfo failed: {e}")

    def rid_brute(self):
        max_rid = self.args.rid_brute
        self.logger.info(f"RID cycling from 500 to {max_rid}")
        try:
            dce = self.get_samr_dce()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            if not domain_name:
                self.logger.fail("Could not find domain")
                return
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            domain_sid_str = domain_sid.formatCanonical()
            resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
            domain_handle = resp["DomainHandle"]
            found = []
            type_names = {1: "User", 2: "Group", 4: "Alias", 5: "WellKnown", 9: "Computer"}
            for rid in range(500, max_rid + 1):
                try:
                    resp = samr.hSamrLookupIdsInDomain(dce, domain_handle, [rid])
                    names = resp["Names"]["Element"]
                    uses = resp["Use"]["Element"]
                    if names and names[0]["Data"]:
                        name = names[0]["Data"]
                        use = uses[0]["Data"] if uses else 0
                        type_name = type_names.get(use, f"Type{use}")
                        sid_str = f"{domain_sid_str}-{rid}"
                        found.append((rid, name, type_name))
                        self.logger.highlight(f"{sid_str} -> {name} ({type_name})")
                        if use == 1:
                            self.db.add_user(self.domain, name, rid=rid)
                except Exception:
                    pass
            self.logger.success(f"Found {len(found)} principal(s)")
        except Exception as e:
            self.logger.fail(f"RID brute failed: {e}")

    def shares(self):
        """netshareenumall"""
        self.logger.info("Enumerating shares (netshareenumall)")
        try:
            dce = self.get_srvs_dce()
            resp = srvs.hNetrShareEnum(dce, 1)
            shares = resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]
            self.logger.success(f"Found {len(shares)} share(s)")
            for s in shares:
                stype = s["shi1_type"] & 0xFFFF
                type_str = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}.get(stype, "Unknown")
                self.logger.highlight(f"netname: {s['shi1_netname']} | type: {type_str} | remark: {s['shi1_remark']}")
        except Exception as e:
            self.logger.fail(f"netshareenum failed: {e}")

    def share(self):
        share_name = self.args.share
        if not share_name.endswith("\x00"):
            share_name += "\x00"
        self.logger.info(f"Getting share info (netsharegetinfo {self.args.share})")
        try:
            dce = self.get_srvs_dce()
            try:
                resp = srvs.hNetrShareGetInfo(dce, share_name, 2)
                info = resp["InfoStruct"]["ShareInfo2"]
                stype = info["shi2_type"] & 0xFFFF
                type_str = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}.get(stype, "Unknown")
                self.logger.highlight(f"netname: {info['shi2_netname']}")
                self.logger.highlight(f"type: {type_str} (0x{info['shi2_type']:x})")
                self.logger.highlight(f"remark: {info['shi2_remark']}")
                self.logger.highlight(f"permissions: {info['shi2_permissions']}")
                self.logger.highlight(f"max_uses: {info['shi2_max_uses']}")
                self.logger.highlight(f"current_uses: {info['shi2_current_uses']}")
                self.logger.highlight(f"path: {info['shi2_path']}")
            except Exception:
                resp = srvs.hNetrShareGetInfo(dce, share_name, 1)
                info = resp["InfoStruct"]["ShareInfo1"]
                stype = info["shi1_type"] & 0xFFFF
                type_str = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}.get(stype, "Unknown")
                self.logger.highlight(f"netname: {info['shi1_netname']}")
                self.logger.highlight(f"type: {type_str} (0x{info['shi1_type']:x})")
                self.logger.highlight(f"remark: {info['shi1_remark']}")
        except Exception as e:
            self.logger.fail(f"netsharegetinfo failed: {e}")

    def sessions(self):
        """netsessenum"""
        self.logger.info("Enumerating sessions")
        try:
            dce = self.get_srvs_dce()
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
            sessions = resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]
            self.logger.success(f"Found {len(sessions)} session(s)")
            for s in sessions:
                self.logger.highlight(f"cname: {s['sesi10_cname']} | username: {s['sesi10_username']} | time: {s['sesi10_time']}")
        except Exception as e:
            self.logger.fail(f"netsessenum failed: {e}")

    def connections(self):
        self.logger.info("Enumerating connections")
        try:
            dce = self.get_srvs_dce()
            share_resp = srvs.hNetrShareEnum(dce, 1)
            shares = share_resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]
            total_conns = 0
            for share in shares:
                share_name = share["shi1_netname"].rstrip("\x00")
                try:
                    resp = srvs.hNetrConnectionEnum(dce, share_name, 1)
                    conns = resp["InfoStruct"]["ConnectInfo"]["Level1"]["Buffer"]
                    for c in conns:
                        total_conns += 1
                        user = c["coni1_username"]
                        netname = c["coni1_netname"]
                        self.logger.highlight(f"share: {share_name} | user: {user} | client: {netname} | opens: {c['coni1_num_opens']} | time: {c['coni1_time']}s")
                except Exception:
                    pass
            if total_conns == 0:
                self.logger.display("No connections found")
            else:
                self.logger.success(f"Found {total_conns} connection(s)")
        except Exception as e:
            self.logger.fail(f"netconnenum failed: {e}")

    def lsa_query(self):
        """lsaquery"""
        self.logger.info("LSA query (lsaquery)")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
            policy_handle = resp["PolicyHandle"]
            resp = lsad.hLsarQueryInformationPolicy(dce, policy_handle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
            info = resp["PolicyInformation"]["PolicyPrimaryDomainInfo"]
            self.logger.highlight(f"Domain Name: {info['Name']}")
            if info["Sid"]:
                self.logger.highlight(f"Domain SID: {info['Sid'].formatCanonical()}")
        except Exception as e:
            self.logger.fail(f"lsaquery failed: {e}")

    def lsa_enum_accounts(self):
        """lsaenumsid"""
        self.logger.info("Enumerating SIDs (lsaenumsid)")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
            policy_handle = resp["PolicyHandle"]
            resp = lsad.hLsarEnumerateAccounts(dce, policy_handle)
            sids = resp["EnumerationBuffer"]["Information"]
            self.logger.success(f"Found {len(sids)} SID(s)")
            for sid_info in sids:
                self.logger.highlight(f"  {sid_info['Sid'].formatCanonical()}")
        except Exception as e:
            self.logger.fail(f"lsaenumsid failed: {e}")

    def lsa_enum_privileges(self):
        """enumprivs"""
        self.logger.info("Enumerating privileges (enumprivs)")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
            policy_handle = resp["PolicyHandle"]
            resp = lsad.hLsarEnumeratePrivileges(dce, policy_handle)
            privs = resp["EnumerationBuffer"]["Privileges"]
            self.logger.success(f"Found {len(privs)} privilege(s)")
            for p in privs:
                self.logger.highlight(f"  {p['Name']}")
        except Exception as e:
            self.logger.fail(f"enumprivs failed: {e}")

    def lsa_enum_account_rights(self):
        """lsaenumacctrights"""
        sid = self.args.lsa_enum_account_rights
        self.logger.info(f"Enumerating account rights (lsaenumacctrights {sid})")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
            policy_handle = resp["PolicyHandle"]
            resp = lsad.hLsarEnumerateAccountRights(dce, policy_handle, sid)
            rights = resp["UserRights"]["UserRights"]
            self.logger.success(f"Found {len(rights)} right(s) for {sid}")
            for r in rights:
                self.logger.highlight(f"  {r['Data']}")
        except Exception as e:
            self.logger.fail(f"lsaenumacctrights failed: {e}")

    def lsa_create_account(self):
        """lsacreateaccount"""
        sid = self.args.lsa_create_account
        self.logger.info(f"Creating LSA account (lsacreateaccount {sid})")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_CREATE_ACCOUNT)
            policy_handle = resp["PolicyHandle"]
            resp = lsad.hLsarCreateAccount(dce, policy_handle, sid)
            self.logger.success(f"Created LSA account for {sid}")
        except Exception as e:
            self.logger.fail(f"lsacreateaccount failed: {e}")

    def lsa_lookup_sids(self):
        """lookupsids"""
        sids_str = self.args.lsa_lookup_sids
        sids = [s.strip() for s in sids_str.split(",")]
        self.logger.info(f"Looking up SIDs (lookupsids)")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsat.POLICY_LOOKUP_NAMES)
            policy_handle = resp["PolicyHandle"]
            for sid in sids:
                try:
                    resp = lsat.hLsarLookupSids(dce, policy_handle, [sid])
                    names = resp["TranslatedNames"]["Names"]
                    domains = resp["ReferencedDomains"]["Domains"]
                    for n in names:
                        dom_idx = n["DomainIndex"]
                        dom = domains[dom_idx]["Name"] if dom_idx >= 0 else ""
                        self.logger.highlight(f"  {sid} -> {dom}\\{n['Name']} (type {n['Use']})")
                except Exception as e:
                    self.logger.fail(f"  {sid} -> lookup failed: {e}")
        except Exception as e:
            self.logger.fail(f"lookupsids failed: {e}")

    def lsa_lookup_names(self):
        """lookupnames via LSA"""
        names_str = self.args.lsa_lookup_names
        names = [n.strip() for n in names_str.split(",")]
        self.logger.info(f"Looking up names via LSA")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsat.POLICY_LOOKUP_NAMES)
            policy_handle = resp["PolicyHandle"]
            resp = lsat.hLsarLookupNames(dce, policy_handle, names)
            sids = resp["TranslatedSids"]["Sids"]
            domains = resp["ReferencedDomains"]["Domains"]
            for i, name in enumerate(names):
                if i < len(sids):
                    sid = sids[i]
                    dom_idx = sid["DomainIndex"]
                    dom_sid = domains[dom_idx]["Sid"].formatCanonical() if dom_idx >= 0 else ""
                    self.logger.highlight(f"  {name} -> {dom_sid}-{sid['RelativeId']} (type {sid['Use']})")
        except Exception as e:
            self.logger.fail(f"lookupnames failed: {e}")

    def lsa_query_security(self):
        self.logger.info("Querying LSA security object (lsaquerysecobj)")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, MAXIMUM_ALLOWED)
            policy_handle = resp["PolicyHandle"]
            sd_bytes = lsad.hLsarQuerySecurityObject(dce, policy_handle, 0x07)
            self.parse_security_descriptor(sd_bytes)
        except Exception as e:
            self.logger.fail(f"lsaquerysecobj failed: {e}")

    def parse_security_descriptor(self, sd_bytes):
        import struct
        if len(sd_bytes) < 20:
            self.logger.fail("Security descriptor too short")
            return
        revision = sd_bytes[0]
        control = struct.unpack("<H", sd_bytes[2:4])[0]
        control_flags = []
        if control & 0x0004:
            control_flags.append("SEC_DESC_DACL_PRESENT")
        if control & 0x8000:
            control_flags.append("SEC_DESC_SELF_RELATIVE")
        self.logger.highlight(f"revision: {revision}")
        self.logger.highlight(f"type: 0x{control:04x}: {' '.join(control_flags)}")
        offset_owner = struct.unpack("<I", sd_bytes[4:8])[0]
        offset_group = struct.unpack("<I", sd_bytes[8:12])[0]
        offset_sacl = struct.unpack("<I", sd_bytes[12:16])[0]
        offset_dacl = struct.unpack("<I", sd_bytes[16:20])[0]
        if offset_dacl and (control & 0x0004):
            self.logger.highlight("DACL")
            self.parse_acl(sd_bytes, offset_dacl)

    def parse_acl(self, sd_bytes, offset):
        import struct
        if offset + 8 > len(sd_bytes):
            return
        acl_revision = sd_bytes[offset]
        acl_size = struct.unpack("<H", sd_bytes[offset + 2:offset + 4])[0]
        ace_count = struct.unpack("<H", sd_bytes[offset + 4:offset + 6])[0]
        self.logger.highlight(f"\tACL\tNum ACEs:\t{ace_count}\trevision:\t{acl_revision}")
        ace_offset = offset + 8
        for _ in range(ace_count):
            if ace_offset + 4 > len(sd_bytes):
                break
            ace_type = sd_bytes[ace_offset]
            ace_flags = sd_bytes[ace_offset + 1]
            ace_size = struct.unpack("<H", sd_bytes[ace_offset + 2:ace_offset + 4])[0]
            if ace_offset + ace_size > len(sd_bytes):
                break
            type_names = {0: "ACCESS ALLOWED", 1: "ACCESS DENIED", 2: "SYSTEM AUDIT"}
            type_str = type_names.get(ace_type, f"TYPE_{ace_type}")
            self.logger.highlight(f"\t---")
            self.logger.highlight(f"\tACE")
            self.logger.highlight(f"\t\ttype: {type_str} ({ace_type}) flags: 0x{ace_flags:02x}")
            if ace_size >= 8:
                mask = struct.unpack("<I", sd_bytes[ace_offset + 4:ace_offset + 8])[0]
                specific = mask & 0xFFFF
                self.logger.highlight(f"\t\tSpecific bits: 0x{specific:x}")
                perms = []
                if mask & 0x80000:
                    perms.append("WRITE_OWNER_ACCESS")
                if mask & 0x40000:
                    perms.append("WRITE_DAC_ACCESS")
                if mask & 0x20000:
                    perms.append("READ_CONTROL_ACCESS")
                if mask & 0x10000:
                    perms.append("DELETE_ACCESS")
                self.logger.highlight(f"\t\tPermissions: 0x{mask:x}: {' '.join(perms)}")
                sid_offset = ace_offset + 8
                sid_len = ace_size - 8
                if sid_len > 0:
                    sid_str = self.parse_sid(sd_bytes[sid_offset:sid_offset + sid_len])
                    self.logger.highlight(f"\t\tSID: {sid_str}")
            ace_offset += ace_size

    def parse_sid(self, sid_bytes):
        import struct
        if len(sid_bytes) < 8:
            return "Invalid SID"
        revision = sid_bytes[0]
        sub_auth_count = sid_bytes[1]
        authority = struct.unpack(">Q", b"\x00\x00" + sid_bytes[2:8])[0]
        if len(sid_bytes) < 8 + sub_auth_count * 4:
            return "Invalid SID"
        sub_auths = []
        for i in range(sub_auth_count):
            sub_auth = struct.unpack("<I", sid_bytes[8 + i * 4:12 + i * 4])[0]
            sub_auths.append(str(sub_auth))
        return f"S-{revision}-{authority}-{'-'.join(sub_auths)}" if sub_auths else f"S-{revision}-{authority}"

    def lookup_names(self):
        """lookupnames via SAMR"""
        names_str = self.args.lookup_names
        names = [n.strip() for n in names_str.split(",")]
        self.logger.info(f"Looking up names (lookupnames)")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            domain_sid = self.domain_sid.formatCanonical()
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, names)
            rids = resp["RelativeIds"]["Element"]
            uses = resp["Use"]["Element"]
            type_names = {1: "User", 2: "Group", 4: "Alias", 5: "WellKnown", 9: "Computer"}
            for i, name in enumerate(names):
                if i < len(rids):
                    rid = rids[i]["Data"]
                    use = uses[i]["Data"]
                    type_name = type_names.get(use, "Unknown")
                    self.logger.highlight(f"{name} {domain_sid}-{rid} ({type_name}: {use})")
        except Exception as e:
            self.logger.fail(f"lookupnames failed: {e}")

    def sid_lookup(self):
        """Lookup SID"""
        sid = self.args.sid_lookup
        self.logger.info(f"Looking up SID {sid}")
        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsat.POLICY_LOOKUP_NAMES)
            policy_handle = resp["PolicyHandle"]
            resp = lsat.hLsarLookupSids(dce, policy_handle, [sid])
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]
            for n in names:
                dom_idx = n["DomainIndex"]
                dom = domains[dom_idx]["Name"] if dom_idx >= 0 else ""
                self.logger.highlight(f"  {sid} -> {dom}\\{n['Name']} (type {n['Use']})")
        except Exception as e:
            self.logger.fail(f"SID lookup failed: {e}")

    def sam_lookup(self):
        """samlookupnames domain|builtin name1,name2,..."""
        domain_type = self.args.sam_lookup[0].lower()
        names = [n.strip() for n in self.args.sam_lookup[1].split(",")]
        self.logger.info(f"SAM lookup (samlookupnames {domain_type})")
        try:
            dce = self.get_samr_dce()
            if domain_type == "builtin":
                self.open_builtin_domain()
                domain_handle = self.builtin_handle
                resp = samr.hSamrLookupDomainInSamServer(dce, self.server_handle, "Builtin")
                domain_sid = resp["DomainId"].formatCanonical()
            else:
                self.open_samr_domain()
                domain_handle = self.domain_handle
                domain_sid = self.domain_sid.formatCanonical()
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, names)
            rids = resp["RelativeIds"]["Element"]
            uses = resp["Use"]["Element"]
            type_names = {1: "User", 2: "Group", 4: "Alias", 5: "WellKnown", 9: "Computer"}
            for i, name in enumerate(names):
                if i < len(rids):
                    rid = rids[i]["Data"]
                    use = uses[i]["Data"]
                    type_name = type_names.get(use, "Unknown")
                    self.logger.highlight(f"{name} {domain_sid}-{rid} ({type_name}: {use})")
        except Exception as e:
            self.logger.fail(f"samlookupnames failed: {e}")

    def lookup_domain(self):
        """lookupdomain"""
        domain_name = self.args.lookup_domain
        self.logger.info(f"Looking up domain (lookupdomain {domain_name})")
        try:
            dce = self.get_samr_dce()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            sid = resp["DomainId"].formatCanonical()
            self.logger.highlight(f"Domain {domain_name} -> SID {sid}")
        except Exception as e:
            self.logger.fail(f"lookupdomain failed: {e}")

    def create_user(self):
        user_pass = self.args.create_user
        try:
            username, password = user_pass.split(":", 1)
        except ValueError:
            self.logger.fail("Format: username:password")
            return
        self.logger.info(f"Creating user (createdomuser {username})")
        try:
            dce = self.get_samr_dce_np()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]
            resp = samr.hSamrCreateUser2InDomain(dce, domain_handle, username, samr.USER_NORMAL_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE)
            user_handle = resp["UserHandle"]
            rid = resp["RelativeId"]
            samr.hSamrChangePasswordUser(dce, user_handle, oldPassword="", newPassword=password, oldPwdHashNT="31d6cfe0d16ae931b73c59d7e0c089c0", newPwdHashLM="", newPwdHashNT="")
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
            user_rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, user_rid)
            user_handle = resp["UserHandle"]
            user_control = samr.SAMPR_USER_INFO_BUFFER()
            user_control["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
            user_control["Control"]["UserAccountControl"] = samr.USER_NORMAL_ACCOUNT
            samr.hSamrSetInformationUser2(dce, user_handle, user_control)
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            self.logger.success(f"Created user {username} with RID 0x{rid:x}")
        except Exception as e:
            self.logger.fail(f"createdomuser failed: {e}")

    def delete_user(self):
        username = self.args.delete_user
        self.logger.info(f"Deleting user (deletedomuser {username})")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [username])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, self.domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            samr.hSamrDeleteUser(dce, user_handle)
            self.logger.success(f"Deleted user {username}")
        except Exception as e:
            self.logger.fail(f"deletedomuser failed: {e}")

    def enable_user(self):
        username = self.args.enable_user
        self.logger.info(f"Enabling user account (setuserinfo2 {username})")
        try:
            dce = self.get_samr_dce_np()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserControlInformation)
            uac = resp["Buffer"]["Control"]["UserAccountControl"]
            if not (uac & samr.USER_ACCOUNT_DISABLED):
                self.logger.display(f"User {username} is already enabled (UAC: 0x{uac:x})")
                samr.hSamrCloseHandle(dce, user_handle)
                dce.disconnect()
                return
            new_uac = uac & ~samr.USER_ACCOUNT_DISABLED
            user_control = samr.SAMPR_USER_INFO_BUFFER()
            user_control["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
            user_control["Control"]["UserAccountControl"] = new_uac
            samr.hSamrSetInformationUser2(dce, user_handle, user_control)
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            self.logger.success(f"Enabled user {username} (UAC: 0x{uac:x} -> 0x{new_uac:x})")
        except Exception as e:
            self.logger.fail(f"Enable user failed: {e}")

    def disable_user(self):
        username = self.args.disable_user
        self.logger.info(f"Disabling user account (setuserinfo2 {username})")
        try:
            dce = self.get_samr_dce_np()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserControlInformation)
            uac = resp["Buffer"]["Control"]["UserAccountControl"]
            if uac & samr.USER_ACCOUNT_DISABLED:
                self.logger.display(f"User {username} is already disabled (UAC: 0x{uac:x})")
                samr.hSamrCloseHandle(dce, user_handle)
                dce.disconnect()
                return
            new_uac = uac | samr.USER_ACCOUNT_DISABLED
            user_control = samr.SAMPR_USER_INFO_BUFFER()
            user_control["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
            user_control["Control"]["UserAccountControl"] = new_uac
            samr.hSamrSetInformationUser2(dce, user_handle, user_control)
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            self.logger.success(f"Disabled user {username} (UAC: 0x{uac:x} -> 0x{new_uac:x})")
        except Exception as e:
            self.logger.fail(f"Disable user failed: {e}")

    def set_user_info(self):
        username = self.args.set_user_info[0]
        info_class = self.args.set_user_info[1].lower()
        value = self.args.set_user_info[2]
        class_map = {
            "fullname": (samr.USER_INFORMATION_CLASS.UserFullNameInformation, "FullName", "FullName"),
            "description": (samr.USER_INFORMATION_CLASS.UserAdminCommentInformation, "AdminComment", "AdminComment"),
            "comment": (samr.USER_INFORMATION_CLASS.UserAdminCommentInformation, "AdminComment", "AdminComment"),
            "homedir": (samr.USER_INFORMATION_CLASS.UserHomeInformation, "Home", "HomeDirectory"),
            "homedrive": (samr.USER_INFORMATION_CLASS.UserHomeInformation, "Home", "HomeDirectoryDrive"),
            "script": (samr.USER_INFORMATION_CLASS.UserScriptInformation, "Script", "ScriptPath"),
            "profile": (samr.USER_INFORMATION_CLASS.UserProfileInformation, "Profile", "ProfilePath"),
            "workstations": (samr.USER_INFORMATION_CLASS.UserWorkStationsInformation, "WorkStations", "WorkStations"),
            "control": (samr.USER_INFORMATION_CLASS.UserControlInformation, "Control", "UserAccountControl"),
            "expires": (samr.USER_INFORMATION_CLASS.UserExpiresInformation, "Expires", "AccountExpires"),
            "primary-group": (samr.USER_INFORMATION_CLASS.UserPrimaryGroupInformation, "PrimaryGroup", "PrimaryGroupId"),
            "parameters": (samr.USER_INFORMATION_CLASS.UserParametersInformation, "Parameters", "Parameters"),
        }
        special_classes = ["name", "logonhours", "preferences"]
        all_classes = list(class_map.keys()) + special_classes
        if info_class not in all_classes:
            self.logger.fail(f"Unknown class: {info_class}. Valid: {', '.join(all_classes)}")
            return
        self.logger.info(f"Setting {info_class} for {username}")
        try:
            dce = self.get_samr_dce_np()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            user_info = samr.SAMPR_USER_INFO_BUFFER()
            if info_class == "name":
                user_info["tag"] = samr.USER_INFORMATION_CLASS.UserNameInformation
                if ":" in value:
                    new_username, new_fullname = value.split(":", 1)
                    user_info["Name"]["UserName"] = new_username
                    user_info["Name"]["FullName"] = new_fullname
                else:
                    user_info["Name"]["UserName"] = value
                    user_info["Name"]["FullName"] = ""
            elif info_class == "logonhours":
                user_info["tag"] = samr.USER_INFORMATION_CLASS.UserLogonHoursInformation
                if value.lower() == "all":
                    hours_bytes = list(b"\xff" * 21)
                elif value.lower() == "none":
                    hours_bytes = list(b"\x00" * 21)
                else:
                    try:
                        hours_bytes = list(bytes.fromhex(value.replace(" ", "")))
                        if len(hours_bytes) != 21:
                            self.logger.fail(f"Logon hours must be 21 bytes (42 hex chars), got {len(hours_bytes)}")
                            return
                    except ValueError as e:
                        self.logger.fail(f"Invalid hex string for logon hours: {e}")
                        return
                user_info["LogonHours"]["LogonHours"]["LogonHours"] = hours_bytes
            elif info_class == "preferences":
                user_info["tag"] = samr.USER_INFORMATION_CLASS.UserPreferencesInformation
                try:
                    parts = value.split(":")
                    if len(parts) == 2:
                        country_code = int(parts[0], 0)
                        code_page = int(parts[1], 0)
                    else:
                        self.logger.fail("Preferences format: countrycode:codepage (e.g., 1:437)")
                        return
                except ValueError:
                    self.logger.fail("Invalid country code or code page")
                    return
                user_info["Preferences"]["UserComment"] = ""
                user_info["Preferences"]["Reserved1"] = ""
                user_info["Preferences"]["CountryCode"] = country_code
                user_info["Preferences"]["CodePage"] = code_page
            else:
                user_class, buffer_name, field_name = class_map[info_class]
                user_info["tag"] = user_class
                if info_class in ("control", "primary-group"):
                    user_info[buffer_name][field_name] = int(value, 0)
                elif info_class == "expires":
                    user_info[buffer_name][field_name] = int(value, 0)
                else:
                    user_info[buffer_name][field_name] = value
            samr.hSamrSetInformationUser2(dce, user_handle, user_info)
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            self.logger.success(f"Set {info_class}='{value}' for {username}")
        except Exception as e:
            self.logger.fail(f"Set user info failed: {e}")

    def change_password(self):
        change_str = self.args.change_password
        try:
            username, old_pass, new_pass = change_str.split(":", 2)
        except ValueError:
            self.logger.fail("Format: username:oldpass:newpass")
            return
        self.logger.info(f"Changing password (chgpasswd {username})")
        try:
            dce = self.get_samr_dce_np()
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            samr.hSamrChangePasswordUser(dce, user_handle, oldPassword=old_pass, newPassword=new_pass)
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            self.logger.success(f"Changed password for {username}")
        except Exception as e:
            self.logger.fail(f"chgpasswd failed: {e}")

    def reset_password(self):
        """setuserinfo2 username 24 password"""
        reset_str = self.args.reset_password
        try:
            username, new_pass = reset_str.split(":", 1)
        except ValueError:
            self.logger.fail("Format: username:newpass")
            return
        self.logger.info(f"Resetting password for {username} (setuserinfo2 level 24)")
        try:
            from Cryptodome.Cipher import ARC4
            rpctransport = transport.SMBTransport(self.host, filename=r"\samr")
            rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)
            if self.doKerberos:
                rpctransport.set_kerberos(True, self.kdcHost)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(MSRPC_UUID_SAMR)
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            domain_name = None
            for d in domains:
                if d["Name"].lower() != "builtin":
                    domain_name = d["Name"]
                    break
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
            user_handle = resp["UserHandle"]
            session_key = dce.get_rpc_transport().get_smb_connection().getSessionKey()
            sam_user_pass = samr.SAMPR_USER_PASSWORD()
            encoded_pass = new_pass.encode("utf-16le")
            plen = len(encoded_pass)
            sam_user_pass["Buffer"] = b"A" * (512 - plen) + encoded_pass
            sam_user_pass["Length"] = plen
            pwd_buff = sam_user_pass.getData()
            rc4 = ARC4.new(session_key)
            enc_buf = rc4.encrypt(pwd_buff)
            sam_user_pass_enc = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
            sam_user_pass_enc["Buffer"] = enc_buf
            request = samr.SamrSetInformationUser2()
            request["UserHandle"] = user_handle
            request["UserInformationClass"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
            request["Buffer"]["tag"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
            request["Buffer"]["Internal5"]["UserPassword"] = sam_user_pass_enc
            request["Buffer"]["Internal5"]["PasswordExpired"] = 0
            dce.request(request)
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            self.logger.success(f"Reset password for {username}")
        except Exception as e:
            self.logger.fail(f"Reset password failed: {e}")

    def create_group(self):
        """createdomgroup"""
        group_name = self.args.create_group
        self.logger.info(f"Creating group (createdomgroup {group_name})")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrCreateGroupInDomain(dce, self.domain_handle, group_name, MAXIMUM_ALLOWED)
            rid = resp["RelativeId"]
            samr.hSamrCloseHandle(dce, resp["GroupHandle"])
            self.logger.success(f"Created group {group_name} with RID 0x{rid:x}")
        except Exception as e:
            self.logger.fail(f"createdomgroup failed: {e}")

    def delete_group(self):
        """deletedomgroup"""
        group_name = self.args.delete_group
        self.logger.info(f"Deleting group (deletedomgroup {group_name})")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [group_name])
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenGroup(dce, self.domain_handle, MAXIMUM_ALLOWED, rid)
            group_handle = resp["GroupHandle"]
            samr.hSamrDeleteGroup(dce, group_handle)
            self.logger.success(f"Deleted group {group_name}")
        except Exception as e:
            self.logger.fail(f"deletedomgroup failed: {e}")

    def add_to_group(self):
        """Add user to group"""
        add_str = self.args.add_to_group
        try:
            username, group_name = add_str.split(":", 1)
        except ValueError:
            self.logger.fail("Format: username:groupname")
            return
        self.logger.info(f"Adding {username} to {group_name}")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [username])
            user_rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [group_name])
            group_rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenGroup(dce, self.domain_handle, MAXIMUM_ALLOWED, group_rid)
            group_handle = resp["GroupHandle"]
            samr.hSamrAddMemberToGroup(dce, group_handle, user_rid, samr.SE_GROUP_ENABLED_BY_DEFAULT)
            samr.hSamrCloseHandle(dce, group_handle)
            self.logger.success(f"Added {username} to {group_name}")
        except Exception as e:
            self.logger.fail(f"Add to group failed: {e}")

    def remove_from_group(self):
        """Remove user from group"""
        remove_str = self.args.remove_from_group
        try:
            username, group_name = remove_str.split(":", 1)
        except ValueError:
            self.logger.fail("Format: username:groupname")
            return
        self.logger.info(f"Removing {username} from {group_name}")
        try:
            self.open_samr_domain()
            dce = self.get_samr_dce()
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [username])
            user_rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrLookupNamesInDomain(dce, self.domain_handle, [group_name])
            group_rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenGroup(dce, self.domain_handle, MAXIMUM_ALLOWED, group_rid)
            group_handle = resp["GroupHandle"]
            samr.hSamrRemoveMemberFromGroup(dce, group_handle, user_rid)
            samr.hSamrCloseHandle(dce, group_handle)
            self.logger.success(f"Removed {username} from {group_name}")
        except Exception as e:
            self.logger.fail(f"Remove from group failed: {e}")
