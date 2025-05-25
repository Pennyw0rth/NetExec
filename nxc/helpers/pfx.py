# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan)
#
# Description:
#     This script will use an existing TGT to request a PAC for the current user using U2U.
#     When the TGT was obtained using PKINIT, the resulting PAC will contain the NT hash which can be
#     used for silver tickets and for backwards compatibility with other tooling.
#
# References:
#
#     U2U: https://tools.ietf.org/html/draft-ietf-cat-user2user-02
#
# Based on examples from minikerberos by skelsec
# Parts of this code was inspired by the following project by @rubin_mor
# https://github.com/morRubin/AzureADJoinedMachinePTC
#
# Author:
#  Tamas Jos (@skelsec)
#  Dirk-jan Mollema (@_dirkjan)
#

import os
import secrets
import hashlib
import datetime
import random
import base64

from binascii import unhexlify, hexlify

from oscrypto.keys import parse_pkcs12, parse_certificate, parse_private
from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key

from asn1crypto import cms
from asn1crypto import algos
from asn1crypto import core
from asn1crypto import keys

from minikerberos.pkinit import PKINIT, DirtyDH
from minikerberos.protocol.constants import NAME_TYPE, PaDataType
from minikerberos.protocol.encryption import Enctype, _enctype_table, Key
from minikerberos.protocol.asn1_structs import KDC_REQ_BODY, PrincipalName, KDCOptions, EncASRepPart, AS_REQ, PADATA_TYPE, PA_PAC_REQUEST
from minikerberos.protocol.rfc4556 import PKAuthenticator, AuthPack, PA_PK_AS_REP, KDCDHKeyInfo, PA_PK_AS_REQ

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, PAC_CREDENTIAL_INFO, \
    PAC_CREDENTIAL_DATA, NTLM_SUPPLEMENTAL_CREDENTIAL
from impacket.krb5.types import Principal, KerberosTime, Ticket

# Imports for pfx_auth
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.common.target import KerberosTarget
from minikerberos.common.ccache import CCACHE

from impacket.krb5.ccache import CCache as impacket_CCache

from nxc.paths import NXC_PATH
from nxc.logger import nxc_logger


class myPKINIT(PKINIT):
    """
    Copy of minikerberos PKINIT
    With some changes where it differs from PKINIT used in NegoEx
    """

    @staticmethod
    def from_pfx(pfxfile, pfxpass, dh_params=None, b64=False):
        with open(pfxfile, "rb") as f:
            pfxdata = f.read()

        if b64:
            pfxdata = base64.b64decode(pfxdata)

        return myPKINIT.from_pfx_data(pfxdata, pfxpass, dh_params)

    @staticmethod
    def from_pfx_data(pfxdata, pfxpass, dh_params=None):
        pkinit = myPKINIT()
        # oscrypto does not seem to support pfx without password, so convert it to PEM using cryptography instead
        if not pfxpass:
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.hazmat.primitives import serialization
            privkey, cert, extra_certs = pkcs12.load_key_and_certificates(pfxdata, None)
            pem_key = privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pkinit.privkey = load_private_key(parse_private(pem_key))
            pem_cert = cert.public_bytes(
                encoding=serialization.Encoding.PEM
            )
            pkinit.certificate = parse_certificate(pem_cert)
        else:
            if isinstance(pfxpass, str):
                pfxpass = pfxpass.encode()
            pkinit.privkeyinfo, pkinit.certificate, pkinit.extra_certs = parse_pkcs12(pfxdata, password=pfxpass)
            pkinit.privkey = load_private_key(pkinit.privkeyinfo)
        pkinit.setup(dh_params=dh_params)
        return pkinit

    @staticmethod
    def from_pem(certfile, privkeyfile, dh_params=None):
        pkinit = myPKINIT()
        with open(certfile, "rb") as f:
            pkinit.certificate = parse_certificate(f.read())
        with open(privkeyfile, "rb") as f:
            pkinit.privkey = load_private_key(parse_private(f.read()))
        pkinit.setup(dh_params=dh_params)
        return pkinit

    def sign_authpack(self, data, wrap_signed=False):
        return self.sign_authpack_native(data, wrap_signed)

    def setup(self, dh_params=None):
        self.issuer = self.certificate.issuer.native["common_name"]
        if dh_params is None:
            print("Generating DH params...")
            print("DH params generated.")
        else:
            if isinstance(dh_params, dict):
                self.diffie = DirtyDH.from_dict(dh_params)
            elif isinstance(dh_params, bytes):
                self.diffie = DirtyDH.from_asn1(dh_params)
            elif isinstance(dh_params, DirtyDH):
                self.diffie = dh_params
            else:
                raise Exception("DH params must be either a bytearray or a dict")

    def build_asreq(self, domain=None, cname=None, kdcopts=None):
        if kdcopts is None:
            kdcopts = ["forwardable", "renewable", "renewable-ok"]
        if isinstance(kdcopts, list):
            kdcopts = set(kdcopts)
        if cname is not None:
            if isinstance(cname, str):
                cname = [cname]
        else:
            cname = [self.cname]

        now = datetime.datetime.now(datetime.timezone.utc)

        kdc_req_body_data = {}
        kdc_req_body_data["kdc-options"] = KDCOptions(kdcopts)
        kdc_req_body_data["cname"] = PrincipalName({"name-type": NAME_TYPE.PRINCIPAL.value, "name-string": cname})
        kdc_req_body_data["realm"] = domain.upper()
        kdc_req_body_data["sname"] = PrincipalName({"name-type": NAME_TYPE.SRV_INST.value, "name-string": ["krbtgt", domain.upper()]})
        kdc_req_body_data["till"] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
        kdc_req_body_data["rtime"] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
        kdc_req_body_data["nonce"] = secrets.randbits(31)
        kdc_req_body_data["etype"] = [18, 17]  # 23 breaks...
        kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)

        checksum = hashlib.sha1(kdc_req_body.dump()).digest()

        authenticator = {}
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = now.replace(microsecond=0)
        authenticator["nonce"] = secrets.randbits(31)
        authenticator["paChecksum"] = checksum

        dp = {}
        dp["p"] = self.diffie.p
        dp["g"] = self.diffie.g
        dp["q"] = 0  # mandatory parameter, but it is not needed

        pka = {}
        pka["algorithm"] = "1.2.840.10046.2.1"
        pka["parameters"] = keys.DomainParameters(dp)

        spki = {}
        spki["algorithm"] = keys.PublicKeyAlgorithm(pka)
        spki["public_key"] = self.diffie.get_public_key()

        authpack = {}
        authpack["pkAuthenticator"] = PKAuthenticator(authenticator)
        authpack["clientPublicValue"] = keys.PublicKeyInfo(spki)
        authpack["clientDHNonce"] = self.diffie.dh_nonce

        authpack = AuthPack(authpack)
        signed_authpack = self.sign_authpack(authpack.dump(), wrap_signed=True)

        payload = PA_PK_AS_REQ()
        payload["signedAuthPack"] = signed_authpack

        pa_data_1 = {}
        pa_data_1["padata-type"] = PaDataType.PK_AS_REQ.value
        pa_data_1["padata-value"] = payload.dump()

        pa_data_0 = {}
        pa_data_0["padata-type"] = int(PADATA_TYPE("PA-PAC-REQUEST"))
        pa_data_0["padata-value"] = PA_PAC_REQUEST({"include-pac": True}).dump()

        asreq = {}
        asreq["pvno"] = 5
        asreq["msg-type"] = 10
        asreq["padata"] = [pa_data_0, pa_data_1]
        asreq["req-body"] = kdc_req_body

        return AS_REQ(asreq).dump()

    def sign_authpack_native(self, data, wrap_signed=False):
        """
        Creating PKCS7 blob which contains the following things:

        1. 'data' blob which is an ASN1 encoded "AuthPack" structure
        2. the certificate used to sign the data blob
        3. the singed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
        """
        da = {}
        da["algorithm"] = algos.DigestAlgorithmId("1.3.14.3.2.26")  # for sha1

        si = {}
        si["version"] = "v1"
        si["sid"] = cms.IssuerAndSerialNumber({
            "issuer":  self.certificate.issuer,
            "serial_number":  self.certificate.serial_number,
        })

        si["digest_algorithm"] = algos.DigestAlgorithm(da)
        si["signed_attrs"] = [
            cms.CMSAttribute({"type": "content_type", "values": ["1.3.6.1.5.2.3.1"]}),  # indicates that the encap_content_info's authdata struct (marked with OID '1.3.6.1.5.2.3.1' is signed )
            cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha1(data).digest()]}),  # hash of the data, the data itself will not be signed, but this block of data will be.
        ]
        si["signature_algorithm"] = algos.SignedDigestAlgorithm({"algorithm": "1.2.840.113549.1.1.1"})
        si["signature"] = rsa_pkcs1v15_sign(self.privkey, cms.CMSAttributes(si["signed_attrs"]).dump(), "sha1")

        ec = {}
        ec["content_type"] = "1.3.6.1.5.2.3.1"
        ec["content"] = data

        sd = {}
        sd["version"] = "v3"
        sd["digest_algorithms"] = [algos.DigestAlgorithm(da)]  # must have only one
        sd["encap_content_info"] = cms.EncapsulatedContentInfo(ec)
        sd["certificates"] = [self.certificate]
        sd["signer_infos"] = cms.SignerInfos([cms.SignerInfo(si)])

        if wrap_signed is True:
            ci = {}
            ci["content_type"] = "1.2.840.113549.1.7.2"  # signed data OID
            ci["content"] = cms.SignedData(sd)
            return cms.ContentInfo(ci).dump()

        return cms.SignedData(sd).dump()

    def decrypt_asrep(self, as_rep):
        def truncate_key(value, keysize):
            output = b""
            currentNum = 0
            while len(output) < keysize:
                currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
                if len(output) + len(currentDigest) > keysize:
                    output += currentDigest[:keysize - len(output)]
                    break
                output += currentDigest
                currentNum += 1

            return output

        for pa in as_rep["padata"]:
            if pa["padata-type"] == 17:
                pkasrep = PA_PK_AS_REP.load(pa["padata-value"]).native
                break
        else:
            raise Exception("PA_PK_AS_REP not found!")
        ci = cms.ContentInfo.load(pkasrep["dhSignedData"]).native
        sd = ci["content"]
        keyinfo = sd["encap_content_info"]
        if keyinfo["content_type"] != "1.3.6.1.5.2.3.2":
            raise Exception("Keyinfo content type unexpected value")
        authdata = KDCDHKeyInfo.load(keyinfo["content"]).native
        pubkey = int("".join(["1"] + [str(x) for x in authdata["subjectPublicKey"]]), 2)

        pubkey = int.from_bytes(core.BitString(authdata["subjectPublicKey"]).dump()[7:], "big", signed=False)
        shared_key = self.diffie.exchange(pubkey)

        server_nonce = pkasrep["serverDHNonce"]
        fullKey = shared_key + self.diffie.dh_nonce + server_nonce

        etype = as_rep["enc-part"]["etype"]
        cipher = _enctype_table[etype]
        if etype == Enctype.AES256:
            t_key = truncate_key(fullKey, 32)
        elif etype == Enctype.AES128:
            t_key = truncate_key(fullKey, 16)
        elif etype == Enctype.RC4:
            raise NotImplementedError("RC4 key truncation documentation missing. it is different from AES")

        key = Key(cipher.enctype, t_key)
        enc_data = as_rep["enc-part"]["cipher"]
        nxc_logger.info("AS-REP encryption key (you might need this later):")
        nxc_logger.info(hexlify(t_key).decode("utf-8"))
        dec_data = cipher.decrypt(key, 3, enc_data)
        encasrep = EncASRepPart.load(dec_data).native
        cipher = _enctype_table[int(encasrep["key"]["keytype"])]
        session_key = Key(cipher.enctype, encasrep["key"]["keyvalue"])
        return encasrep, session_key, cipher, hexlify(t_key).decode("utf-8")


class GETPAC:

    def printPac(self, data, key=None):
        nthash = None
        encTicketPart = decoder.decode(data, asn1Spec=EncTicketPart())[0]
        adIfRelevant = decoder.decode(encTicketPart["authorization-data"][0]["ad-data"], asn1Spec=AD_IF_RELEVANT())[
            0]
        # So here we have the PAC
        pacType = PACTYPE(adIfRelevant[0]["ad-data"].asOctets())
        buff = pacType["Buffers"]
        found = False
        for _bufferN in range(pacType["cBuffers"]):
            infoBuffer = PAC_INFO_BUFFER(buff)
            data = pacType["Buffers"][infoBuffer["Offset"] - 8:][:infoBuffer["cbBufferSize"]]
            nxc_logger.debug(f"TYPE 0x{infoBuffer['ulType']}")
            if infoBuffer["ulType"] == 2:
                found = True
                credinfo = PAC_CREDENTIAL_INFO(data)
                newCipher = _enctype_table[credinfo["EncryptionType"]]
                out = newCipher.decrypt(key, 16, credinfo["SerializedData"])
                type1 = TypeSerialization1(out)
                # I'm skipping here 4 bytes with its the ReferentID for the pointer
                newdata = out[len(type1) + 4:]
                pcc = PAC_CREDENTIAL_DATA(newdata)
                for cred in pcc["Credentials"]:
                    credstruct = NTLM_SUPPLEMENTAL_CREDENTIAL(b"".join(cred["Credentials"]))

                    nxc_logger.info("Recovered NT Hash")
                    nxc_logger.info(hexlify(credstruct["NtPassword"]).decode("utf-8"))
                    nthash = hexlify(credstruct["NtPassword"]).decode("utf-8")

            buff = buff[len(infoBuffer):]

        if not found:
            nxc_logger.info("Did not find the PAC_CREDENTIAL_INFO in the PAC. Are you sure your TGT originated from a PKINIT operation?")
        return nthash

    def __init__(self, username, domain, kdcHost, key, tgt):
        self.__username = username
        self.__domain = domain.upper()
        self.__kdcHost = kdcHost
        self.__asrep_key = key
        self.__tgt = tgt["KDC_REP"]
        self.__cipher = tgt["cipher"]
        self.__sessionKey = tgt["sessionKey"]

    def dump(self):
        # Try all requested protocols until one works.
        tgt = self.__tgt
        cipher = self.__cipher
        sessionKey = self.__sessionKey

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT["ticket"])

        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq["ap-options"] = constants.encodeFlags(opts)
        seq_set(apReq, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = str(decodedTGT["crealm"])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, "crealm", "cname")

        seq_set(authenticator, "cname", clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        nxc_logger.debug("AUTHENTICATOR")
        nxc_logger.debug(authenticator.prettyPrint() + "\n")

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq["pvno"] = 5
        tgsReq["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq["padata"] = noValue
        tgsReq["padata"][0] = noValue
        tgsReq["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq["padata"][0]["padata-value"] = encodedApReq

        reqBody = seq_set(tgsReq, "req-body")

        opts = []
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody["kdc-options"] = constants.encodeFlags(opts)

        serverName = Principal(self.__username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, "sname", serverName.components_to_asn1)
        reqBody["realm"] = str(decodedTGT["crealm"])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody["till"] = KerberosTime.to_asn1(now)
        reqBody["nonce"] = random.getrandbits(31)
        seq_set_iter(reqBody, "etype",
                     (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, "additional-tickets", (myTicket,))
        nxc_logger.debug("Final TGS")
        nxc_logger.debug(tgsReq.prettyPrint())

        message = encoder.encode(tgsReq)
        nxc_logger.info("Requesting ticket to self with PAC")

        r = sendReceive(message, self.__domain, self.__kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        nxc_logger.debug("TGS_REP")
        nxc_logger.debug(tgs.prettyPrint())

        cipherText = tgs["ticket"]["enc-part"]["cipher"]

        # Key Usage 2
        # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
        #  application session key), encrypted with the service key
        #  (section 5.4.2)

        # S4USelf + U2U uses this other key
        plainText = cipher.decrypt(sessionKey, 2, cipherText)
        specialkey = Key(18, unhexlify(self.__asrep_key))
        return self.printPac(plainText, specialkey)


def pfx_auth(self):
    """Handles the authentication using a PFX or PEM file"""
    # Static DH params because the ones generated by cryptography are considered unsafe by AD for some weird reason
    dhparams = {
        "p": int("00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff", 16),
        "g": 2
    }
    self.logger.info("Loading certificate and key from file")

    # Load the certificate and key from file
    if self.args.pfx_cert or self.args.pfx_base64:
        pfx = self.args.pfx_cert if self.args.pfx_cert else self.args.pfx_base64
        ini = myPKINIT.from_pfx(pfx, self.args.pfx_pass, dhparams, bool(self.args.pfx_base64))
    elif self.args.pem_cert and self.args.pem_key:
        ini = myPKINIT.from_pem(self.args.pem_cert, self.args.pem_key, dhparams)
    else:
        self.logger.fail("You must either specify a PFX file + optional password or a combination of Cert PEM file and Private key PEM file")
        return None

    username = self.args.username[0]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S").replace(":", "-")
    log_ccache = os.path.normpath(os.path.expanduser(f"{NXC_PATH}/logs/{self.hostname}_{self.host}_{timestamp}-{username}.ccache"))

    # Request a TGT with the cert data
    req = ini.build_asreq(self.domain, username)
    self.logger.info("Requesting TGT")

    sock = KerberosClientSocket(KerberosTarget(self.kdcHost))
    try:
        res = sock.sendrecv(req)
    except Exception as e:
        self.logger.fail(str(e))
        return False

    encasrep, session_key, cipher, key = ini.decrypt_asrep(res.native)
    ccache_minikerberos = CCACHE()
    ccache_minikerberos.add_tgt(res.native, encasrep)
    ccache_minikerberos.to_file(log_ccache)
    self.logger.info(f"Saved TGT to file {log_ccache}")
    self.logger.info(f"Using Kerberos Cache {log_ccache}")
    ccache = impacket_CCache.loadFile(log_ccache)
    principal = f"krbtgt/{self.domain.upper()}@{self.domain.upper()}"
    creds = ccache.getCredential(principal)
    if creds is not None:
        tgt = creds.toTGT()
        dumper = GETPAC(username, self.domain, self.kdcHost, key, tgt)
        nthash = dumper.dump()
        if not self.kerberos:
            self.hash_login(self.domain, username, nthash)
        else:
            self.kerberos_login(self.domain, username, "", nthash, "", self.kdcHost, False)

    self.logger.info("Successfully authenticated using Certificate")
    return True
