import datetime
import logging
import struct
import random
from six import b

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5
from impacket.krb5 import constants

def kerberos_login_with_S4U(domain, hostname, username, password, nthash, lmhash, aesKey, kdcHost, impersonate, spn, useCache, no_s4u2proxy = False):
    logger = logging.getLogger("nxc")
    TGT = None
    if useCache:
        domain, user, tgt, _ = CCache.parseFile(domain, username, f"cifs/{hostname}")
        if TGT is None:
            raise
        TGT = tgt["KDC_REP"]
        cipher = tgt["cipher"]
        sessionKey = tgt["sessionKey"]
    if TGT is None:
        userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logger.debug("Getting TGT for user")
        tgt, cipher, _, sessionKey = getKerberosTGT(userName, password, domain,
                                                                lmhash, nthash,
                                                                aesKey,
                                                                kdcHost)
        TGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    decodedTGT=TGT
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decodedTGT["ticket"])

    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
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

    # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
    # requests a service ticket to itself on behalf of a user. The user is
    # identified to the KDC by the user"s name and realm.
    clientName = Principal(impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    S4UByteArray = struct.pack("<I", constants.PrincipalNameType.NT_PRINCIPAL.value)
    S4UByteArray += b(impersonate) + b(domain) + b"Kerberos"

    # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
    # with the following three parameters: the session key of the TGT of
    # the service performing the S4U2Self request, the message type value
    # of 17, and the byte array S4UByteArray.
    checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

    paForUserEnc = PA_FOR_USER_ENC()
    seq_set(paForUserEnc, "userName", clientName.components_to_asn1)
    paForUserEnc["userRealm"] = domain
    paForUserEnc["cksum"] = noValue
    paForUserEnc["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
    paForUserEnc["cksum"]["checksum"] = checkSum
    paForUserEnc["auth-package"] = "Kerberos"

    encodedPaForUserEnc = encoder.encode(paForUserEnc)

    tgsReq["padata"][1] = noValue
    tgsReq["padata"][1]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
    tgsReq["padata"][1]["padata-value"] = encodedPaForUserEnc

    reqBody = seq_set(tgsReq, "req-body")

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.canonicalize.value)

    reqBody["kdc-options"] = constants.encodeFlags(opts)

    serverName = Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

    seq_set(reqBody, "sname", serverName.components_to_asn1)
    reqBody["realm"] = str(decodedTGT["crealm"])

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody["till"] = KerberosTime.to_asn1(now)
    reqBody["nonce"] = random.getrandbits(31)
    seq_set_iter(reqBody, "etype",
                    (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

    logger.info("Requesting S4U2self")
    message = encoder.encode(tgsReq)

    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    if no_s4u2proxy:
        cipherText = tgs["enc-part"]["cipher"]

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        newSessionKey = Key(encTGSRepPart["key"]["keytype"], encTGSRepPart["key"]["keyvalue"].asOctets())

        # Creating new cipher based on received keytype
        cipher = _enctype_table[encTGSRepPart["key"]["keytype"]]

        #return r, cipher, sessionKey, newSessionKey
        tgs_formated = dict()
        tgs_formated["KDC_REP"] = r
        tgs_formated["cipher"] = cipher
        tgs_formated["sessionKey"] = newSessionKey
        return tgs_formated

    ################################################################################
    # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
    # So here I have a ST for me.. I now want a ST for another service
    # Extract the ticket from the TGT
    ticketTGT = Ticket()
    ticketTGT.from_asn1(decodedTGT["ticket"])

    # Get the service ticket
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])

    apReq = AP_REQ()
    apReq["pvno"] = 5
    apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq["ap-options"] = constants.encodeFlags(opts)
    seq_set(apReq, "ticket", ticketTGT.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decodedTGT["crealm"])

    clientName = Principal()
    clientName.from_asn1(decodedTGT, "crealm", "cname")

    seq_set(authenticator, "cname", clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

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

    # Add resource-based constrained delegation support
    paPacOptions = PA_PAC_OPTIONS()
    paPacOptions["flags"] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

    tgsReq["padata"][1] = noValue
    tgsReq["padata"][1]["padata-type"] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
    tgsReq["padata"][1]["padata-value"] = encoder.encode(paPacOptions)

    reqBody = seq_set(tgsReq, "req-body")

    opts = list()
    # This specified we"re doing S4U
    opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
    opts.append(constants.KDCOptions.canonicalize.value)
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)

    reqBody["kdc-options"] = constants.encodeFlags(opts)
    service2 = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(reqBody, "sname", service2.components_to_asn1)
    reqBody["realm"] = domain

    myTicket = ticket.to_asn1(TicketAsn1())
    seq_set_iter(reqBody, "additional-tickets", (myTicket,))

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody["till"] = KerberosTime.to_asn1(now)
    reqBody["nonce"] = random.getrandbits(31)
    seq_set_iter(reqBody, "etype",
                    (
                        int(constants.EncryptionTypes.rc4_hmac.value),
                        int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                        int(constants.EncryptionTypes.des_cbc_md5.value),
                        int(cipher.enctype)
                    )
                )
    message = encoder.encode(tgsReq)

    logger.info("Requesting S4U2Proxy")
    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    cipherText = tgs["enc-part"]["cipher"]

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

    newSessionKey = Key(encTGSRepPart["key"]["keytype"], encTGSRepPart["key"]["keyvalue"].asOctets())

    # Creating new cipher based on received keytype
    cipher = _enctype_table[encTGSRepPart["key"]["keytype"]]

    #return r, cipher, sessionKey, newSessionKey
    tgs_formated = dict()
    tgs_formated["KDC_REP"] = r
    tgs_formated["cipher"] = cipher
    tgs_formated["sessionKey"] = newSessionKey
    return tgs_formated