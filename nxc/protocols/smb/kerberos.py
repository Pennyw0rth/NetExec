import datetime
import logging
import struct
import random
from impacket.winregistry import hexdump
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
    TGT = None
    if useCache:
        domain, user, tgt, _ = CCache.parseFile(domain, user, 'cifs/%s' % hostname)
        if TGT is None:
            raise
        TGT = tgt['KDC_REP']
        cipher = tgt['cipher']
        sessionKey = tgt['sessionKey']
    if TGT is None:
        userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Getting TGT for user')
        tgt, cipher, _, sessionKey = getKerberosTGT(userName, password, domain,
                                                                lmhash, nthash,
                                                                aesKey,
                                                                kdcHost)
        TGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    decodedTGT=TGT
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decodedTGT['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = str(decodedTGT['crealm'])

    clientName = Principal()
    clientName.from_asn1(decodedTGT, 'crealm', 'cname')

    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    if logging.getLogger().level == logging.DEBUG:
        logging.debug('AUTHENTICATOR')
        print(authenticator.prettyPrint())
        print('\n')

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    encodedApReq = encoder.encode(apReq)

    tgsReq = TGS_REQ()

    tgsReq['pvno'] = 5
    tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    tgsReq['padata'] = noValue
    tgsReq['padata'][0] = noValue
    tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq['padata'][0]['padata-value'] = encodedApReq

    # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
    # requests a service ticket to itself on behalf of a user. The user is
    # identified to the KDC by the user's name and realm.
    clientName = Principal(impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    S4UByteArray = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
    S4UByteArray += b(impersonate) + b(domain) + b'Kerberos'

    if logging.getLogger().level == logging.DEBUG:
        logging.debug('S4UByteArray')
        hexdump(S4UByteArray)

    # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
    # with the following three parameters: the session key of the TGT of
    # the service performing the S4U2Self request, the message type value
    # of 17, and the byte array S4UByteArray.
    checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

    if logging.getLogger().level == logging.DEBUG:
        logging.debug('CheckSum')
        hexdump(checkSum)

    paForUserEnc = PA_FOR_USER_ENC()
    seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
    paForUserEnc['userRealm'] = domain
    paForUserEnc['cksum'] = noValue
    paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
    paForUserEnc['cksum']['checksum'] = checkSum
    paForUserEnc['auth-package'] = 'Kerberos'

    if logging.getLogger().level == logging.DEBUG:
        logging.debug('PA_FOR_USER_ENC')
        print(paForUserEnc.prettyPrint())

    encodedPaForUserEnc = encoder.encode(paForUserEnc)

    tgsReq['padata'][1] = noValue
    tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
    tgsReq['padata'][1]['padata-value'] = encodedPaForUserEnc

    reqBody = seq_set(tgsReq, 'req-body')

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.canonicalize.value)

    reqBody['kdc-options'] = constants.encodeFlags(opts)

    serverName = Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    reqBody['realm'] = str(decodedTGT['crealm'])

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = random.getrandbits(31)
    seq_set_iter(reqBody, 'etype',
                    (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

    if logging.getLogger().level == logging.DEBUG:
        logging.debug('Final TGS')
        print(tgsReq.prettyPrint())

    logging.info('\tRequesting S4U2self')
    message = encoder.encode(tgsReq)

    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    if no_s4u2proxy:
        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())

        # Creating new cipher based on received keytype
        cipher = _enctype_table[encTGSRepPart['key']['keytype']]

        #return r, cipher, sessionKey, newSessionKey
        tgs_formated = dict()
        tgs_formated['KDC_REP'] = r
        tgs_formated['cipher'] = cipher
        tgs_formated['sessionKey'] = newSessionKey
        return tgs_formated

    if logging.getLogger().level == logging.DEBUG:
        logging.debug('TGS_REP')
        print(tgs.prettyPrint())

    # if self.__force_forwardable:
        # Convert hashes to binary form, just in case we're receiving strings
        # if isinstance(nthash, str):
        #     try:
        #         nthash = unhexlify(nthash)
        #     except TypeError:
        #         pass
        # if isinstance(aesKey, str):
        #     try:
        #         aesKey = unhexlify(aesKey)
        #     except TypeError:
        #         pass

        # # Compute NTHash and AESKey if they're not provided in arguments
        # if password != '' and domain != '' and username != '':
        #     if not nthash:
        #         nthash = compute_nthash(password)
        #         if logging.getLogger().level == logging.DEBUG:
        #             logging.debug('NTHash')
        #             print(hexlify(nthash).decode())
        #     if not aesKey:
        #         salt = domain.upper() + username
        #         aesKey = _AES256CTS.string_to_key(password, salt, params=None).contents
        #         if logging.getLogger().level == logging.DEBUG:
        #             logging.debug('AESKey')
        #             print(hexlify(aesKey).decode())

        # # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
        # cipherText = tgs['ticket']['enc-part']['cipher']

        # # Check which cipher was used to encrypt the ticket. It's not always the same
        # # This determines which of our keys we should use for decryption/re-encryption
        # newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
        # if newCipher.enctype == Enctype.RC4:
        #     key = Key(newCipher.enctype, nthash)
        # else:
        #     key = Key(newCipher.enctype, aesKey)

        # # Decrypt and decode the ticket
        # # Key Usage 2
        # # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
        # #  application session key), encrypted with the service key
        # #  (section 5.4.2)
        # plainText = newCipher.decrypt(key, 2, cipherText)
        # encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

        # # Print the flags in the ticket before modification
        # logging.debug('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
        # logging.debug('\tService ticket from S4U2self is'
        #                 + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
        #                 + ' forwardable')

        # # Customize flags the forwardable flag is the only one that really matters
        # logging.info('\tForcing the service ticket to be forwardable')
        # # convert to string of bits
        # flagBits = encTicketPart['flags'].asBinary()
        # # Set the forwardable flag. Awkward binary string insertion
        # flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
        # # Overwrite the value with the new bits
        # encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

        # logging.debug('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
        # logging.debug('\tService ticket now is'
        #                 + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
        #                 + ' forwardable')

        # # Re-encode and re-encrypt the ticket
        # # Again, Key Usage 2
        # encodedEncTicketPart = encoder.encode(encTicketPart)
        # cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

        # # put it back in the TGS
        # tgs['ticket']['enc-part']['cipher'] = cipherText

    ################################################################################
    # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
    # So here I have a ST for me.. I now want a ST for another service
    # Extract the ticket from the TGT
    ticketTGT = Ticket()
    ticketTGT.from_asn1(decodedTGT['ticket'])

    # Get the service ticket
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticketTGT.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = str(decodedTGT['crealm'])

    clientName = Principal()
    clientName.from_asn1(decodedTGT, 'crealm', 'cname')

    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    encodedApReq = encoder.encode(apReq)

    tgsReq = TGS_REQ()

    tgsReq['pvno'] = 5
    tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq['padata'] = noValue
    tgsReq['padata'][0] = noValue
    tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq['padata'][0]['padata-value'] = encodedApReq

    # Add resource-based constrained delegation support
    paPacOptions = PA_PAC_OPTIONS()
    paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

    tgsReq['padata'][1] = noValue
    tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
    tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

    reqBody = seq_set(tgsReq, 'req-body')

    opts = list()
    # This specified we're doing S4U
    opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
    opts.append(constants.KDCOptions.canonicalize.value)
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)

    reqBody['kdc-options'] = constants.encodeFlags(opts)
    service2 = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(reqBody, 'sname', service2.components_to_asn1)
    reqBody['realm'] = domain

    myTicket = ticket.to_asn1(TicketAsn1())
    seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = random.getrandbits(31)
    seq_set_iter(reqBody, 'etype',
                    (
                        int(constants.EncryptionTypes.rc4_hmac.value),
                        int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                        int(constants.EncryptionTypes.des_cbc_md5.value),
                        int(cipher.enctype)
                    )
                    )
    message = encoder.encode(tgsReq)

    logging.info('\tRequesting S4U2Proxy')
    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    cipherText = tgs['enc-part']['cipher']

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

    newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())

    # Creating new cipher based on received keytype
    cipher = _enctype_table[encTGSRepPart['key']['keytype']]

    #return r, cipher, sessionKey, newSessionKey
    tgs_formated = dict()
    tgs_formated['KDC_REP'] = r
    tgs_formated['cipher'] = cipher
    tgs_formated['sessionKey'] = newSessionKey
    return tgs_formated