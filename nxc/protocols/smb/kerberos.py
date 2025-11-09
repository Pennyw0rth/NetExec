# Standard library imports
import datetime
import struct
import random
from six import b

# External library imports
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REQ,
    AS_REP,
    TGS_REQ,
    Authenticator,
    TGS_REP,
    seq_set,
    seq_set_iter,
    PA_FOR_USER_ENC,
    Ticket as TicketAsn1,
    EncTGSRepPart,
    PA_PAC_OPTIONS,
)
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT, KerberosError
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5
from impacket.krb5 import constants

# Local library imports
from nxc.logger import nxc_logger


def kerberos_login_with_S4U(
    domain: str,
    hostname: str,
    username: str,
    password: str,
    nthash: str,
    lmhash: str,
    aesKey: str,
    kdcHost: str,
    impersonate: str,
    spn: str,
    use_cache: bool,
    no_s4u2proxy: bool = False,
):
    my_tgt = None
    if use_cache:
        domain, _, tgt, _ = CCache.parseFile(domain, username, f"cifs/{hostname}")
        if my_tgt is None:
            raise
        my_tgt = tgt["KDC_REP"]
        cipher = tgt["cipher"]
        session_key = tgt["sessionKey"]
    if my_tgt is None:
        principal = Principal(
            username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        nxc_logger.debug("Getting TGT for user")
        tgt, cipher, _, session_key = getKerberosTGT(
            principal, password, domain, lmhash, nthash, aesKey, kdcHost
        )
        my_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    decoded_tgt = my_tgt
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    ap_req["ap-options"] = constants.encodeFlags(opts)
    seq_set(ap_req, "ticket", ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decoded_tgt["crealm"])

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")

    seq_set(authenticator, "cname", client_name.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encrypted_encoded_authenticator = cipher.encrypt(
        session_key, 7, encoded_authenticator, None
    )

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

    encoded_ap_req = encoder.encode(ap_req)

    tgs_req = TGS_REQ()

    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgs_req["padata"][0]["padata-value"] = encoded_ap_req

    # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
    # requests a service ticket to itself on behalf of a user. The user is
    # identified to the KDC by the user's name and realm.
    client_name = Principal(
        impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    s4u_byte_array = struct.pack("<I", constants.PrincipalNameType.NT_PRINCIPAL.value)
    s4u_byte_array += impersonate.encode() + b(domain) + b"Kerberos"

    # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
    # with the following three parameters: the session key of the TGT of
    # the service performing the S4U2Self request, the message type value
    # of 17, and the byte array s4u_byte_array.
    checksum = _HMACMD5.checksum(session_key, 17, s4u_byte_array)

    pa_fo_user_enc = PA_FOR_USER_ENC()
    seq_set(pa_fo_user_enc, "userName", client_name.components_to_asn1)
    pa_fo_user_enc["userRealm"] = domain
    pa_fo_user_enc["cksum"] = noValue
    pa_fo_user_enc["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
    pa_fo_user_enc["cksum"]["checksum"] = checksum
    pa_fo_user_enc["auth-package"] = "Kerberos"

    encoded_pa_for_user_enc = encoder.encode(pa_fo_user_enc)

    tgs_req["padata"][1] = noValue
    tgs_req["padata"][1]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_FOR_USER.value
    )
    tgs_req["padata"][1]["padata-value"] = encoded_pa_for_user_enc

    req_body = seq_set(tgs_req, "req-body")

    opts = []
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.canonicalize.value)

    req_body["kdc-options"] = constants.encodeFlags(opts)

    server_name = Principal(username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

    seq_set(req_body, "sname", server_name.components_to_asn1)
    req_body["realm"] = str(decoded_tgt["crealm"])

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    req_body["till"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(
        req_body,
        "etype",
        (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)),
    )

    nxc_logger.info("Requesting S4U2self")
    message = encoder.encode(tgs_req)

    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    if no_s4u2proxy:
        cipher_text = tgs["enc-part"]["cipher"]

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plaintext = cipher.decrypt(session_key, 8, cipher_text)

        enc_tgs_rep_part = decoder.decode(plaintext, asn1Spec=EncTGSRepPart())[0]

        new_session_key = Key(
            enc_tgs_rep_part["key"]["keytype"],
            enc_tgs_rep_part["key"]["keyvalue"].asOctets(),
        )

        # Creating new cipher based on received keytype
        cipher = _enctype_table[enc_tgs_rep_part["key"]["keytype"]]

        tgs_formated = {}
        tgs_formated["KDC_REP"] = r
        tgs_formated["cipher"] = cipher
        tgs_formated["sessionKey"] = new_session_key
        return tgs_formated

    ################################################################################
    # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
    # So here I have a ST for me.. I now want a ST for another service
    # Extract the ticket from the TGT
    ticket_tgt = Ticket()
    ticket_tgt.from_asn1(decoded_tgt["ticket"])

    # Get the service ticket
    ticket = Ticket()
    ticket.from_asn1(tgs["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    ap_req["ap-options"] = constants.encodeFlags(opts)
    seq_set(ap_req, "ticket", ticket_tgt.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decoded_tgt["crealm"])

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")

    seq_set(authenticator, "cname", client_name.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encrypted_encoded_authenticator = cipher.encrypt(
        session_key, 7, encoded_authenticator, None
    )

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_encoded_authenticator

    encoded_ap_req = encoder.encode(ap_req)

    tgs_req = TGS_REQ()

    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgs_req["padata"][0]["padata-value"] = encoded_ap_req

    # Add resource-based constrained delegation support
    pa_pac_options = PA_PAC_OPTIONS()
    pa_pac_options["flags"] = constants.encodeFlags(
        (constants.PAPacOptions.resource_based_constrained_delegation.value,)
    )

    tgs_req["padata"][1] = noValue
    tgs_req["padata"][1][
        "padata-type"
    ] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
    tgs_req["padata"][1]["padata-value"] = encoder.encode(pa_pac_options)

    req_body = seq_set(tgs_req, "req-body")

    opts = []
    # This specified we"re doing S4U
    opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
    opts.append(constants.KDCOptions.canonicalize.value)
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)

    req_body["kdc-options"] = constants.encodeFlags(opts)
    service2 = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(req_body, "sname", service2.components_to_asn1)
    req_body["realm"] = domain

    my_ticket = ticket.to_asn1(TicketAsn1())
    seq_set_iter(req_body, "additional-tickets", (my_ticket,))

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    req_body["till"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(
        req_body,
        "etype",
        (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
            int(constants.EncryptionTypes.des_cbc_md5.value),
            int(cipher.enctype),
        ),
    )
    message = encoder.encode(tgs_req)

    nxc_logger.info("Requesting S4U2Proxy")
    r = sendReceive(message, domain, kdcHost)

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    cipher_text = tgs["enc-part"]["cipher"]

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plaintext = cipher.decrypt(session_key, 8, cipher_text)

    enc_tgs_rep_part = decoder.decode(plaintext, asn1Spec=EncTGSRepPart())[0]

    new_session_key = Key(
        enc_tgs_rep_part["key"]["keytype"],
        enc_tgs_rep_part["key"]["keyvalue"].asOctets(),
    )

    # Creating new cipher based on received keytype
    cipher = _enctype_table[enc_tgs_rep_part["key"]["keytype"]]

    tgs_formated = {}
    tgs_formated["KDC_REP"] = r
    tgs_formated["cipher"] = cipher
    tgs_formated["sessionKey"] = new_session_key
    return tgs_formated


def kerberos_asreq_user_enum(domain: str, username: str, kdcHost: str) -> str:
    """
    Check if a username exists in Active Directory via Kerberos AS-REQ enumeration.

    This function sends a Kerberos AS-REQ (Authentication Service Request) with
    no preauthentication data. The KDC's response reveals whether the user exists
    without incrementing badPwdCount since no password is provided.

    KDC Response Codes:
        - KDC_ERR_PREAUTH_REQUIRED (25): User exists (preauth required)
        - KDC_ERR_C_PRINCIPAL_UNKNOWN (6): User does not exist
        - KDC_ERR_CLIENT_REVOKED: User account is disabled
        - Other errors: Various account/policy issues

    Args:
        domain (str): The target Active Directory domain (e.g., 'CORP.LOCAL')
        username (str): Username to check (without domain)
        kdcHost (str): IP address or FQDN of the KDC (Domain Controller)

    Returns:
        str: Status of the user check
            - "valid": User exists and is active
            - "disabled": User exists but account is disabled
            - "invalid": User does not exist
            - "wrong_realm": Wrong domain/realm
            - "timeout": Connection timeout
            - "error:<message>": Other error occurred
    """
    try:
        # Build the principal name
        client_principal = Principal(
            username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )

        # Build AS-REQ
        as_req = AS_REQ()

        # Set domain
        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        # Request body
        req_body = seq_set(as_req, "req-body")

        # KDC Options - request forwardable and renewable tickets
        opts = []
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.renewable_ok.value)
        req_body["kdc-options"] = constants.encodeFlags(opts)

        # Set client principal
        seq_set(req_body, "cname", client_principal.components_to_asn1)
        req_body["realm"] = domain

        # Set server principal (krbtgt)
        server_principal = Principal(
            f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        seq_set(req_body, "sname", server_principal.components_to_asn1)

        now = datetime.datetime.utcnow()

        req_body["till"] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
        req_body["rtime"] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
        req_body["nonce"] = random.randint(
            1, 2147483647
        )  # Random 32-bit positive integer

        # Set encryption types - prefer AES
        supported_ciphers = (
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.rc4_hmac.value,
        )
        seq_set_iter(req_body, "etype", supported_ciphers)

        # No preauthentication data (this is key for enumeration)
        # We deliberately don't include PA-DATA to trigger preauth required response

        # Encode and send the request
        message = encoder.encode(as_req)

        try:
            sendReceive(message, domain, kdcHost)
        except KerberosError as e:
            # Analyze the error code to determine user status
            error_code = e.getErrorCode()

            if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                # User exists! (KDC requires preauthentication)
                return "valid"

            elif error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                # User does not exist
                return "invalid"

            elif error_code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                # User exists but account is disabled
                return "disabled"

            elif error_code == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value:
                return "wrong_realm"

            else:
                # Other Kerberos error
                error_msg = (
                    constants.ErrorCodes(error_code).name
                    if hasattr(constants.ErrorCodes, "_value2member_map_")
                    else str(error_code)
                )
                return f"error:krb_{error_msg}"

        # If we get an AS-REP without error, user exists (very rare without preauth)
        return "valid"

    except TimeoutError:
        return "error:timeout"
    except OSError as e:
        return f"error:socket_{e}"
    except Exception as e:
        return f"error:{e}"
