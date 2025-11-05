# Standard library imports
import random
from datetime import datetime, timezone

# External library imports
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import Principal, KerberosTime
from pyasn1.codec.der import encoder

# Local library imports
from nxc.logger import nxc_logger

class KerberosUserEnum:
    """
    Kerberos User Enumeration Class

    Provides methods to enumerate valid Active Directory usernames via Kerberos
    AS-REQ requests without triggering badPwdCount increments.
    """

    def __init__(self, domain, kdcHost, timeout=10):
        """
        Initialize Kerberos User Enumeration

        Args:
            domain (str): The target Active Directory domain (e.g., 'CORP.LOCAL')
            kdcHost (str): IP address or FQDN of the KDC (Domain Controller)
            timeout (int): Socket timeout in seconds
        """
        self.domain = domain.upper()
        self.kdcHost = kdcHost
        self.timeout = timeout

    def check_user_exists(self, username: str) -> bool:
        """
        Check if a username exists in Active Directory via Kerberos AS-REQ.

        This method sends a Kerberos AS-REQ (Authentication Service Request) with
        no preauthentication data. The KDC's response reveals whether the user exists:

        - KDC_ERR_PREAUTH_REQUIRED (KDC_ERR_CODE 25): User exists (preauth required)
        - KDC_ERR_C_PRINCIPAL_UNKNOWN (KDC_ERR_CODE 6): User does not exist
        - KDC_ERR_CLIENT_REVOKED: User account is disabled
        - Other errors: Various account/policy issues

        This method does NOT increment badPwdCount since no password is provided.

        Args:
            username (str): Username to check (without domain)

        Returns:
            bool or str:
                - True if user exists and is valid
                - False if user does not exist
                - Error string if another error occurred
        """
        try:
            # Build the principal name
            client_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

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
            req_body["realm"] = self.domain

            # Set server principal (krbtgt)
            server_principal = Principal(
                f"krbtgt/{self.domain}",
                type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            seq_set(req_body, "sname", server_principal.components_to_asn1)

            now = datetime.now(timezone.utc)

            req_body["till"] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
            req_body["rtime"] = KerberosTime.to_asn1(now.replace(year=now.year + 1))
            req_body["nonce"] = random.randint(1, 2147483647)  # Random 32-bit positive integer

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
                sendReceive(message, self.domain, self.kdcHost)
            except KerberosError as e:
                # Analyze the error code to determine user status
                error_code = e.getErrorCode()

                if error_code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                    # User exists! (KDC requires preauthentication)
                    return True

                elif error_code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                    # User does not exist
                    return False

                elif error_code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                    # User exists but account is disabled
                    nxc_logger.debug(f"User {username} exists but account is disabled")
                    return "ACCOUNT_DISABLED"

                elif error_code == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value:
                    return "WRONG_REALM"

                else:
                    # Other Kerberos error
                    error_msg = constants.ErrorCodes(error_code).name if hasattr(constants.ErrorCodes, "_value2member_map_") else str(error_code)
                    nxc_logger.debug(f"Kerberos error for {username}: {error_msg}")
                    return f"KRB_ERROR_{error_code}"

            # If we get an AS-REP without error, user exists (very rare without preauth)
            return True

        except TimeoutError:
            return "TIMEOUT"
        except OSError as e:
            return f"SOCKET_ERROR: {e}"
        except Exception as e:
            nxc_logger.debug(f"Unexpected error checking {username}: {e}")
            return f"ERROR: {e}"
