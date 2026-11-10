import random
from datetime import UTC, datetime, timedelta

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, AS_REP, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue
from sys import exit

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Kerberos username enumeration (same approach as kerbrute and nmap krb5-enum-users).

    Sends a pre-auth-less AS-REQ per username: PRINCIPAL UNKNOWN means the user is absent,
    a pre-auth request means it exists, and an AS-REP back means it exists with pre-auth off.
    No login is attempted, so no account gets locked out. Logs event 4768 on the DC.

    Module by: @CobblePot59
    """
    name = "user-enum"
    description = "Enumerate valid usernames via Kerberos pre-auth without locking out accounts"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        USER        Single username to check
        USERSFILE   Path to a file containing usernames, one per line

        Examples:
        nxc ldap $DC_IP -u '' -p '' -M user-enum -o USER=administrator
        nxc ldap $DC_IP -u '' -p '' -M user-enum -o USERSFILE=users.txt
        """
        self.single_user = module_options.get("USER")
        self.usersfile = module_options.get("USERSFILE")

        if not self.single_user and not self.usersfile:
            context.log.fail("USER or USERSFILE option is required")
            exit(1)

    def on_login(self, context, connection):
        domain = connection.domain
        kdc_host = connection.kdcHost or connection.host

        if self.single_user:
            usernames = [self.single_user]
        else:
            with open(self.usersfile) as users_file:
                usernames = [line.strip() for line in users_file if line.strip()]

        found = 0
        for username in usernames:
            if self.check_user(context, connection, username, domain, kdc_host):
                found += 1

        if found:
            context.log.success(f"Found {found} valid username(s), added to the database")
        else:
            context.log.fail("No valid usernames found")

    def check_user(self, context, connection, username, domain, kdc_host):
        # Check one username and store it in the database if it exists.
        note = ""
        try:
            response = sendReceive(self.build_as_req(username, domain), domain, kdc_host, timeout=connection.args.ldap_timeout)
            if self.is_as_rep(response):
                note = " (no pre-auth required, AS-REP roastable)"
        except KerberosError as e:
            code = e.getErrorCode()
            if code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                note = " (disabled or locked account)"
            elif code == constants.ErrorCodes.KDC_ERR_KEY_EXPIRED.value:
                note = " (password expired)"
            elif code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                context.log.debug(f"{username}@{domain} does not exist")
                return False
            else:
                context.log.error(f"Error checking {username}@{domain}: {e}")
                return False

        context.log.highlight(f"{username}@{domain}{note}")
        connection.db.add_credential("plaintext", domain, username, "")
        return True

    def is_as_rep(self, response):
        # If the KDC returned an AS-REP, meaning pre-auth is disabled.
        try:
            decoder.decode(response, asn1Spec=AS_REP())[0]
            return True
        except PyAsn1Error:
            return False

    def build_as_req(self, username, domain):
        client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        server_name = Principal(f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pac_request = KERB_PA_PAC_REQUEST()
        pac_request["include-pac"] = True

        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        as_req["padata"][0]["padata-value"] = encoder.encode(pac_request)

        req_body = seq_set(as_req, "req-body")
        req_body["kdc-options"] = constants.encodeFlags([constants.KDCOptions.forwardable.value, constants.KDCOptions.renewable.value, constants.KDCOptions.proxiable.value])
        seq_set(req_body, "cname", client_name.components_to_asn1)
        seq_set(req_body, "sname", server_name.components_to_asn1)
        req_body["realm"] = domain.upper()

        expiry = datetime.now(UTC) + timedelta(days=1)
        req_body["till"] = KerberosTime.to_asn1(expiry)
        req_body["rtime"] = KerberosTime.to_asn1(expiry)
        req_body["nonce"] = random.getrandbits(31)

        seq_set_iter(req_body, "etype", (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        ))
        return encoder.encode(as_req)
