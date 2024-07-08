from json import loads
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652

from impacket.ldap import ldap as ldap_impacket
from impacket.krb5.kerberosv5 import KerberosError
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dpapi_ng import EncryptedPasswordBlob, KeyIdentifier, compute_kek, create_sd, decrypt_plaintext, unwrap_cek

from nxc.logger import NXCAdapter

ldap_error_status = {
    "1": "STATUS_NOT_SUPPORTED",
    "533": "STATUS_ACCOUNT_DISABLED",
    "701": "STATUS_ACCOUNT_EXPIRED",
    "531": "STATUS_ACCOUNT_RESTRICTION",
    "530": "STATUS_INVALID_LOGON_HOURS",
    "532": "STATUS_PASSWORD_EXPIRED",
    "773": "STATUS_PASSWORD_MUST_CHANGE",
    "775": "USER_ACCOUNT_LOCKED",
    "50": "LDAP_INSUFFICIENT_ACCESS",
    "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED",
}


class LDAPConnect:
    def __init__(self, host, port, hostname):
        self.logger = None
        self.proto_logger(host, port, hostname)

    def proto_logger(self, host, port, hostname):
        self.logger = NXCAdapter(extra={"protocol": "LDAP", "host": host, "port": port, "hostname": hostname})

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False, dns_server=""):
        lmhash = ""
        nthash = ""

        if kdcHost is None or domain not in kdcHost:
            self.logger.fail("Please provide the FQDN of the domain controller with --kdcHost")
            exit(1)

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash and ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        elif ntlm_hash:
            nthash = ntlm_hash

        # Create the baseDN
        baseDN = ""
        domainParts = domain.split(".")
        for i in domainParts:
            baseDN += f"DC={i},"
        # Remove last ','
        baseDN = baseDN[:-1]

        try:
            self.logger.info(f"Connecting to ldap://{kdcHost} - {baseDN} - {domain} [1]")
            ldap_connection = ldap_impacket.LDAPConnection(f"ldap://{kdcHost}", baseDN, dns_server if dns_server else domain)
            ldap_connection.kerberosLogin(
                username,
                password,
                domain,
                lmhash,
                nthash,
                aesKey,
                kdcHost=kdcHost,
                useCache=False,
            )
            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "389"
            return ldap_connection
        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    ldap_connection = ldap_impacket.LDAPConnection(f"ldaps://{kdcHost}", baseDN, dns_server if dns_server else domain)
                    ldap_connection.login(
                        username,
                        password,
                        domain,
                        lmhash,
                        nthash,
                        aesKey,
                        kdcHost=kdcHost,
                        useCache=False,
                    )
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    return ldap_connection
                except ldap_impacket.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if error_code in ldap_error_status else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if error_code in ldap_error_status else "red",
                )
            return False
        except OSError:
            self.logger.debug(f"{domain}\\{username}:{password if password else ntlm_hash} {'Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller'}")
            return False
        except KerberosError as e:
            self.logger.fail(f"{domain}\\{username}:{password if password else ntlm_hash} {e!s}", color="red")
            return False

    def auth_login(self, domain, username, password, ntlm_hash, dns_server):
        lmhash = ""
        nthash = ""

        # This checks to see if we didn't provide the LM Hash
        if ntlm_hash and ntlm_hash.find(":") != -1:
            lmhash, nthash = ntlm_hash.split(":")
        elif ntlm_hash:
            nthash = ntlm_hash

        # Create the baseDN
        base_dn = ""
        domain_parts = domain.split(".")
        for i in domain_parts:
            base_dn += f"dc={i},"
        # Remove last ','
        base_dn = base_dn[:-1]

        try:
            ldap_connection = ldap_impacket.LDAPConnection(f"ldap://{domain}", base_dn, dns_server if dns_server else domain)
            ldap_connection.login(username, password, domain, lmhash, nthash)

            # Connect to LDAP
            self.logger.extra["protocol"] = "LDAP"
            self.logger.extra["port"] = "389"

            return ldap_connection

        except ldap_impacket.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                # We need to try SSL
                try:
                    ldap_connection = ldap_impacket.LDAPConnection(f"ldaps://{domain}", base_dn, dns_server if dns_server else domain)
                    ldap_connection.login(username, password, domain, lmhash, nthash)
                    self.logger.extra["protocol"] = "LDAPS"
                    self.logger.extra["port"] = "636"
                    return ldap_connection
                except ldap_impacket.LDAPSessionError as e:
                    error_code = str(e).split()[-2][:-1]
                    self.logger.fail(
                        f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                        color="magenta" if error_code in ldap_error_status else "red",
                    )
            else:
                error_code = str(e).split()[-2][:-1]
                self.logger.fail(
                    f"{domain}\\{username}:{password if password else ntlm_hash} {ldap_error_status[error_code] if error_code in ldap_error_status else ''}",
                    color="magenta" if error_code in ldap_error_status else "red",
                )
            return False

        except OSError:
            self.logger.debug(f"{domain}\\{username}:{password if password else ntlm_hash} {'Error connecting to the domain, please add option --kdcHost with the FQDN of the domain controller'}")
            return False


class LAPSv2Extract:
    def __init__(self, data, username, password, domain, ntlm_hash, do_kerberos, kdcHost, port, dns_server):
        if ntlm_hash.find(":") != -1:
            self.lmhash, self.nthash = ntlm_hash.split(":")
        else:
            self.nthash = ntlm_hash
            self.lmhash = ""

        self.data = data
        self.username = username
        self.password = password
        self.domain = domain
        self.do_kerberos = do_kerberos
        self.kdcHost = kdcHost
        self.logger = None
        self.dns_server = dns_server
        self.proto_logger(self.domain, port, self.domain)

    def proto_logger(self, host, port, hostname):
        self.logger = NXCAdapter(extra={"protocol": "LDAP", "host": host, "port": port, "hostname": hostname})

    def run(self):
        kds_cache = {}
        self.logger.info("[-] Unpacking blob")
        try:
            encrypted_laps_blob = EncryptedPasswordBlob(self.data)
            parsed_cms_data, remaining = decoder.decode(encrypted_laps_blob["Blob"], asn1Spec=rfc5652.ContentInfo())
            enveloped_data_blob = parsed_cms_data["content"]
            parsed_enveloped_data, _ = decoder.decode(enveloped_data_blob, asn1Spec=rfc5652.EnvelopedData())

            recipient_infos = parsed_enveloped_data["recipientInfos"]
            kek_recipient_info = recipient_infos[0]["kekri"]
            kek_identifier = kek_recipient_info["kekid"]
            key_id = KeyIdentifier(bytes(kek_identifier["keyIdentifier"]))
            tmp, _ = decoder.decode(kek_identifier["other"]["keyAttr"])
            sid = tmp["field-1"][0][0][1].asOctets().decode("utf-8")
            target_sd = create_sd(sid)
        except Exception as e:
            self.logger.error(f"Cannot unpack msLAPS-EncryptedPassword blob due to error {e}")
            return None

        # Check if item is in cache
        if key_id["RootKeyId"] in kds_cache:
            self.logger.info("Got KDS from cache")
            gke = kds_cache[key_id["RootKeyId"]]
        else:
            # Connect on RPC over TCP to MS-GKDI to call opnum 0 GetKey
            string_binding = hept_map(destHost=self.domain if not self.dns_server else self.dns_server, remoteIf=MSRPC_UUID_GKDI, protocol="ncacn_ip_tcp")
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            if hasattr(rpc_transport, "set_credentials"):
                rpc_transport.set_credentials(username=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
            if self.do_kerberos:
                self.logger.info("Connecting using kerberos")
                rpc_transport.set_kerberos(self.do_kerberos, kdcHost=self.kdcHost)

            dce = rpc_transport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.logger.info(f"Connecting to {string_binding}")
            try:
                dce.connect()
            except Exception as e:
                self.logger.error(f"Something went wrong, check error status => {e}")
                return False
            self.logger.info("Connected")
            try:
                dce.bind(MSRPC_UUID_GKDI)
            except Exception as e:
                self.logger.error(f"Something went wrong, check error status => {e!s}")
                return False
            self.logger.info("Successfully bound")
            self.logger.info("Calling MS-GKDI GetKey")

            resp = GkdiGetKey(dce, target_sd=target_sd, l0=key_id["L0Index"], l1=key_id["L1Index"], l2=key_id["L2Index"], root_key_id=key_id["RootKeyId"])
            self.logger.info("Decrypting password")
            # Unpack GroupKeyEnvelope
            gke = GroupKeyEnvelope(b"".join(resp["pbbOut"]))
            kds_cache[gke["RootKeyId"]] = gke

        kek = compute_kek(gke, key_id)
        self.logger.info(f"KEK:\t{kek}")
        enc_content_parameter = bytes(parsed_enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
        iv, _ = decoder.decode(enc_content_parameter)
        iv = bytes(iv[0])

        cek = unwrap_cek(kek, bytes(kek_recipient_info["encryptedKey"]))
        self.logger.info(f"CEK:\t{cek}")
        plaintext = decrypt_plaintext(cek, iv, remaining)
        self.logger.info(plaintext[:-18].decode("utf-16le"))
        return plaintext[:-18].decode("utf-16le")


def laps_search(self, username, password, cred_type, domain, dns_server):
    prev_protocol = self.logger.extra["protocol"]
    prev_port = self.logger.extra["port"]
    self.logger.extra["protocol"] = "LDAP"
    self.logger.extra["port"] = "389"

    ldapco = LDAPConnect(self.domain, "389", self.domain)

    if self.kerberos:
        if self.kdcHost is None:
            self.logger.fail("Add --kdcHost parameter to use laps with kerberos")
            return None, None, None

        connection = ldapco.kerberos_login(
            domain[0],
            username[0] if username else "",
            password[0] if cred_type[0] == "plaintext" else "",
            password[0] if cred_type[0] == "hash" else "",
            kdcHost=self.kdcHost,
            aesKey=self.aesKey,
            dns_server=dns_server
        )
    else:
        connection = ldapco.auth_login(
            domain[0],
            username[0] if username else "",
            password[0] if cred_type[0] == "plaintext" else "",
            password[0] if cred_type[0] == "hash" else "",
            dns_server
        )
    if not connection:
        self.logger.fail(f"LDAP connection failed with account {username[0]}")

        return None, None, None

    search_filter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=" + self.hostname + "))"
    attributes = [
        "msLAPS-EncryptedPassword",
        "msLAPS-Password",
        "ms-MCS-AdmPwd",
        "sAMAccountName",
    ]
    results = connection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)

    msMCSAdmPwd = ""
    sAMAccountName = ""
    username_laps = ""

    from impacket.ldap import ldapasn1 as ldapasn1_impacket

    results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
    if len(results) != 0:
        for host in results:
            values = {str(attr["type"]).lower(): attr["vals"][0] for attr in host["attributes"]}
            if "mslaps-encryptedpassword" in values:
                msMCSAdmPwd = values["mslaps-encryptedpassword"]
                d = LAPSv2Extract(
                    bytes(msMCSAdmPwd),
                    username[0] if username else "",
                    password[0] if cred_type[0] == "plaintext" else "",
                    domain[0],
                    password[0] if cred_type[0] == "hash" else "",
                    self.kerberos,
                    self.kdcHost,
                    339,
                    dns_server
                )
                try:
                    data = d.run()
                except Exception as e:
                    self.logger.fail(str(e))
                    return None, None, None
                r = loads(data)
                msMCSAdmPwd = r["p"]
                username_laps = r["n"]
            elif "mslaps-password" in values:
                r = loads(str(values["mslaps-password"]))
                msMCSAdmPwd = r["p"]
                username_laps = r["n"]
            elif "ms-mcs-admpwd" in values:
                msMCSAdmPwd = str(values["ms-mcs-admpwd"])
            else:
                self.logger.fail("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password")
        self.logger.debug(f"Host: {sAMAccountName:<20} Password: {msMCSAdmPwd} {self.hostname}")
    else:
        self.logger.fail(f"msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS property for {self.hostname}")
        return None, None, None

    if msMCSAdmPwd == "":
        self.logger.fail(f"msMCSAdmPwd or msLAPS-Password is empty or account cannot read LAPS property for {self.hostname}")
        return None, None, None

    username = username_laps if username_laps else self.args.laps
    password = msMCSAdmPwd
    domain = self.hostname
    self.args.local_auth = True
    self.args.kerberos = False
    self.logger.extra["protocol"] = prev_protocol
    self.logger.extra["port"] = prev_port
    return username, password, domain
