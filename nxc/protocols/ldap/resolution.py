from re import sub, I
from errno import EHOSTUNREACH, ETIMEDOUT, ENETUNREACH
from OpenSSL.SSL import SysCallError

from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket

from nxc.parsers.ldap_results import parse_result_attributes
from nxc.logger import nxc_logger


class LDAPResolution:

    def __init__(self, host):
        self.host = host

    def get_resolution(self):
        target = ""
        target_domain = ""
        base_dn = ""
        try:
            ldap_url = f"ldap://{self.host}"
            nxc_logger.info(f"Connecting to {ldap_url} with no baseDN")
            try:
                self.ldap_connection = ldap_impacket.LDAPConnection(ldap_url, dstIp=self.host)
                if self.ldap_connection:
                    nxc_logger.debug(f"ldap_connection: {self.ldap_connection}")
            except SysCallError as e:
                nxc_logger.fail(f"LDAP connection to {ldap_url} failed: {e}")
                return False

            resp = self.ldap_connection.search(
                scope=ldapasn1_impacket.Scope("baseObject"),
                attributes=["defaultNamingContext", "dnsHostName"],
                sizeLimit=0,
            )
            resp_parsed = parse_result_attributes(resp)[0]

            target = resp_parsed["dnsHostName"]
            base_dn = resp_parsed["defaultNamingContext"]
            target_domain = sub(
                r",DC=",
                ".",
                base_dn[base_dn.lower().find("dc="):],
                flags=I,
            )[3:]
            # Extract machine name from target (hostname part of FQDN)
            if target:
                machine_name = target.split(".")[0]
                nxc_logger.debug(f"Extracted machine name: {machine_name}")

            self.ldap_connection.close()
        except ConnectionRefusedError as e:
            nxc_logger.debug(f"{e} on host {self.host}")
            return False
        except OSError as e:
            if e.errno in (EHOSTUNREACH, ENETUNREACH, ETIMEDOUT):
                nxc_logger.info(f"Error connecting to {self.host} - {e}")
                return False
            else:
                nxc_logger.error(f"Error getting ldap info {e}")

        nxc_logger.debug(f"Target: {machine_name}.{target_domain}; target_domain: {target_domain}; base_dn: {base_dn}")
        return machine_name, target_domain