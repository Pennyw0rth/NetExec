import socket
import ssl
import asyncio
import hashlib
import random

from msldap.connection import MSLDAPClientConnection
from msldap.commons.target import MSLDAPTarget

from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential

from asysocks.unicomm.common.target import UniTarget, UniProto
import contextlib


class NXCModule:
    """
    Checks whether LDAP signing and LDAPS channel binding are required and/or enforced.

    Module by LuemmelSec (@theluemmel), updated by @zblurx/@Mercury0
    Original work thankfully taken from @zyn3rgy's Ldap Relay Scan project: https://github.com/zyn3rgy/LdapRelayScan
    """
    name = "ldap-checker"
    description = "[REMOVED] Checks whether LDAP signing and channel binding are required and / or enforced"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No options available."""

    # Conduct a bind to LDAPS and determine if channel
    # binding is enforced based on the contents of potential
    # errors returned. This can be determined unauthenticated,
    # because the error indicating channel binding enforcement
    # will be returned regardless of a successful LDAPS bind.
    async def run_ldaps_noEPA(self, context, connection, target, credential):
        try:
            client = MSLDAPClientConnection(target, credential)
            _, err = await client.connect()
            if err:
                context.log.debug(f"Error connecting to {connection.domain}: {err}")
                return None

            client.cb_data = None
            _, err = await client.bind()
            if err and "data 80090346" in str(err):
                return True  # -> channel binding IS enforced
            elif err and "data 52e" in str(err):
                return False  # -> channel binding not enforced
            elif err is None:
                return False  # LDAPS bind successful -> channel binding not enforced
            else:
                context.log.debug(f"Unexpected error during LDAPS bind (noEPA): {err}")
                return None
        except Exception as e:
            context.log.debug(f"Exception in run_ldaps_noEPA: {e}")
            return None
        finally:
            with contextlib.suppress(Exception):
                await client.disconnect()

    # Conduct a bind to LDAPS with channel binding supported
    # but intentionally miscalculated. In the case that an
    # LDAPS bind without channel binding supported has occurred,
    # you can determine whether the policy is set to "never" or
    # if it's set to "when supported" based on the potential
    # error received from the bind attempt.
    async def run_ldaps_withEPA(self, context, connection, target, credential):
        try:
            client = MSLDAPClientConnection(target, credential)
            _, err = await client.connect()
            if err:
                context.log.fail(f"Error connecting to {connection.domain}: {err}")
                return None

            try:
                context.log.debug("Retrieving TLS certificate hash...")
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((connection.host, 636)) as sock, ssl_context.wrap_socket(sock, server_hostname=connection.host) as ssl_sock:
                    cert = ssl_sock.getpeercert(binary_form=True)
                
                if cert:
                    cert_hash = hashlib.sha256(cert).digest()
                    context.log.debug(f"Original certificate hash: {cert_hash.hex()}")
                    pos = random.randint(0, len(cert_hash) - 1)
                    tampered_bytes = bytearray(cert_hash)
                    tampered_bytes[pos] = (tampered_bytes[pos] + 1) % 256
                    context.log.debug(f"Tampered certificate hash: {bytes(tampered_bytes).hex()}")
                    context.log.debug(f"Modified byte at position {pos}")
                    client.cb_data = b"tls-server-end-point:" + bytes(tampered_bytes)
                else:
                    client.cb_data = b"\x00" * 64
            except Exception as e:
                context.log.debug(f"Failed to retrieve TLS certificate hash: {e}")
                client.cb_data = b"\x00" * 64

            _, err = await client.bind()
            if err and "data 80090346" in str(err):
                return True
            elif (err and "data 52e" in str(err)) or err is None:
                return False
            else:
                context.log.fail(f"Unexpected error during LDAPS bind (withEPA): {err}")
                return None
        except Exception as e:
            context.log.fail(f"Exception in run_ldaps_withEPA: {e}")
            return None
            
    # Domain Controllers do not have a certificate setup for
    # LDAPS on port 636 by default. If this has not been setup,
    # the TLS handshake will hang and you will not be able to
    # interact with LDAPS. The condition for the certificate
    # existing as it should is either an error regarding
    # the fact that the certificate is self-signed, or
    # no error at all. Any other "successful" edge cases
    # not yet accounted for.
    def does_ldaps_complete_handshake(self, context, dc_ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_sock = ssl_context.wrap_socket(s, do_handshake_on_connect=False, suppress_ragged_eofs=False)
        try:
            ssl_sock.connect((dc_ip, 636))
            ssl_sock.do_handshake()
            return True
        except Exception as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                return True
            elif "handshake operation timed out" in str(e):
                return False
            else:
                context.log.fail(f"Unexpected error during LDAPS handshake: {e}")
                return False
        finally:
            ssl_sock.close()
    
    # Conduct an LDAP bind and determine if server signing
    # requirements are enforced based on potential errors
    # during the bind attempt.
    async def run_ldap(self, context, target, credential):
        try:
            client = MSLDAPClientConnection(target, credential)
            client._disable_signing = True  # deliberately disable LDAP signing on client connection
            _, err = await client.connect()
            if err:
                context.log.fail(f"Error connecting for LDAP bind: {err}")
                return None

            _, err = await client.bind()
            if err:
                errstr = str(err).lower()
                if "stronger" in errstr:
                    return True
                    # because LDAP server signing requirements ARE enforced
                else:
                    context.log.fail(f"LDAP bind error: {err}")
                    return None
            else:
                # LDAPS bind successful
                return False
                # because LDAP server signing requirements are not enforced
        except Exception as e:
            context.log.debug(f"Exception during LDAP bind: {e}")
            return None
    
    # Determine authentication context and proceed to
    # enumerate LDAP signing and channel binding settings    
    def on_login(self, context, connection):
        context.log.fail("[REMOVED] Now natively supported in the host banner")
        return
        stype = asyauthSecret.PASS
        secret = connection.password
        if connection.nthash:
            stype = asyauthSecret.NT
            secret = connection.nthash
        if connection.aesKey:
            stype = asyauthSecret.AES
            secret = connection.aesKey

        anon_credential = NTLMCredential(
            secret="",
            username="",
            domain=connection.domain,
            stype=asyauthSecret.PASS
        )

        if not connection.username and not secret:
            context.log.highlight("No credentials provided, skipping LDAP signing check")
            credential = anon_credential
        else:
            if not connection.kerberos:
                credential = NTLMCredential(
                    secret=secret,
                    username=connection.username,
                    domain=connection.domain,
                    stype=stype
                )
            else:
                kerberos_target = UniTarget(
                    connection.host,
                    88,
                    UniProto.CLIENT_TCP,
                    hostname=connection.remoteName,
                    dc_ip=connection.kdcHost,
                    domain=connection.domain,
                    proxies=None,
                    dns=None,
                )
                credential = KerberosCredential(
                    target=kerberos_target,
                    secret=secret,
                    username=connection.username,
                    domain=connection.domain,
                    stype=stype,
                )

        ldap_signing_status = None
        if connection.username or secret:
            target = MSLDAPTarget(
                connection.host, 389,
                hostname=connection.remoteName,
                domain=connection.domain,
                dc_ip=connection.kdcHost,
            )
            ldap_signing_status = asyncio.run(self.run_ldap(context, target, credential))
            if ldap_signing_status is True:
                context.log.highlight("LDAP signing IS enforced")
            elif ldap_signing_status is False:
                context.log.highlight("LDAP signing NOT enforced")
            else:
                context.log.fail("Could not determine LDAP signing requirement.")

        if self.does_ldaps_complete_handshake(context, connection.host):
            target = MSLDAPTarget(
                connection.host, 636,
                UniProto.CLIENT_SSL_TCP,
                hostname=connection.remoteName,
                domain=connection.domain,
                dc_ip=connection.kdcHost,
            )
            ldaps_noEPA = asyncio.run(self.run_ldaps_noEPA(context, connection, target, anon_credential))
            ldaps_withEPA = asyncio.run(self.run_ldaps_withEPA(context, connection, target, anon_credential))

            if ldaps_noEPA is False and ldaps_withEPA is True:
                context.log.highlight("LDAPS channel binding is set to: When Supported")
            elif ldaps_noEPA is False and ldaps_withEPA is False:
                context.log.highlight("LDAPS channel binding is set to: Never")
            elif ldaps_noEPA is True:
                context.log.highlight("LDAPS channel binding is set to: Required")
            else:
                context.log.fail("Could not determine LDAPS channel binding settings")
        else:
            context.log.fail(f"{connection.domain} - TLS handshake failed; certificate likely not configured")