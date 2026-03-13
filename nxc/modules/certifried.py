import builtins
import copy
import io
import os
import socket
import tempfile
from contextlib import redirect_stderr, redirect_stdout

from certipy.commands.find import Find
from certipy.commands.req import Request
from certipy.lib.certificate import get_identities_from_certificate, get_object_sid_from_certificate_sid_extension, load_pfx
from certipy.lib.ldap import LDAPConnection
from certipy.lib.target import DnsResolver, Target
from impacket.dcerpc.v5.samr import SAM_MACHINE_ACCOUNT

from nxc.helpers.misc import CATEGORY


class Probe:
    def __init__(self, template_name, identities, object_sid, cert, key):
        self.template_name = template_name
        self.identities = identities
        self.object_sid = object_sid
        self.cert = cert
        self.key = key
        self.schannel_identity = None
        self.schannel_error = None


class NXCModule:
    name = "certifried"
    description = "Passive Certifried (CVE-2022-26923) checker"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.ca_name = None
        self.passive_template = None
        self.timeout = 5

    def options(self, context, module_options):
        """
        CA                OPTIONAL: Restrict checks to a specific CA name
        PASSIVE_TEMPLATE  OPTIONAL: Force a specific template for the CA/DC probe
        TIMEOUT           OPTIONAL: Timeout in seconds for Certipy operations (default: 5)
        """
        self.ca_name = module_options.get("CA")
        self.passive_template = module_options.get("PASSIVE_TEMPLATE")
        self.timeout = 5

        if "TIMEOUT" in module_options:
            try:
                self.timeout = int(module_options["TIMEOUT"])
            except ValueError:
                context.log.fail("TIMEOUT must be an integer")
                self.timeout = 5

    def on_login(self, context, connection):
        target = self._build_target(connection)
        cert_connection = LDAPConnection(target)

        try:
            cert_connection.connect()
        except Exception as exc:
            context.log.fail(f"Failed to establish Certipy LDAP context: {exc}")
            return

        finder = Find(target=target, connection=cert_connection)

        try:
            templates = finder.get_certificate_templates()
            cas = finder.get_certificate_authorities()
            finder._link_cas_and_templates(cas, templates)
            finder._process_ca_properties(cas)
            finder._process_template_properties(templates)
        except Exception as exc:
            context.log.fail(f"Failed to enumerate AD CS: {exc}")
            return

        if self.ca_name is not None:
            cas = [ca for ca in cas if ca.get("name", "").lower() == self.ca_name.lower()]
            if not cas:
                context.log.fail(f"CA {self.ca_name!r} was not found")
                return

        if not cas:
            context.log.fail("No Enterprise CAs found")
            return

        principal_entry = cert_connection.get_user(
            connection.username,
            silent=True,
            attributes=["dNSHostName", "objectClass", "sAMAccountType"],
        )
        is_computer_account = False
        computer_dns_host_name = None

        if principal_entry is not None:
            is_computer_account = self._is_computer_account(principal_entry)
            if is_computer_account:
                computer_dns_host_name = self._get_attribute_value(principal_entry, "dNSHostName")

        for ca in cas:
            self._evaluate_ca(context, connection, target, finder, ca, templates, is_computer_account, computer_dns_host_name)

    def _evaluate_ca(self, context, connection, target, finder, ca, templates, is_computer_account, computer_dns_host_name):
        ca_name = ca.get("name")
        ca_templates = [template for template in templates if ca_name in (template.get("cas") or [])]

        current_user_candidates = self._probe_templates(finder, ca_templates, is_computer_account)
        selected_template = current_user_candidates[0].get("name") if current_user_candidates else None

        passive_probe = self._request_probe_certificate(target, ca, current_user_candidates)

        if passive_probe is None:
            if is_computer_account and selected_template == "Machine" and not computer_dns_host_name:
                context.log.display("Machine cert probe failed, machine account has no dNSHostName")
                return
            context.log.display("Cert probe: failed")
            return

        identity_summary = self._format_identities(passive_probe.identities)
        sid_state = "present" if passive_probe.object_sid else "absent"
        context.log.display(f"Cert probe: template {passive_probe.template_name!r}, SID extension {sid_state}, identities [{identity_summary}]")

        # A SID-bearing cert is already a CA-side hardening signal so Schannel adds nothing here
        if passive_probe.object_sid is None:
            schannel_probe = self._probe_schannel(connection, passive_probe)
            passive_probe.schannel_identity = schannel_probe[0]
            passive_probe.schannel_error = schannel_probe[1]

            if passive_probe.schannel_identity:
                context.log.display(f"Schannel: accepted as {passive_probe.schannel_identity}")
            else:
                context.log.display(f"Schannel: rejected ({passive_probe.schannel_error})")
        else:
            context.log.display("Schannel: skipped")

        self._log_conclusion(context, passive_probe)

    def _log_conclusion(self, context, passive_probe):
        if passive_probe.object_sid is not None:
            context.log.display("CA-side hardening present: issued cert includes the SID extension")
            return

        if passive_probe.schannel_identity:
            context.log.highlight("Possible vulnerable to Certifried, SID-less user cert accepted over Schannel")
            context.log.display("Reference: https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4")
            return

        context.log.display("SID-less cert was rejected over Schannel")

    def _build_target(self, connection):
        dns_server = connection.args.dns_server
        if not dns_server:
            try:
                socket.inet_aton(connection.host)
                dns_server = connection.host
            except OSError:
                dns_server = None

        resolver = DnsResolver.create(dns_server)
        hashes = None
        if connection.nthash:
            hashes = connection.nthash if not connection.lmhash else f"{connection.lmhash}:{connection.nthash}"

        return Target(
            resolver=resolver,
            domain=connection.domain,
            username=connection.username,
            password=connection.password or None,
            remote_name=connection.remoteName,
            hashes=hashes,
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            do_kerberos=connection.kerberos,
            aes=connection.aesKey,
            dc_ip=connection.host,
            dc_host=connection.remoteName,
            target_ip=connection.host,
            timeout=self.timeout,
            ldap_port=connection.port,
            ldap_scheme="ldaps" if connection.port == 636 else "ldap",
            ldap_signing=bool(connection.signing_required),
            ldap_channel_binding=connection.cbt_status in ["Always", "When Supported"],
        )

    def _probe_templates(self, finder, templates, is_computer_account):
        current_user_templates = []

        for template in templates:
            user_can_enroll, _ = finder.can_user_enroll_in_template(template)
            if not user_can_enroll:
                continue

            if not template.get("client_authentication"):
                continue

            if template.get("requires_manager_approval"):
                continue

            if template.get("authorized_signatures_required", 0):
                continue

            current_user_templates.append(template)

        if self.passive_template:
            return [template for template in current_user_templates if template.get("name", "").lower() == self.passive_template.lower()]

        if is_computer_account:
            preferred_order = {
                "Machine": 0,
                "User": 1,
            }
            return sorted(
                current_user_templates,
                key=lambda template: (preferred_order.get(template.get("name"), 99), template.get("name", "")),
            )

        # Fall back to the default User template order when Machine is not available
        return sorted(
            current_user_templates,
            key=lambda template: (template.get("name") != "User", template.get("name", "")),
        )

    def _request_probe_certificate(self, target, ca, template_candidates):
        ca_host = ca.get("dNSHostName")
        try:
            ca_ip = target.resolver.resolve(ca_host)
        except Exception:
            return None

        for template in template_candidates:
            probe = self._request_certificate(target, ca.get("name"), ca_host, ca_ip, template.get("name"))
            if probe is not None:
                return probe

        return None

    def _request_certificate(self, target, ca_name, ca_host, ca_ip, template_name):
        probe_target = copy.copy(target)
        probe_target.remote_name = ca_host
        probe_target.target_ip = ca_ip

        # Certipy writes the request output to disk so keep probe artifacts in a temp dir
        with tempfile.TemporaryDirectory(prefix="nxc-certifried-") as temp_dir:
            requester = Request(target=probe_target, ca=ca_name, template=template_name, out="probe")
            cwd = os.getcwd()
            old_input = builtins.input
            try:
                os.chdir(temp_dir)
                builtins.input = lambda *args, **kwargs: "n"
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = requester.request()
            except Exception:
                return None
            finally:
                builtins.input = old_input
                os.chdir(cwd)

            if not result:
                return None

            pfx_data, _ = result
            key, cert = load_pfx(pfx_data)
            if key is None or cert is None:
                return None

            return Probe(
                template_name,
                get_identities_from_certificate(cert),
                get_object_sid_from_certificate_sid_extension(cert),
                cert,
                key,
            )

    def _probe_schannel(self, connection, probe):
        if connection.cbt_status == "No TLS cert":
            return (None, "LDAPS is not configured on the DC")

        schannel_target = copy.copy(self._build_target(connection))
        schannel_target.remote_name = connection.remoteName
        schannel_target.target_ip = connection.host
        schannel_target.username = ""
        schannel_target.password = None
        schannel_target.lmhash = ""
        schannel_target.nthash = ""
        schannel_target.hashes = None
        schannel_target.do_kerberos = False
        schannel_target.ldap_scheme = "ldaps"
        schannel_target.ldap_port = 636
        schannel_target.ldap_channel_binding = False
        schannel_target.ldap_signing = False

        try:
            schannel_connection = LDAPConnection(schannel_target, (probe.cert, probe.key))
            schannel_connection.schannel_connect()
            return (
                schannel_connection.ldap_conn.extend.standard.who_am_i(),
                None,
            )
        except Exception as exc:
            return (None, str(exc))

    def _format_identities(self, identities):
        if not identities:
            return "none"

        return ", ".join(f"{id_type}={value}" for id_type, value in identities)

    def _get_attribute_value(self, entry, attribute):
        value = entry.get(attribute)
        if isinstance(value, list):
            return value[0] if value else None
        return value or None

    def _is_computer_account(self, entry):
        object_classes = entry.get("objectClass", [])
        if isinstance(object_classes, str):
            object_classes = [object_classes]

        if "computer" in [object_class.lower() for object_class in object_classes]:
            return True

        sam_account_type = self._get_attribute_value(entry, "sAMAccountType")
        try:
            return int(sam_account_type) == SAM_MACHINE_ACCOUNT
        except (TypeError, ValueError):
            return False