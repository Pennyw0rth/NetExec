from impacket.ldap import ldapasn1
from impacket.ldap.ldap import escape_filter_chars

from pyasn1.codec.ber import encoder
from pyasn1.type import namedtype, univ

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

# Credits to SpecterOps: https://specterops.io/blog/2023/01/25/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc/

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
    "msDS-RevealedList",
]
principal_attributes = ["sAMAccountName", "distinguishedName"]
all_principals_filter = "(&(objectClass=user)(sAMAccountName=*))"
cacheability_attribute = "msDS-IsUserCachableAtRodc"
cacheability_attributes = ["distinguishedName", cacheability_attribute]
dn_input_control_oid = "1.2.840.113556.1.4.2026"
cached_account_batch_size = 50
policy_fields = (
    ("msDS-RevealOnDemandGroup", "Direct allow policy references", "Allowed"),
    ("msDS-NeverRevealGroup", "Direct deny policy references", "Denied"),
)


class DnInputRequestValue(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType("InputDN", univ.OctetString()))


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


def _revealed_principals(values):
    principals = {}
    for value in values:
        parts = str(value).split(":", 3)
        principal = parts[3] if len(parts) == 4 and parts[0] == "S" else str(value)
        principals.setdefault(_normalize_dn(principal), principal)
    return list(principals.values())


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
    description = "Audit RODC password replication policy and cache state"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        RODC    Filter by RODC account name, short hostname, or FQDN
        TARGET  Check sAMAccountName, or use ALL to check every domain account

        Use --verbose flag to show policy and cached-account DNs.
        """
        self.option_error = None
        self.rodc = self._option(module_options, "RODC")
        self.target = self._option(module_options, "TARGET")
        self.all_targets = self.target is not None and self.target.casefold() == "all"

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

        response = connection.search(searchFilter=rodc_filter, attributes=rodc_attributes)
        rodcs = parse_result_attributes(response or [])
        if self.rodc:
            rodcs = [rodc for rodc in rodcs if self._matches_rodc(rodc, self.rodc)]

        if not rodcs:
            qualifier = f" matching {self.rodc}" if self.rodc else ""
            context.log.fail(f"No RODCs found{qualifier}")
            return

        cached_accounts = None
        if self.all_targets:
            targets = self._resolve_all_targets(connection)
        elif self.target:
            target = self._resolve_target(context, connection)
            if target is None:
                return
            targets = [target]
        else:
            cached_principals = self._cached_principals(rodcs)
            cached_accounts = self._resolve_cached_accounts(
                connection, cached_principals.values()
            )
            targets = self._cached_targets(cached_principals, cached_accounts)

        if self.all_targets and len(rodcs) == 1:
            self._stream_all_targets(
                context,
                connection,
                rodcs[0],
                targets,
            )
            return

        cacheability = self._query_cacheability(connection, targets)

        for rodc in rodcs:
            show_identity = len(rodcs) > 1 or not self._matches_rodc(
                rodc, connection.hostname
            )
            self._report_rodc(
                context,
                rodc,
                targets,
                cacheability,
                cached_accounts,
                show_identity,
            )

    def _resolve_target(self, context, connection):
        search_filter = f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.target)}))"
        response = connection.search(searchFilter=search_filter, attributes=principal_attributes)
        targets = parse_result_attributes(response or [])
        if len(targets) != 1:
            context.log.fail(f"Target {self.target} was not returned exactly once ({len(targets)} matches)")
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

    def _query_cacheability(self, connection, targets):
        results = {}
        for target in targets:
            results.update(self._query_target_cacheability(connection, target))
        return results

    @staticmethod
    def _query_target_cacheability(connection, target):
        target_dn = target["distinguishedName"]
        response = connection.search(
            searchFilter=rodc_filter,
            attributes=cacheability_attributes,
            searchControls=[_dn_input_control(target_dn)],
        )
        results = {}
        for entry in parse_result_attributes(response or []):
            rodc_dn = entry.get("distinguishedName")
            if rodc_dn:
                key = (_normalize_dn(target_dn), _normalize_dn(rodc_dn))
                results[key] = entry.get(cacheability_attribute)
        return results

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

    @staticmethod
    def _cached_principals(rodcs):
        principals = {}
        for rodc in rodcs:
            for distinguished_name in _revealed_principals(_as_list(rodc.get("msDS-RevealedList"))):
                principals.setdefault(_normalize_dn(distinguished_name), distinguished_name)
        return principals

    @staticmethod
    def _resolve_cached_accounts(connection, principal_dns):
        accounts = {}
        distinguished_names = list(principal_dns)
        for index in range(0, len(distinguished_names), cached_account_batch_size):
            batch = distinguished_names[index:index + cached_account_batch_size]
            clauses = "".join(
                f"(distinguishedName={escape_filter_chars(distinguished_name)})"
                for distinguished_name in batch
            )
            response = connection.search(
                searchFilter=f"(|{clauses})",
                attributes=principal_attributes,
            )
            for entry in parse_result_attributes(response or []):
                distinguished_name = entry.get("distinguishedName")
                account_name = entry.get("sAMAccountName")
                if distinguished_name and account_name:
                    accounts[_normalize_dn(distinguished_name)] = str(account_name)
        return accounts

    @staticmethod
    def _cached_targets(principals, cached_accounts):
        return [
            {
                "sAMAccountName": cached_accounts.get(
                    normalized_dn,
                    f"{_rdn_value(distinguished_name)} (unresolved)",
                ),
                "distinguishedName": distinguished_name,
            }
            for normalized_dn, distinguished_name in principals.items()
        ]

    def _report_rodc(self, context, rodc, targets, cacheability, cached_accounts, show_identity):
        principals = self._report_rodc_overview(
            context,
            rodc,
            cached_accounts,
            show_identity,
        )
        if principals is None:
            return

        if self.all_targets:
            self._report_all_targets(context, rodc, targets, cacheability, principals)
        elif self.target:
            target = targets[0]
            cached_dns = {_normalize_dn(principal) for principal in principals}
            cache_state = _normalize_dn(target["distinguishedName"]) in cached_dns
            result = self._cacheability_result(cacheability, target, rodc)
            self._report_target(context, target, result, cache_state)
        else:
            self._report_cacheable_accounts(context, rodc, targets, cacheability)

    def _stream_all_targets(self, context, connection, rodc, targets):
        show_identity = not self._matches_rodc(rodc, connection.hostname)
        principals = self._report_rodc_overview(context, rodc, None, show_identity)
        if principals is None:
            return

        cached_dns = {_normalize_dn(principal) for principal in principals}
        unavailable = 0
        for target in targets:
            target_cacheability = self._query_target_cacheability(connection, target)
            if not self._report_all_target(
                context,
                rodc,
                target,
                target_cacheability,
                cached_dns,
            ):
                unavailable += 1
        self._report_unavailable(context, len(targets), unavailable, "account")

    def _report_rodc_overview(self, context, rodc, cached_accounts, show_identity):
        account_name = rodc.get("sAMAccountName")
        hostname = rodc.get("dNSHostName")
        distinguished_name = rodc.get("distinguishedName")
        identity = account_name or hostname or distinguished_name
        if not identity:
            context.log.fail("RODC result did not include an identity")
            return None

        if show_identity:
            label = f"{account_name} ({hostname})" if account_name and hostname else identity
            context.log.highlight(f"RODC: {label}")
        if distinguished_name:
            context.log.info(f"RODC DN: {distinguished_name}")

        self._report_krbtgt(context, rodc)
        for attribute, summary_label, detail_label in policy_fields:
            self._report_attribute(context, rodc, attribute, summary_label, detail_label)
        metadata = _as_list(rodc.get("msDS-RevealedList"))
        principals = _revealed_principals(metadata)
        if cached_accounts is not None:
            self._report_cached_accounts(context, principals, cached_accounts)
        return principals

    def _report_all_targets(self, context, rodc, targets, cacheability, principals):
        cached_dns = {_normalize_dn(principal) for principal in principals}
        unavailable = 0
        for target in targets:
            if not self._report_all_target(
                context,
                rodc,
                target,
                cacheability,
                cached_dns,
            ):
                unavailable += 1

        self._report_unavailable(context, len(targets), unavailable, "account")

    def _report_all_target(
        self,
        context,
        rodc,
        target,
        cacheability,
        cached_dns,
    ):
        result = self._cacheability_result(cacheability, target, rodc)
        if result is None:
            return False

        cache_state = _normalize_dn(target["distinguishedName"]) in cached_dns
        if _is_cacheable(result) or cache_state:
            self._report_target(context, target, result, cache_state)
        return True

    @staticmethod
    def _report_krbtgt(context, rodc):
        links = _as_list(rodc.get("msDS-KrbTgtLink"))
        if len(links) != 1:
            context.log.fail("RODC krbtgt: unavailable")
            return

        context.log.highlight(f"RODC krbtgt account: {_rdn_value(links[0])}")
        context.log.info(f"RODC krbtgt DN: {links[0]}")

    @staticmethod
    def _report_attribute(context, rodc, attribute, summary_label, detail_label):
        values = _as_list(rodc.get(attribute))
        context.log.highlight(f"{summary_label}: {len(values)}")
        for value in values:
            context.log.info(f"{detail_label}: {value}")

    @staticmethod
    def _report_cached_accounts(context, principals, cached_accounts):
        if not principals:
            context.log.highlight("Cached accounts: none")
            return

        context.log.highlight("Cached accounts:")
        for principal in principals:
            account_name = cached_accounts.get(_normalize_dn(principal))
            label = account_name or f"{_rdn_value(principal)} (unresolved)"
            context.log.highlight(f"  {label}")
            context.log.info(f"Cached account DN ({label}): {principal}")

    def _report_cacheable_accounts(self, context, rodc, targets, cacheability):
        cacheable = []
        unavailable = 0
        for target in targets:
            result = self._cacheability_result(cacheability, target, rodc)
            if result is None:
                unavailable += 1
            elif _is_cacheable(result):
                cacheable.append(target)

        if self._report_unavailable(
            context, len(targets), unavailable, "cached account"
        ):
            return
        if not cacheable:
            context.log.highlight("Cacheable accounts: none")
            return

        context.log.highlight("Cacheable accounts:")
        for target in cacheable:
            label = target.get("sAMAccountName", "<unknown>")
            context.log.highlight(f"  {label}")
            target_dn = target.get("distinguishedName")
            if target_dn:
                context.log.info(f"Cacheable account DN ({label}): {target_dn}")

    @staticmethod
    def _cacheability_result(cacheability, target, rodc):
        target_dn = target.get("distinguishedName")
        rodc_dn = rodc.get("distinguishedName")
        if not target_dn or not rodc_dn:
            return None
        return cacheability.get((_normalize_dn(target_dn), _normalize_dn(rodc_dn)))

    @staticmethod
    def _report_unavailable(context, target_count, unavailable, subject):
        if target_count and unavailable == target_count:
            context.log.fail("PRP status unavailable")
            context.log.fail("Query the RODC directly or check permissions")
            return True

        if unavailable:
            subject_label = subject if unavailable == 1 else f"{subject}s"
            context.log.info(
                f"PRP status unavailable for {unavailable} {subject_label}; "
                "query the RODC directly or check permissions"
            )
        return False

    @staticmethod
    def _report_target(context, target, result, cache_state):
        target_name = target.get("sAMAccountName", "<unknown>")
        if result is None:
            context.log.fail(f"{target_name}: PRP status unavailable")
            context.log.fail("Query the RODC directly or check permissions")
        elif _is_cacheable(result):
            state = "cached" if cache_state else "cacheable"
            context.log.success(f"{target_name}: {state}")
        elif cache_state:
            context.log.fail(f"{target_name}: cached (PRP mismatch)")
        else:
            context.log.fail(f"{target_name}: not cacheable")
