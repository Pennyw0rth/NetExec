import json

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Find orphaned constrained-delegation SPNs.

    Module by @wyndoo
    """

    name = "orphan-spns"
    description = "Find orphaned constrained-delegation targets (SPNs not registered to any account)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        STRICT    Also flag targets where the exact SPN is unregistered even if the host computer exists (default: False)
        OUTPUT    Write the orphaned delegation SPNs to a JSON file

        Examples
        --------
        netexec ldap $DC-IP -u $username -p $password -M orphan-spns
        netexec ldap $DC-IP -u $username -p $password -M orphan-spns -o STRICT=true
        netexec ldap $DC-IP -u $username -p $password -M orphan-spns -o OUTPUT=/tmp/orphan_spns.json
        """
        self.strict = False
        self.output_file = None

        if "STRICT" in module_options and module_options["STRICT"].lower() in ("true", "1", "yes"):
            self.strict = True
        if "OUTPUT" in module_options:
            self.output_file = module_options["OUTPUT"]

    @staticmethod
    def ci_get(attrs, name):
        """Case-insensitive lookup of an LDAP attribute in a parsed result dict."""
        if name in attrs:
            return attrs[name]
        low = name.lower()
        for key, val in attrs.items():
            if key.lower() == low:
                return val
        return None

    @staticmethod
    def ldap_escape(value):
        """Escape RFC 4515 special characters so a value is safe inside a search filter."""
        for char, repl in (("\\", r"\5c"), ("*", r"\2a"), ("(", r"\28"), (")", r"\29"), ("\x00", r"\00")):
            value = value.replace(char, repl)
        return value

    @staticmethod
    def spn_host(spn):
        """Extract the lowercased host component from an SPN (service/host[:port][/name])."""
        parts = spn.split("/", 2)
        if len(parts) < 2:
            return None
        host = parts[1].split(":", 1)[0].strip().lower()
        return host or None

    def target_status(self, connection, spn):
        """Return (spn_registered, host_exists) for a delegation target SPN."""
        # Delegation target exists if some account still holds this exact SPN (computer or service account)
        resp = connection.search(
            searchFilter=f"(servicePrincipalName={self.ldap_escape(spn)})",
            attributes=["sAMAccountName"],
        )
        if parse_result_attributes(resp):
            # Target account exists; host_exists is only consulted when the SPN is
            # unregistered, so skip the redundant host lookup.
            return True, False

        # SPN unregistered: does the host the SPN points to exist as a computer account at all?
        host_exists = False
        host = self.spn_host(spn)
        if host:
            short = host.split(".")[0]
            resp = connection.search(
                searchFilter=(
                    f"(&(objectCategory=computer)(|(dNSHostName={self.ldap_escape(host)})"
                    f"(sAMAccountName={self.ldap_escape(short)}$)(cn={self.ldap_escape(short)})))"
                ),
                attributes=["sAMAccountName"],
            )
            host_exists = bool(parse_result_attributes(resp))

        return False, host_exists

    def on_login(self, context, connection):
        # Find every account configured for constrained delegation
        resp = connection.search(
            searchFilter="(msDS-AllowedToDelegateTo=*)",
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo", "distinguishedName"],
        )
        delegators = parse_result_attributes(resp)
        if not delegators:
            context.log.display("No accounts with constrained delegation (msDS-AllowedToDelegateTo) configured")
            return

        context.log.success(f"Found {len(delegators)} account(s) with constrained delegation configured")

        # For each unique target SPN, check whether the referenced account exists
        spn_cache = {}   # lowercased spn -> (spn_registered, host_exists)
        orphans = []     # (account, dn, spn, host_exists)

        for item in delegators:
            account = self.ci_get(item, "sAMAccountName") or "<unknown>"
            dn = self.ci_get(item, "distinguishedName") or ""
            targets = self.ci_get(item, "msDS-AllowedToDelegateTo")
            if not targets:
                continue
            if isinstance(targets, str):
                targets = [targets]

            context.log.info(f"{account} is allowed to delegate to: {', '.join(targets)}")

            for spn in targets:
                key = spn.lower()
                if key not in spn_cache:
                    spn_cache[key] = self.target_status(connection, spn)
                spn_registered, host_exists = spn_cache[key]

                if not spn_registered and not host_exists:
                    orphans.append((account, dn, spn, False))
                elif self.strict and not spn_registered and host_exists:
                    orphans.append((account, dn, spn, True))

        if not orphans:
            context.log.success("All constrained delegation targets resolve to existing accounts")
            return

        context.log.success(f"Found {len(orphans)} orphaned constrained-delegation SPN(s):")
        last_account = None
        for account, _dn, spn, host_exists in sorted(orphans, key=lambda o: (o[0].lower(), o[2].lower())):
            if account != last_account:
                context.log.highlight(f"Account: {account}")
                last_account = account
            reason = "SPN unregistered, host exists" if host_exists else "no such computer/service account"
            context.log.highlight(f"    {spn}  ->  {reason} (ORPHANED)")

        if self.output_file:
            records = [
                {
                    "account": account,
                    "spn": spn,
                    "reason": "host_exists_spn_unregistered" if host_exists else "account_missing",
                    "dn": dn,
                }
                for account, dn, spn, host_exists in sorted(orphans, key=lambda o: (o[0].lower(), o[2].lower()))
            ]
            try:
                with open(self.output_file, "w") as f:
                    json.dump(records, f, indent=4)
                context.log.success(f"Results saved to {self.output_file}")
            except Exception as e:
                context.log.error(f"Failed to write to file {self.output_file}: {e}")
