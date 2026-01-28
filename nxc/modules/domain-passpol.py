from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Created by @d0mi33 (Dominic Thirshatha)
    LDAP password policy values are returned as signed 64-bit
    100ns intervals (unlike SAMR FILETIME structs), so conversion must be handled locally to maintain parity with --pass-pol. 
    """
    name = "domain-passpol"
    description = "Enumerate default domain password policy via LDAP"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    ATTRS = [
        "minPwdLength",
        "pwdHistoryLength",
        "maxPwdAge",
        "minPwdAge",
        "pwdProperties",
        "lockoutThreshold",
        "lockoutDuration",
        "lockoutObservationWindow",
    ]

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        context.log.success(
            f"Dumping password info for domain: {context.domain.split('.')[0].upper()}"
        )

        vals = {}

        for attr in self.ATTRS:
            res = connection.search("(objectClass=domainDNS)", [attr])
            entries = parse_result_attributes(res)
            if not entries:
                continue

            e = entries[0]
            vals[attr] = e.get(attr) or e.get("lockOutObservationWindow")

        # ---------- helpers ----------
        def ldap_ticks_to_time(ticks, lockout=False):
            if not ticks or int(ticks) == 0:
                return "Not Set"
            ticks = abs(int(ticks))
            seconds = ticks // 10_000_000
            if lockout:
                return f"{seconds // 60} minutes"

            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            minutes = (seconds % 3600) // 60

            out = []
            if days:
                out.append(f"{days} days")
            if hours:
                out.append(f"{hours} hours")
            if minutes:
                out.append(f"{minutes} minutes")

            return " ".join(out)

        def d2b_local(v):
            return format(int(v), "06b")

        # ---------- output ----------
        context.log.highlight(f"Minimum password length: {vals.get('minPwdLength')}")
        context.log.highlight(f"Password history length: {vals.get('pwdHistoryLength')}")
        context.log.highlight(
            f"Maximum password age: {ldap_ticks_to_time(vals.get('maxPwdAge'))}"
        )
        context.log.highlight("")

        props = d2b_local(vals.get("pwdProperties", 0))
        context.log.highlight(f"Password Complexity Flags: {props}")

        PASSCOMPLEX = {
            5: "Domain Password Complex:",
            4: "Domain Password No Anon Change:",
            3: "Domain Password No Clear Change:",
            2: "Domain Password Lockout Admins:",
            1: "Domain Password Store Cleartext:",
            0: "Domain Refuse Password Change:",
        }

        for i, bit in enumerate(props):
            context.log.highlight(f"\t{PASSCOMPLEX[i]} {bit}")

        context.log.highlight("")
        context.log.highlight(
            f"Minimum password age: {ldap_ticks_to_time(vals.get('minPwdAge'))}"
        )
        context.log.highlight(
            f"Reset Account Lockout Counter: "
            f"{ldap_ticks_to_time(vals.get('lockoutObservationWindow'), lockout=True)}"
        )
        context.log.highlight(
            f"Locked Account Duration: "
            f"{ldap_ticks_to_time(vals.get('lockoutDuration'), lockout=True)}"
        )
        context.log.highlight(
            f"Account Lockout Threshold: {vals.get('lockoutThreshold')}"
        )
        context.log.highlight("Forced Log off Time: Not Set")

