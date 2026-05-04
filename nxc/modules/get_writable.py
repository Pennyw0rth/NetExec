import shutil
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.helpers.misc import CATEGORY


OTYPE_FILTERS = {
    "all":      "(objectClass=*)",
    "user":     "(sAMAccountType=805306368)",
    "computer": "(objectClass=computer)",
    "group":    "(objectClass=group)",
    "ou":       "(|(objectClass=organizationalUnit)(objectClass=container))",
    "gpo":      "(objectClass=groupPolicyContainer)",
    "domain":   "(objectClass=domain)",
}

SD_RIGHTS = {
    3: "OWNER",
    4: "DACL",
    8: "SACL",
}


class NXCModule:
    """
    Module by @goultarde - inspired by bloodyAD get writable
    Enumerates AD objects on which the current user has write permissions,
    using DC-computed operational attributes (allowedAttributesEffective,
    allowedChildClassesEffective, sDRightsEffective).
    No ACL parsing needed - the DC does the work.
    """

    name = "get_writable"
    description = "Enumerates AD objects writable by the current user (WRITE, CREATE_CHILD, OWNER, DACL)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        OTYPE   Object type to filter: all, user, computer, group, ou, gpo, domain (default: all)
        RIGHT   Right to look for: ALL, WRITE, CHILD (default: ALL)
        DETAIL  Show attribute/class names instead of just 'permission' (default: False)
        """
        otype = module_options.get("OTYPE", "all").lower()
        if otype not in OTYPE_FILTERS:
            context.log.fail(f"Invalid OTYPE '{otype}'. Choose from: {', '.join(OTYPE_FILTERS)}")
            self.otype_filter = OTYPE_FILTERS["all"]
        else:
            self.otype_filter = OTYPE_FILTERS[otype]

        self.right = module_options.get("RIGHT", "ALL").upper()
        if self.right not in ("ALL", "WRITE", "CHILD"):
            self.right = "ALL"

        self.detail = module_options.get("DETAIL", "").lower() in ("true", "1", "yes")

    def on_login(self, context, connection):
        attrs = ["distinguishedName", "sAMAccountName", "objectClass"]
        if self.right in ("WRITE", "ALL"):
            attrs += ["allowedAttributesEffective", "sDRightsEffective"]
        if self.right in ("CHILD", "ALL"):
            attrs.append("allowedChildClassesEffective")

        context.log.display("Enumerating writable objects (this may take a while)...")

        resp = connection.search(
            searchFilter=self.otype_filter,
            attributes=attrs,
        )

        if not resp:
            context.log.display("No results or no write permissions found")
            return

        findings = []
        for entry in parse_result_attributes(resp):
            dn = entry.get("distinguishedName", "")
            if not dn:
                continue

            permissions = []

            if self.right in ("WRITE", "ALL"):
                allowed_attrs = entry.get("allowedAttributesEffective", [])
                if isinstance(allowed_attrs, str):
                    allowed_attrs = [allowed_attrs]
                if allowed_attrs:
                    permissions.append(("WRITE", list(allowed_attrs) if self.detail else []))

                sd_raw = entry.get("sDRightsEffective", 0)
                try:
                    sd_mask = int(sd_raw)
                except (ValueError, TypeError):
                    sd_mask = 0
                for mask, label in SD_RIGHTS.items():
                    if sd_mask & mask:
                        permissions.append((label, []))

            if self.right in ("CHILD", "ALL"):
                child_classes = entry.get("allowedChildClassesEffective", [])
                if isinstance(child_classes, str):
                    child_classes = [child_classes]
                if child_classes:
                    permissions.append(("CREATE_CHILD", list(child_classes) if self.detail else []))

            if permissions:
                sam = entry.get("sAMAccountName", "")
                findings.append({"dn": dn, "sam": sam, "permissions": permissions})

        if not findings:
            context.log.display("No writable objects found")
            return

        context.log.success(f"{len(findings)} writable object(s) found")
        for f in findings:
            context.log.highlight(f"DN         : {f['dn']}")
            if self.detail:
                context.log.highlight("Permission :")
            sd_rights = []
            simple_rights = []
            for right, details in f["permissions"]:
                if right in ("OWNER", "DACL", "SACL"):
                    sd_rights.append(right)
                elif self.detail and details:
                    label = f"  {right:<12} : "
                    pad = " " * len(label)
                    # NXC prefix is ~56 chars (module + ip + port + hostname)
                    available = shutil.get_terminal_size((120, 24)).columns - 56 - len(label)
                    available = max(available, 40)
                    lines = []
                    current = []
                    current_len = 0
                    for attr in details:
                        entry = f"{attr}, "
                        if current_len + len(entry) > available and current:
                            lines.append(current)
                            current = []
                            current_len = 0
                        current.append(attr)
                        current_len += len(entry)
                    if current:
                        lines.append(current)
                    context.log.highlight(f"{label}{', '.join(lines[0])}")
                    for line in lines[1:]:
                        context.log.highlight(f"{pad}{', '.join(line)}")
                else:
                    simple_rights.append(right)
            if simple_rights:
                context.log.highlight(f"  Permission : {'; '.join(simple_rights)}")
            if sd_rights:
                context.log.highlight(f"  {' / '.join(sd_rights)}")
