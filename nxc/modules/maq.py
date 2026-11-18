import re
import ntpath

from io import BytesIO
from nxc.helpers.misc import CATEGORY
from nxc.helpers.smb import get_smb_connection
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.protocols.ldap.constants import WELL_KNOWN_SIDS

from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.krb5.kerberosv5 import KerberosError
from impacket import nt_errors


class NXCModule:
    """
    Module by Shutdown, Podalirius and serwiz
    Modified by @azoxlpf to handle null session errors and avoid IndexError when no LDAP results are returned.

    Initial module:
      https://github.com/ShutdownRepo/CrackMapExec-MachineAccountQuota

    Authors:
      Shutdown: @_nwodtuhs
      Podalirius: @podalirius_
    """
    name = "maq"
    description = "Retrieves the MachineAccountQuota domain-level attribute and check SeMachineAccountPrivilege (GPO/SYSVOL)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota")
        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        context.log.highlight(f"MachineAccountQuota: {entries[0]['ms-DS-MachineAccountQuota']}")

        self.get_SeMachineAccountPrivilege(context, connection)

    def get_SeMachineAccountPrivilege(self, context, connection):
        gpo_links = self.get_gpo_links(context, connection)
        if not gpo_links:
            context.log.debug("No enabled GPO links found for the domain and Domain Controllers OU")
            return
        context.log.debug(f"gPLink parsed: {gpo_links}")

        try:
            smb = get_smb_connection(context, connection)
        except (OSError, SessionError, NetBIOSError, NetBIOSTimeout, KerberosError) as e:
            context.log.fail(f"Unable to connect to SYSVOL through SMB: {e}")
            return
        if not smb:
            return
        context.log.display("Getting SeMachineAccountPrivilege")

        try:
            for link in gpo_links:
                guid = link["guid"]
                gpo_name = self.resolve_gpo(connection, guid) or f"{{{guid}}}"
                # Accessing the GPO in the SYSVOL share to parse GptTmpl.inf
                path = ntpath.join(connection.targetDomain, "Policies", f"{{{guid}}}", "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")

                try:
                    buf = BytesIO()
                    smb.getFile("SYSVOL", path, buf.write)
                    GptTmpl = buf.getvalue().decode("utf-16le")
                except SessionError as e:
                    if e.getErrorCode() in (nt_errors.STATUS_NO_SUCH_FILE, nt_errors.STATUS_OBJECT_NAME_NOT_FOUND, nt_errors.STATUS_OBJECT_PATH_NOT_FOUND):
                        context.log.debug(f"No GptTmpl.inf for GPO {guid}")
                    else:
                        enforced_str = ", Enforced" if link["enforced"] else ""
                        context.log.fail(f'(GPO) "{gpo_name}" [DN: {link["scope_dn"]}] [Link order: {link["link_order"]}{enforced_str}] not readable ({e.getErrorString()[0]}), result may be incomplete')
                    continue
                except (OSError, NetBIOSError, NetBIOSTimeout, UnicodeError) as e:
                    context.log.fail(f"Unable to read {path}: {e}")
                    continue

                # An absent setting inherits; an explicitly empty assignment overrides.
                for line in GptTmpl.splitlines():
                    match = re.match(r"^\s*SeMachineAccountPrivilege\s*=(.*)$", line.lstrip("\ufeff"))
                    if match:
                        value = match.group(1).strip()
                        break
                else:
                    context.log.debug(f"SeMachineAccountPrivilege not in {path}")
                    continue

                enforced_str = ", Enforced" if link["enforced"] else ""
                context.log.success(f'(GPO) "{gpo_name}" [DN: {link["scope_dn"]}] [Link order: {link["link_order"]}{enforced_str}]')
                context.log.info(f"\t{line.strip()}")
                if not value:
                    context.log.highlight("SeMachineAccountPrivilege explicitly assigned to nobody")
                    continue

                principals = [principal.strip() for principal in value.split(",") if principal.strip()]
                for principal in principals:
                    match = re.fullmatch(r"\*?(S-\d+(?:-\d+)+)", principal)
                    if not match:
                        context.log.highlight(f'\t\t - "{principal}"')
                        continue
                    sid = match.group(1)
                    if sid in WELL_KNOWN_SIDS:
                        context.log.highlight(f'\t\t - "{WELL_KNOWN_SIDS[sid]}" ({sid})')
                        continue
                    resp = connection.search(searchFilter=f"(objectSid={sid})", attributes=["sAMAccountName"])
                    entries = parse_result_attributes(resp)
                    if entries and entries[0].get("sAMAccountName"):
                        context.log.highlight(f'\t\t - "{entries[0]["sAMAccountName"]}" ({sid})')
                    else:
                        context.log.highlight(f"\t\t - {sid} (unresolved)")
        finally:
            smb.logoff()

    def get_gpo_links(self, context, connection):
        ou_dn = f"OU=Domain Controllers,{connection.baseDN}"
        gpo_links = []
        block_inheritance = False

        for scope_dn in (ou_dn, connection.baseDN):
            ldap_response = connection.search(searchFilter=f"(distinguishedName={scope_dn})", baseDN=scope_dn, attributes=["gPLink", "gPOptions"])
            entries = parse_result_attributes(ldap_response)
            if not entries:
                context.log.fail(f"Unable to read GPO links for {scope_dn}")
                return []
            if scope_dn == ou_dn:
                block_inheritance = bool(int(entries[0].get("gPOptions") or 0) & 0x1)
            for link in self.parse_gplink(entries[0].get("gPLink") or ""):
                if link["disabled"]:
                    context.log.debug(f'GPO link {link["guid"]} disabled, skipping')
                    continue
                if scope_dn == connection.baseDN and block_inheritance and not link["enforced"]:
                    context.log.debug(f'GPO link {link["guid"]} blocked by inheritance, skipping')
                    continue
                link["scope_dn"] = scope_dn
                # Enforced domain, enforced OU, normal OU, then normal domain links.
                link["priority"] = (0 if scope_dn == connection.baseDN else 1) if link["enforced"] else (2 if scope_dn == ou_dn else 3)
                gpo_links.append(link)
        return sorted(gpo_links, key=lambda link: (link["priority"], link["link_order"]))

    def resolve_gpo(self, connection, guid):
        resp = connection.search(baseDN=f"CN=Policies,CN=System,{connection.baseDN}", searchFilter=f"(&(objectClass=groupPolicyContainer)(name={{{guid}}}))", attributes=["displayName", "name"])
        results = parse_result_attributes(resp)
        if not results:
            return ""
        return results[0].get("displayName") or results[0].get("name") or ""

    def parse_gplink(self, gplink):
        raw_entries = re.findall(r"(?i)\[LDAP://cn=\{([0-9a-f\-]{36})\}[^;\]]*;(\d+)\]", gplink)
        parsed = []
        # Number every link, including disabled links (last listed = order 1).
        for link_order, (guid, flags_str) in enumerate(reversed(raw_entries), 1):
            flags = int(flags_str)
            parsed.append({"guid": guid, "flags": flags, "disabled": bool(flags & 0x1), "enforced": bool(flags & 0x2), "link_order": link_order})
        return parsed
