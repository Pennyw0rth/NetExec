import re
import ntpath

from io import BytesIO
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

from impacket.smbconnection import SMBConnection, SessionError
from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.krb5.kerberosv5 import KerberosError


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

    name = "maqq"
    description = "Retrieves the MachineAccountQuota domain-level attribute and check SeMachineAccountPrivilege (GPO/SYSVOL)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    WELL_KNOWN_SIDS = {
        "S-1-1-0": "Everyone",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-18": "Local System",
        "S-1-5-32-544": "Administrators",
        "S-1-5-32-545": "Users",
    }

    def options(self, context, module_options):
        """No options available"""

    def resolve_gpo(self, context, connection, guid):
        gpo_dn = f"CN={{{guid}}},CN=Policies,CN=System,{connection.baseDN}"

        try:
            resp = connection.search(
                    baseDN=gpo_dn,
                    searchFilter="(objectClass=groupPolicyContainer)",
                    attributes=["displayName", "name"]
                    )

            results = parse_result_attributes(resp)
            if results:
                return results[0].get("displayName") or results[0].get("name")
            else:
                return ""
        except Exception as e:
            context.logger.debug(f"Exception raised while looking for groupPolicyContainer: {e}")
            return ""

    # Just handle smb connection
    def connect_smb(self, connection):
        smb = SMBConnection(
                remoteName=connection.hostname,
                remoteHost=connection.host,
                sess_port=445,
                timeout=connection.args.timeout or 3,
        )

        if connection.kerberos:
            smb.kerberosLogin(
                    user=connection.username,
                    password=connection.password,
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                    aesKey=connection.aesKey,
                    kdcHost=connection.kdcHost,
                    useCache=connection.use_kcache,
                )
        elif connection.nthash or connection.lmhash:
            smb.login(connection.username, "", connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)

        else:
            smb.login(connection.username, connection.password, connection.domain)

        return smb

    def parse_gplink(self, context, gplink):
        """
        Parse une chaîne gPLink et retourne une liste de dicts contenant
        pour chaque lien : guid, flags bruts, disabled, enforced, et
        link_order (1 = le plus prioritaire, au sens de l'ordre affiché
        dans GPMC / gpresult, donc le dernier appliqué qui gagne).

        Format gPLink: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;FLAGS][...]
        FLAGS bit 0 (1) = link Disabled
        FLAGS bit 1 (2) = Enforced (No Override)

        Ordre d'application AD : le DERNIER lien listé dans gPLink est
        appliqué en dernier donc gagne en cas de conflit -> link_order 1.
        On inverse donc l'ordre d'apparition pour numéroter le link order,
        en ignorant les liens désactivés dans la numérotation.
        """
        raw_entries = re.findall(
            r"(?i)\[LDAP://cn=\{([0-9a-f\-]{36})\}[^;\]]*;(\d+)\]",
            gplink
        )

        parsed = []
        for guid, flags_str in raw_entries:
            flags = int(flags_str)
            parsed.append({
                "guid": guid,
                "flags": flags,
                "disabled": bool(flags & 0x1),
                "enforced": bool(flags & 0x2),
            })

        # Numérotation du link order parmi les liens actifs uniquement,
        # en inversant l'ordre d'apparition (dernier listé = order 1)
        active = [p for p in parsed if not p["disabled"]]
        for idx, entry in enumerate(reversed(active)):
            entry["link_order"] = idx + 1

        # Les liens désactivés n'ont pas de link order applicable
        for entry in parsed:
            if entry["disabled"]:
                entry["link_order"] = None

        return parsed

    def get_SeMachineAccountPrivilege(self, context, connection):

        # Getting the gPLink applies to Domain Controllers OU
        ou_dn = f"OU=Domain Controllers,{connection.baseDN}"
        try:
            ldap_response = connection.search(
                searchFilter="(objectClass=*)",
                baseDN=ou_dn,
                attributes=["gPLink"]
            )
            entries = parse_result_attributes(ldap_response)
        except Exception as e:
            context.logger.debug(f"Exception raised while looking for gPLink: {e}")
            return

        if not entries:
            context.log.fail("No gPLink entries returned.")
            return

        gplink = entries[0].get("gPLink", "")
        if not gplink:
            context.log.debug("No gPLink found for Domain Controllers OU")
            return

        gpo_links = self.parse_gplink(context, gplink)
        context.log.debug(f"gPLink parsed: {gpo_links}")

        try:
            smb = self.connect_smb(connection)
        except (OSError, SessionError, NetBIOSError, NetBIOSTimeout, KerberosError) as e:
            context.log.debug(f"Unable to connect to SYSVOL through SMB: {e}")
            return

        context.log.display("Getting SeMachineAccountPrivilege")

        for link in gpo_links:
            guid = link["guid"]

            if link["disabled"]:
                context.log.debug(f"GPO link {guid} disabled, skipping")
                continue

            # Accessing the GPO in the SYSVOL share to parse GptTmpl.inf
            path = ntpath.join(connection.targetDomain, "Policies", f"{{{guid}}}", "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
            try:
                buf = BytesIO()
                smb.getFile("SYSVOL", path, buf.write)
                buf.seek(0)
                GptTmpl = buf.read().decode("utf-16le", errors="ignore")
            except Exception as e:
                context.log.debug(f'({guid}) no GptTmpl.inf or not reachable: \n gpo_path:"{path}"\nException: {e}')
                continue

            # Parse the GptTmpl.inf to find SeMachineAccountPrivilege
            sids = []
            found = False
            for line in GptTmpl.splitlines():
                if "SeMachineAccountPrivilege" in line:
                    found = True
                    gpo_name = self.resolve_gpo(context, connection, guid)
                    enforced_str = "Enforced" if link["enforced"] else "Not Enforced"
                    context.log.success(f'(GPO) "{gpo_name}" [CN: {ou_dn}] [Link order: {link["link_order"]}, {enforced_str}]')
                    context.log.highlight(f"\t{line.strip()}")
                    # extract all the sid concerns by the SeMachineAccountPrivilege
                    sids = re.findall(r"\*?(S-\d+(?:-\d+)+)", line)
                    break

            if not found:
                context.log.debug(f"SeMachineAccountPrivilege not in {path}")
                continue

            if sids != []:
                for sid in sids:
                    if sid in self.WELL_KNOWN_SIDS:
                        context.log.highlight(f'\t\t - "{self.WELL_KNOWN_SIDS[sid]}" ({sid})')
                        continue

                    resp = connection.search(
                        searchFilter=f"(objectSid={sid})",
                        attributes=["sAMAccountName"]
                    )
                    entries = parse_result_attributes(resp)
                    if entries and entries[0].get("sAMAccountName"):
                        context.log.highlight(f'\t\t - "{entries[0]["sAMAccountName"]}" ({sid})')
                    else:
                        context.log.debug(f"Could not resolve SID: {sid}")

            else:
                context.log.fail("No SID(s) found in SeMachineAccountPrivilege")

        smb.logoff()

        return

    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota")

        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        context.log.highlight(f"MachineAccountQuota: {entries[0]['ms-DS-MachineAccountQuota']}")

        self.get_SeMachineAccountPrivilege(context, connection)
