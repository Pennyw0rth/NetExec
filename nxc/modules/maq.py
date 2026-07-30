import re
import ntpath

from io import BytesIO
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

from impacket.smbconnection import SMBConnection


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

    def get_SeMachineAccountPrivilege(self, context, connection):

        # Getting the gPLink applies to Domain Controllers OU
        try:
            base = f"OU=Domain Controllers,{connection.baseDN}"
            ldap_response = connection.search(
                searchFilter="(objectClass=*)",
                baseDN=base,
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

        # Extract GUIDS from the output using regex
        guids = re.findall(r"(?i)cn=\{([0-9a-f\-]{36})\}", gplink)
        context.log.debug(f"GUID founds: {guids}")

        smb = self.connect_smb(connection)

        for guid in guids:
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
                    context.log.success(f'(GPO) "{gpo_name}"')
                    context.log.highlight(f"\t{line}")
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

        context.log.display("Getting SeMachineAccountPrivilege")

        self.get_SeMachineAccountPrivilege(context, connection)
