import re
import ntpath

from io import BytesIO
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED


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

    def options(self, context, module_options):
        """No options available"""

    name = "maq"
    description = "Retrieves the MachineAccountQuota domain-level attribute and check SeMachineAccountPrivilege (GPO/SYSVOL)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def get_SeMachineAccountPrivilege(self, context, connection):

        def resolve_gpo(context, connection, guid):
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
        def connect_smb(connection):
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
            exit(1)

        if not entries:
            context.log.fail("No gPLink entries returned.")
            return

        # Extract GUIDS from the output using regex
        guids = re.findall(r"(?i)cn=\{([0-9a-f\-]{36})\}", entries[0]["gPLink"])
        context.log.debug(f"GUID founds: {guids}")

        smb = connect_smb(connection)

        for guid in guids:
            # Accessing the GPO in the SYSVOL share to parse GptTmpl.inf
            path = ntpath.join(connection.targetDomain, "Policies", f"{{{guid}}}", "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf",)
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
                    gpo_name = resolve_gpo(context, connection, guid)
                    context.log.success(f'[GPO] "{gpo_name}"')
                    context.log.highlight(f"{line}")
                    # extract all the sid concerns by the SeMachineAccountPrivilege
                    sids = re.findall(r"\*?(S-\d+(?:-\d+)+)", line)
                    break

            if found == False:
                context.log.debug(f"SeMachineAccountPrivilege not in {path}")
                continue


            if sids != []:
                sessions = {}
                for sid in sids:
                    sessions.setdefault(sid, {"Username": ""})

                try:
                    # Handle RPC connection
                    string_binding = rf"ncacn_np:{connection.host}[\pipe\lsarpc]"
                    rpctransport = DCERPCTransportFactory(string_binding)
                    rpctransport.set_credentials(connection.username, connection.password, connection.domain, connection.lmhash, connection.nthash,)
                    rpctransport.set_connect_timeout(15)
                    dce = rpctransport.get_dce_rpc()
                    if connection.kerberos:
                        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
                    dce.connect()
                    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                    dce.bind(lsat.MSRPC_UUID_LSAT)
                except Exception as e:
                    context.log.debug(f"Error connecting to {string_binding}: {e!s}")

                try:
                    # Getting the LSA policy
                    policy_handle = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
                except Exception as e:
                    context.log.debug(f"Unable to get policy handle: {e!s}")
                    return

                try:
                    # Sid translation (lookup sid)
                    resp = lsat.hLsarLookupSids(dce, policy_handle, sessions.keys(), lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
                except DCERPCException as e:
                    if str(e).find("STATUS_SOME_NOT_MAPPED") >= 0:
                        resp = e.get_packet()
                        context.log.debug(f"Could not resolve some SIDs: {e}")
                    else:
                        resp = None
                        context.log.debug(f"Could not resolve SID(s): {e}")
                if resp:
                    for sid, item in zip(sessions.keys(), resp["TranslatedNames"]["Names"], strict=False):
                        if item["DomainIndex"] >= 0:
                            context.log.highlight(f"\t({sid}) \"{item['Name']}\"")

            else:
                context.log.fail("No SID(s) found in SeMachineAccountPrivilege")

        return

                

    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota and SeMachineAccountPrivilege")

        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        context.log.highlight(f"MachineAccountQuota: {entries[0]['ms-DS-MachineAccountQuota']}")

        self.get_SeMachineAccountPrivilege(context, connection)
