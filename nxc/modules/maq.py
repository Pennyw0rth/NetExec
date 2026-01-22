import re 
import ntpath

from io import BytesIO
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

from impacket.smbconnection import SMBConnection

class NXCModule:
    """
    Module by Shutdown and Podalirius
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
                        nthash=connection.lmhash,
                        aesKey=connection.aesKey,
                        kdcHost=connection.kdcHost,
                        useCache=connection.use_kcache,
                    )
            
            elif connection.nthash or connection.lmhash:
                smb.login(connection.username, "", connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)

            else:
                smb.login(connection.username, connection.password, connection.domain)

            return smb

        context.log.display("Getting the SeMachineAccountPrivilege")
        base = f"OU=Domain Controllers,{connection.baseDN}"
        ldap_response = connection.search(
            searchFilter="(objectClass=*)",
            baseDN=base,
            attributes=["gPLink"]
        )
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No gPLink entries returned.")
            return

        guids = re.findall(r"(?i)cn=\{([0-9a-f\-]{36})\}", entries[0]["gPLink"])
        context.log.debug(f"GUID founds: {guids}")
        
        smb = connect_smb(connection)

        for guid in guids:
            path = ntpath.join(
                    connection.domain,
                    "Policies",
                    f"{{{guid.upper()}}}",
                    "MACHINE",
                    "Microsoft",
                    "Windows NT",
                    "SecEdit",
                    "GptTmpl.inf",
                    )
            
            try:
                buf = BytesIO()
                smb.getFile("SYSVOL", path, buf.write)
                buf.seek(0)
                GptTmpl = buf.read().decode("utf-16le", errors="ignore")

            except Exception as e:
                context.log.debug(f"{guid}: no GptTmpl.inf / not reachable ({e})")
                continue
            
            for line in GptTmpl.splitlines():
                if "SeMachineAccountPrivilege" in line:
                    context.log.highlight(f"{line}")
                    # Ajouter la traduction du/des sid(s)
                    # ldap_response = connection.search("")
                    return


    def on_login(self, context, connection):
        context.log.display("Getting the MachineAccountQuota")

        ldap_response = connection.search("(ms-DS-MachineAccountQuota=*)", ["ms-DS-MachineAccountQuota"])
        entries = parse_result_attributes(ldap_response)

        if not entries:
            context.log.fail("No LDAP entries returned.")
            return

        context.log.highlight(f"MachineAccountQuota: {entries[0]['ms-DS-MachineAccountQuota']}\n")

        self.get_SeMachineAccountPrivilege(context, connection)
        
