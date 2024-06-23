from dateutil.relativedelta import relativedelta as rd
from impacket.ldap import ldapasn1 as ldapasn1_impacket


class NXCModule:
    """
    Initial FGPP/PSO script written by @n00py: https://github.com/n00py/GetFGPP

    Module by @_sandw1ch
    """
    name = "pso"
    description = "Module to get the Fine Grained Password Policy/PSOs"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """No options available."""

    def on_login(self, context, connection):
        # Are there even any FGPPs?
        context.log.success("Attempting to enumerate policies...")
        resp = connection.ldapConnection.search(searchBase=f"CN=Password Settings Container,CN=System,{''.join([f'DC={dc},' for dc in connection.domain.split('.')]).rstrip(',')}", searchFilter="(objectclass=*)")
        if len(resp) > 1:
            context.log.highlight(f"{len(resp) - 1} PSO Objects found!")
            context.log.highlight("")
            context.log.success("Attempting to enumerate objects with an applied policy...")

        # Who do they apply to?
        resp = connection.search(searchFilter="(objectclass=*)", attributes=["DistinguishedName", "msDS-PSOApplied"])
        for attrs in resp:
            if isinstance(attrs, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            for attr in attrs["attributes"]:
                if str(attr["type"]) in "msDS-PSOApplied":
                    context.log.highlight(f"Object: {attrs['objectName']}")
                    context.log.highlight("Applied Policy: ")
                    for value in attr["vals"]:
                        context.log.highlight(f"\t{value}")
                    context.log.highlight("")

        # Let"s find out even more details!
        context.log.success("Attempting to enumerate details...\n")
        resp = connection.search(searchFilter="(objectclass=msDS-PasswordSettings)",
                                 attributes=["name", "msds-lockoutthreshold", "msds-psoappliesto", "msds-minimumpasswordlength",
                                             "msds-passwordhistorylength", "msds-lockoutobservationwindow", "msds-lockoutduration",
                                             "msds-passwordsettingsprecedence", "msds-passwordcomplexityenabled", "Description",
                                             "msds-passwordreversibleencryptionenabled", "msds-minimumpasswordage", "msds-maximumpasswordage"])
        for attrs in resp:
            if not isinstance(attrs, ldapasn1_impacket.SearchResultEntry):
                continue
            policyName, description, passwordLength, passwordhistorylength, lockoutThreshold, observationWindow, lockoutDuration, complexity, minPassAge, maxPassAge, reverseibleEncryption, precedence, policyApplies = ("",) * 13
            for attr in attrs["attributes"]:
                if str(attr["type"]) == "name":
                    policyName = attr["vals"][0]
                elif str(attr["type"]) == "msDS-LockoutThreshold":
                    lockoutThreshold = attr["vals"][0]
                elif str(attr["type"]) == "msDS-MinimumPasswordLength":
                    passwordLength = attr["vals"][0]
                elif str(attr["type"]) == "msDS-PasswordHistoryLength":
                    passwordhistorylength = attr["vals"][0]
                elif str(attr["type"]) == "msDS-LockoutObservationWindow":
                    observationWindow = attr["vals"][0]
                elif str(attr["type"]) == "msDS-LockoutDuration":
                    lockoutDuration = attr["vals"][0]
                elif str(attr["type"]) == "msDS-PasswordSettingsPrecedence":
                    precedence = attr["vals"][0]
                elif str(attr["type"]) == "msDS-PasswordComplexityEnabled":
                    complexity = attr["vals"][0]
                elif str(attr["type"]) == "msDS-PasswordReversibleEncryptionEnabled":
                    reverseibleEncryption = attr["vals"][0]
                elif str(attr["type"]) == "msDS-MinimumPasswordAge":
                    minPassAge = attr["vals"][0]
                elif str(attr["type"]) == "msDS-MaximumPasswordAge":
                    maxPassAge = attr["vals"][0]
                elif str(attr["type"]) == "description":
                    description = attr["vals"][0]
                elif str(attr["type"]) == "msDS-PSOAppliesTo":
                    policyApplies = ""
                    for value in attr["vals"]:
                        policyApplies += f"{value};"
            context.log.highlight(f"Policy Name: {policyName}")
            if description:
                context.log.highlight(f"Description: {description}")
            context.log.highlight(f"Minimum Password Length: {passwordLength}")
            context.log.highlight(f"Minimum Password History Length: {passwordhistorylength}")
            context.log.highlight(f"Lockout Threshold: {lockoutThreshold}")
            context.log.highlight(f"Observation Window: {mins(observationWindow)}")
            context.log.highlight(f"Lockout Duration: {mins(lockoutDuration)}")
            context.log.highlight(f"Complexity Enabled: {complexity}")
            context.log.highlight(f"Minimum Password Age: {days(minPassAge)}")
            context.log.highlight(f"Maximum Password Age: {days(maxPassAge)}")
            context.log.highlight(f"Reversible Encryption: {reverseibleEncryption}")
            context.log.highlight(f"Precedence: {precedence} (Lower is Higher Priority)")
            context.log.highlight("Policy Applies to:")
            for value in str(policyApplies)[:-1].split(";"):
                if value:
                    context.log.highlight(f"\t{value}")
            context.log.highlight("")


def days(ldap_time):
    return f"{rd(seconds=int(abs(int(ldap_time)) / 10000000)).days} days"


def mins(ldap_time):
    return f"{rd(seconds=int(abs(int(ldap_time)) / 10000000)).minutes} minutes"
