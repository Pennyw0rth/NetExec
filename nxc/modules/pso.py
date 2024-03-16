#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
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
        resp = connection.ldapConnection.search(searchBase="CN=Password Settings Container,CN=System," + "".join([f"DC={dc}," for dc in connection.domain.split(".")]).rstrip(","), searchFilter="(objectclass=*)")
        if len(resp) > 1:
            context.log.highlight(str(len(resp) - 1) + " PSO Objects found!")
            context.log.highlight("")
            context.log.success("Attempting to enumerate objects with an applied policy...")

        # Who do they apply to?
        resp = connection.search(searchFilter="(objectclass=*)", attributes=["DistinguishedName", "msDS-PSOApplied"])
        for i in resp:
            if isinstance(i, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            for attr in i["attributes"]:
                if (str(attr["type"]) == "msDS-PSOApplied"):
                    context.log.highlight("Object: " + str(i["objectName"]))
                    if len(attr["vals"]) == 1:
                        context.log.highlight("Applied Policy: ")
                        context.log.highlight("\t"+attr["vals"][0])
                        context.log.highlight("")
                    else:
                        policies = ""
                        for value in attr["vals"]:
                            policies = policies+value+";"
                        context.log.highlight("Applied Policy: ")
                        for obj in str(policies)[:-1].split(";"):
                            context.log.highlight("\t"+str(obj))
                        context.log.highlight("")

        # Let"s find out even more details!
        context.log.success("Attempting to enumerate details...\n")
        resp = connection.search(searchFilter="(objectclass=msDS-PasswordSettings)",
                                 attributes=["name", "msds-lockoutthreshold", "msds-psoappliesto", "msds-minimumpasswordlength",
                                             "msds-passwordhistorylength", "msds-lockoutobservationwindow", "msds-lockoutduration",
                                             "msds-passwordsettingsprecedence", "msds-passwordcomplexityenabled", "Description",
                                             "msds-passwordreversibleencryptionenabled", "msds-minimumpasswordage", "msds-maximumpasswordage"])
        for i in resp:
            if isinstance(i, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            policyName, description, passwordLength, passwordhistorylength, lockoutThreshold, obersationWindow, lockoutDuration, complexity, minPassAge, maxPassAge, reverseibleEncryption, precedence, policyApplies = ("",)*13
            for attr in i["attributes"]:
                if (str(attr["type"]) == "name"):
                    policyName = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-LockoutThreshold"):
                    lockoutThreshold = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-MinimumPasswordLength"):
                    passwordLength = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-PasswordHistoryLength"):
                    passwordhistorylength = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-LockoutObservationWindow"):
                    obersationWindow = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-LockoutDuration"):
                    lockoutDuration = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-PasswordSettingsPrecedence"):
                    precedence = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-PasswordComplexityEnabled"):
                    complexity = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-PasswordReversibleEncryptionEnabled"):
                    reverseibleEncryption = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-MinimumPasswordAge"):
                    minPassAge = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-MaximumPasswordAge"):
                    maxPassAge = attr["vals"][0]
                elif (str(attr["type"]) == "description"):
                    description = attr["vals"][0]
                elif (str(attr["type"])) == "msDS-PSOAppliesTo":
                    policyApplies = ""
                    for value in attr["vals"]:
                        policyApplies = policyApplies+value+";"
            context.log.highlight("Policy Name: " + str(policyName))
            if description:
                context.log.highlight("Description: " + str(description))
            context.log.highlight("Minimum Password Length: " + str(passwordLength))
            context.log.highlight("Minimum Password History Length: " + str(passwordhistorylength))
            context.log.highlight("Lockout Threshold: " + str(lockoutThreshold))
            context.log.highlight("Observation Window: " + clock(int(str(obersationWindow))))
            context.log.highlight("Lockout Duration: " + clock(int(str(lockoutDuration))))
            context.log.highlight("Complexity Enabled: " + str(complexity))
            context.log.highlight("Minimum Password Age " + clock(int(str(minPassAge))))
            context.log.highlight("Maximum Password Age: " + clock(int(str(maxPassAge))))
            context.log.highlight("Reversible Encryption: " + str(reverseibleEncryption))
            context.log.highlight("Precedence: " + str(precedence) + " (Lower is Higher Priority)")
            context.log.highlight("Policy Applies to: ")
            for obj in str(policyApplies)[:-1].split(";"):
                context.log.highlight("\t"+str(obj))
            context.log.highlight("")


def clock(ldap_time):
    fmt = "%d days %H hours %M minutes %S seconds"
    epoch = datetime(1601, 1, 1) + timedelta(seconds=int(ldap_time) / 10000000)
    return epoch.strftime(fmt)
