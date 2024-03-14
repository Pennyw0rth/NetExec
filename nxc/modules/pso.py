#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
from dateutil.relativedelta import relativedelta as rd
import argparse
import time

class NXCModule:
    """
    Initial FGPP/PSO script written by @n00py: https://github.com/n00py/GetFGPP

    Module by @_sandw1ch
    """
    name = "PSO"
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

        # Set some variables
        self.__domain = connection.domain
        self.__kdcHost = (f'{connection.hostname}.{connection.domain}')
        self.__username = connection.username
        self.__password = connection.password

        # Are there even any FGPPs?
        context.log.success("Attempting to enumerate policies...")
        resp = connection.ldapConnection.search(searchBase="CN=Password Settings Container,CN=System,"+ base_creator(self.__domain), searchFilter="(objectclass=*)")
        if len(resp) > 1:
            context.log.highlight(str(len(resp) - 1) + " PSO Objects found!")
            context.log.highlight("")
            context.log.success("Attempting to enumerate objects with an applied policy...")

        # Who do they apply to?
        resp=connection.search(searchFilter="(objectclass=*)",attributes=["DistinguishedName","msDS-PSOApplied"])
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
                        policies=""
                        for value in attr["vals"]:
                            policies=policies+value+";"
                        context.log.highlight("Applied Policy: ")
                        for object in str(policies)[:-1].split(";"):
                            context.log.highlight("\t"+str(object))
                        context.log.highlight("")

        # Let"s find out even more details!
        context.log.success("Attempting to enumerate details...\n")
        resp=connection.search(searchFilter="(objectclass=msDS-PasswordSettings)",
                     attributes=["name", "msds-lockoutthreshold", "msds-psoappliesto", "msds-minimumpasswordlength",
                                 "msds-passwordhistorylength", "msds-lockoutobservationwindow", "msds-lockoutduration",
                                 "msds-passwordsettingsprecedence", "msds-passwordcomplexityenabled", "Description",
                                 "msds-passwordreversibleencryptionenabled","msds-minimumpasswordage","msds-maximumpasswordage"])
        for i in resp:
            if isinstance(i, ldapasn1_impacket.SearchResultEntry) is not True:
                continue
            policyName,description,passwordLength,passwordhistorylength,lockoutThreshold,obersationWindow,lockoutDuration,complexity,minPassAge,maxPassAge,reverseibleEncryption,precedence,policyApplies=("",)*13
            for attr in i["attributes"]:
                if (str(attr["type"]) == "name"):
                    name = attr["vals"][0]
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
                    reverseibleEncryption= attr["vals"][0]
                elif (str(attr["type"]) == "msDS-MinimumPasswordAge"):
                    minPassAge = attr["vals"][0]
                elif (str(attr["type"]) == "msDS-MaximumPasswordAge"):
                    maxPassAge = attr["vals"][0]
                elif (str(attr["type"]) == "description"):
                    description = attr["vals"][0]
                elif (str(attr["type"])) == "msDS-PSOAppliesTo":
                    policyApplies = ""
                    for value in attr["vals"]:
                        policyApplies=policyApplies+value+";"
            context.log.highlight("Policy Name: " + str(name))
            if description != "":
                context.log.highlight("Description: " + str(description))
            context.log.highlight("Minimum Password Length: " + str(passwordLength))
            context.log.highlight("Minimum Password History Length: " + str(passwordhistorylength))
            context.log.highlight("Lockout Threshold: " + str(lockoutThreshold))
            context.log.highlight("Observation Window: "  + clock(int(str(obersationWindow))))
            context.log.highlight("Lockout Duration: "  + clock(int(str(lockoutDuration))))
            context.log.highlight("Complexity Enabled: " + str(complexity))
            context.log.highlight("Minimum Password Age "+ clock(int(str(minPassAge))))
            context.log.highlight("Maximum Password Age: " + clock(int(str(maxPassAge))))
            context.log.highlight("Reversible Encryption: " + str(reverseibleEncryption))
            context.log.highlight("Precedence: " + str(precedence)+ " (Lower is Higher Priority)")
            context.log.highlight("Policy Applies to: ")
            for object in str(policyApplies)[:-1].split(";"):
                context.log.highlight("\t"+str(object))
            context.log.highlight("")

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += (f'DC={b},')
    return search_base[:-1]

def clock(nano):
    fmt = "{0.days} days {0.hours} hours {0.minutes} minutes {0.seconds} seconds"
    sec = int(abs(nano/10000000))
    return fmt.format(rd(seconds=sec))
