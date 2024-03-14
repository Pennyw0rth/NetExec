#!/usr/bin/env python3

from datetime import datetime, timedelta
from nxc.paths import NXC_PATH
import socket


class NXCModule:
    """
    Extract obsolete operating systems from LDAP
    Module by Brandon Fisher @shad0wcntr0ller
    """
    name = "obsolete"
    description = "Extract all obsolete operating systems from LDAP"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = True

    def ldap_time_to_datetime(self, ldap_time):
        """Convert an LDAP timestamp to a datetime object."""
        if ldap_time == "0":  # Account for never-set passwords
            return "Never"
        try:
            epoch = datetime(1601, 1, 1) + timedelta(seconds=int(ldap_time) / 10000000)
            return epoch.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Conversion Error"

    def options(self, context, module_options):
        """No module-specific options required."""

    def on_login(self, context, connection):
        search_filter = ("(&(objectclass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                         "(|(operatingSystem=*Windows 6*)(operatingSystem=*Windows 2000*)"
                         "(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)"
                         "(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)"
                         "(operatingSystem=*Windows 8.1*)(operatingSystem=*Windows Server 2003*)"
                         "(operatingSystem=*Windows Server 2008*)(operatingSystem=*Windows Server 2012*)))")
        attributes = ["name", "operatingSystem", "dNSHostName", "pwdLastSet"]

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldapConnection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except Exception:
            context.log.error("LDAP search error:", exc_info=True)
            return False

        answers = []
        context.log.debug(f"Total of records returned {len(resp)}")

        for item in resp:
            if "attributes" not in item:
                continue
            dns_hostname, pwd_last_set = "", "0"  # Default '0' for pwdLastSet
            for attribute in item["attributes"]:
                attr_type = str(attribute["type"])
                if attr_type == "operatingSystem":
                    os = str(attribute["vals"][0])
                elif attr_type == "dNSHostName":
                    dns_hostname = str(attribute["vals"][0])
                elif attr_type == "pwdLastSet":
                    pwd_last_set = str(attribute["vals"][0])

            if dns_hostname and os:
                pwd_last_set_readable = self.ldap_time_to_datetime(pwd_last_set)
                try:
                    ip_address = socket.gethostbyname(dns_hostname)
                    answers.append((dns_hostname, ip_address, os, pwd_last_set_readable))
                except socket.gaierror:
                    answers.append((dns_hostname, "N/A", os, pwd_last_set_readable))

        if answers:
            obsolete_hosts_count = len(answers)
            filename = f"{NXC_PATH}/logs/{connection.domain}.obsoletehosts.txt"
            context.log.display(f"{obsolete_hosts_count} Obsolete hosts will be saved to {filename}")
            with open(filename, "w") as f:
                for dns_hostname, ip_address, os, pwd_last_set_readable in answers:
                    log_message = f"{dns_hostname} ({ip_address}) : {os} [pwd-last-set: {pwd_last_set_readable}]"
                    context.log.highlight(log_message)
                    f.write(log_message + "\n")
        else:
            context.log.display("No Obsolete Hosts Identified")

        return True
