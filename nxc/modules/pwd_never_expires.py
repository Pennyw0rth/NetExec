#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NXC module to list active accounts with "Password Never Expires"

from datetime import datetime, timedelta
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    """
    Extract all active user accounts with "Password Never Expires" attribute
    Module by: DaahtK
    """
    
    name = 'pwd_never_expires'
    description = 'List active user accounts with Password Never Expires enabled'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION
    
    def ldap_time_to_datetime(self, ldap_time):
        """Convert an LDAP timestamp to a datetime object."""
        if ldap_time == "0":
            return "Never"
        try:
            epoch = datetime(1601, 1, 1) + timedelta(seconds=int(ldap_time) / 10000000)
            return epoch.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Conversion Error"
    
    def options(self, context, module_options):
        """
        Module options:
        DETAILED    Show additional details (DN, whenCreated, lastLogon)
        """
        self.detailed = module_options.get('DETAILED', False)
    
    def on_login(self, context, connection):
        """Executed upon successful LDAP connection"""
        
        context.log.display("Search for accounts with 'Password Never Expires'...")
        
        
        search_filter = ("(&(objectClass=user)(objectCategory=person)"
                        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                        "(userAccountControl:1.2.840.113556.1.4.803:=65536))")
        
        # Attributes to retrieve
        attributes = ['sAMAccountName', 'userAccountControl', 'distinguishedName', 
                     'whenCreated', 'pwdLastSet', 'description']
        
        try:
            context.log.debug(f"Search Filter={search_filter}")
            
            # Executing the LDAP query
            resp = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0
            )
            
            context.log.debug(f"Total of records returned {len(resp)}")
            
            if not resp:
                context.log.display("No accounts found with Password Never Expires")
                return True
            
            accounts = []
            
            # Processing of results
            for item in resp:
                if "attributes" not in item:
                    continue
                
                account_data = {}
                
                for attribute in item["attributes"]:
                    attr_type = str(attribute["type"])
                    
                    if attr_type == "sAMAccountName":
                        account_data['username'] = str(attribute["vals"][0])
                    elif attr_type == "distinguishedName":
                        account_data['dn'] = str(attribute["vals"][0])
                    elif attr_type == "userAccountControl":
                        account_data['uac'] = int(attribute["vals"][0])
                    elif attr_type == "whenCreated":
                        account_data['created'] = str(attribute["vals"][0])
                    elif attr_type == "pwdLastSet" and attribute["vals"]:
                        pwd_last_set = str(attribute["vals"][0])
                        account_data['pwdLastSet'] = self.ldap_time_to_datetime(pwd_last_set)
                    elif attr_type == "description" and attribute["vals"]:
                        account_data['description'] = str(attribute["vals"][0])
                
                if 'username' in account_data:
                    accounts.append(account_data)
            
            # Saving and displaying results
            if accounts:
                account_count = len(accounts)
                filename = f"{NXC_PATH}/logs/{connection.domain}.pwd_never_expires.txt"
                context.log.display(f"{account_count} account(s) with Password Never Expires will be saved in {filename}")
                
                with open(filename, "w") as f:
                    for account in accounts:
                        username = account.get('username', 'N/A')
                        pwd_last_set = account.get('pwdLastSet', 'N/A')
                        
                        if self.detailed:
                            log_message = f"{username} [pwd-last-set: {pwd_last_set}]"
                            if 'description' in account:
                                log_message += f" - {account['description']}"
                            if 'dn' in account:
                                log_message += f"\n  DN: {account['dn']}"
                        else:
                            log_message = f"{username} [pwd-last-set: {pwd_last_set}]"
                        
                        context.log.highlight(log_message)
                        f.write(log_message + "\n")
            else:
                context.log.display("No accounts found with Password Never Expires")
        
        except Exception as e:
            context.log.error(f"Error during LDAP query: {str(e)}", exc_info=True)
            return False
        
        return True
