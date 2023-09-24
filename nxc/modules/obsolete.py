#!/usr/bin/env python3
# -*- coding: utf-8 -*-



class CMEModule:
    '''
    Extract obsolete operating systems from LDAP
    Module by Brandon Fisher @shad0wcntr0ller
    '''
    name = 'obsolete'
    description = 'Extract all obsolete operating systems from LDAP'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        search_filter = ("(&(objectclass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                         "(|(operatingSystem=*Windows 6*)(operatingSystem=*Windows 2000*)"
                         "(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)"
                         "(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)"
                         "(operatingSystem=*Windows 8.1*)(operatingSystem=*Windows Server 2003*)"
                         "(operatingSystem=*Windows Server 2008*)))")
        attributes = ['name', 'operatingSystem', 'dNSHostName']

        try:
            context.log.debug(f'Search Filter={search_filter}')
            resp = connection.ldapConnection.search(searchFilter=search_filter, attributes=attributes, sizeLimit=0)
        except ldap_impacket.LDAPSearchError as e:
            if 'sizeLimitExceeded' in e.getErrorString():
                context.log.debug('sizeLimitExceeded exception caught, processing the data received')
                resp = e.getAnswers()
            else:
                context.log.debug(e)
                return False

        answers = []
        context.log.debug(f'Total of records returned {len(resp)}')
        
        for item in resp:
            if not isinstance(item, ldapasn1_impacket.SearchResultEntry):
                continue
            try:
                name, os, dns_hostname = '', '', ''
                for attribute in item['attributes']:
                    attr_type = str(attribute['type'])
                    if attr_type == 'name':
                        name = str(attribute['vals'][0])
                    elif attr_type == 'operatingSystem':
                        os = str(attribute['vals'][0])
                    elif attr_type == 'dNSHostName':
                        dns_hostname = str(attribute['vals'][0])

                if dns_hostname and os:
                    answers.append([dns_hostname, os])
            except Exception as e:
                context.log.debug("Exception encountered:", exc_info=True)
                context.log.debug(f'Skipping item, cannot process due to error {str(e)}')

        if answers:
            
            hostname_parts = answers[0][0].split('.')
            domain = ".".join(hostname_parts[1:])
            
            home = Path.home()
            cme_path = home / ".cme"
            logs_path = cme_path / 'logs'
            filename = logs_path / f'{domain}.obsoletehosts.txt'
            
            context.log.display(f'Obsolete hosts will be saved to {filename}')
            context.log.success('Found the following obsolete operating systems:')
            
            for answer in answers:
                try:
                    ip_address = socket.gethostbyname(answer[0])
                except socket.gaierror:
                    ip_address = "N/A"

                context.log.highlight(f'{answer[0]} -> {ip_address} -> {answer[1]} ')
                with open(filename, 'a') as f:
                    f.write(f'{answer[0]}\n')
        else:
            context.log.display("No Obsolete Hosts Identified")

        return True
