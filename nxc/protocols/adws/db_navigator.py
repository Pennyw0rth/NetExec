from nxc.helpers.misc import validate_ntlm
from nxc.nxcdb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_hosts(self, hosts):
        data = [["HostID", "IP", "Hostname", "Domain", "OS", "ADWS Reachable"]]

        for host in hosts:
            host_id = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            try:
                os = host[4].decode()
            except Exception:
                os = host[4]
            adws_reachable = host[5]

            data.append([host_id, ip, hostname, domain, os, adws_reachable])

        print_table(data, title="Hosts")

    def do_hosts(self, line):
        filter_term = line.strip()

        if filter_term == "":
            hosts = self.db.get_hosts()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)

            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [["HostID", "IP", "Hostname", "Domain", "OS", "ADWS Reachable"]]
                for host in hosts:
                    try:
                        os = host[4].decode()
                    except Exception:
                        os = host[4]
                    data.append([host[0], host[1], host[2], host[3], os, host[5]])
                print_table(data, title="Host")

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'IP', 'Hostname', 'Domain', 'OS', 'ADWS Reachable' |
        Subcommands:
            filter_term - filters hosts with filter_term
        """
        print_help(help_string)

    def display_creds(self, creds):
        data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
        data.extend([cred[0], cred[4], cred[1], cred[2], cred[3]] for cred in creds)
        print_table(data, title="Credentials")

    def do_creds(self, line):
        filter_term = line.strip()

        if filter_term == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "add":
            args = filter_term.split()[1:]
            if len(args) == 3:
                domain, username, password = args
                if validate_ntlm(password):
                    self.db.add_credential("hash", domain, username, password)
                else:
                    self.db.add_credential("plaintext", domain, username, password)
            else:
                print("[!] Format is 'add domain username password'")
        elif filter_term.split()[0].lower() == "remove":
            args = filter_term.split()[1:]
            if len(args) != 1:
                print("[!] Format is 'remove <credID>'")
            else:
                self.db.remove_credentials(args)
        elif filter_term.split()[0].lower() == "plaintext":
            creds = self.db.get_credentials(cred_type="plaintext")
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "hash":
            creds = self.db.get_credentials(cred_type="hash")
            self.display_creds(creds)
        else:
            creds = self.db.get_credentials(filter_term=filter_term)
            data = [["CredID", "CredType", "Domain", "UserName", "Password"]]
            data.extend([cred[0], cred[4], cred[1], cred[2], cred[3]] for cred in creds)
            print_table(data, title="Credential(s)")

    def help_creds(self):
        help_string = """
        creds [add|remove|plaintext|hash|filter_term]
        By default prints all creds
        Table format:
        | 'CredID', 'CredType', 'Domain', 'UserName', 'Password' |
        Subcommands:
            add - format: "add domain username password"
            remove - format: "remove <credID>"
            plaintext - prints plaintext creds
            hash - prints hashed creds
            filter_term - filters creds with filter_term
        """
        print_help(help_string)

    def do_clear_database(self, line):
        if input("This will destroy all data in the current database, are you SURE you want to run this? (y/n): ") == "y":
            self.db.clear_database()

    def help_clear_database(self):
        help_string = """
        clear_database
        THIS COMPLETELY DESTROYS ALL DATA IN THE CURRENTLY CONNECTED DATABASE
        YOU CANNOT UNDO THIS COMMAND
        """
        print_help(help_string)
