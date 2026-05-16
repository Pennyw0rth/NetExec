from nxc.nxcdb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [["CredID", "Total Logins", "Username", "Password"]]
        for cred in creds:
            total_users = self.db.get_loggedin_relations(cred_id=cred[0])
            data.append([
                cred[0],
                f"{len(total_users)} Host(s)",
                cred[1],
                cred[2],
            ])
        print_table(data, title="Credentials")

    def display_hosts(self, hosts):
        data = [["HostID", "Host", "Port", "Scheme", "URL", "Status", "Server", "Title", "Technologies"]]
        data.extend([[h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]] for h in hosts])
        print_table(data, title="Hosts")

    def do_hosts(self, line):
        filter_term = line.strip()
        if filter_term == "":
            hosts = self.db.get_hosts()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)
            self.display_hosts(hosts)

    @staticmethod
    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'Host', 'Port', 'Scheme', 'URL', 'Status', 'Server', 'Title', 'Technologies' |
        """
        print_help(help_string)

    def do_creds(self, line):
        filter_term = line.strip()
        if filter_term == "":
            creds = self.db.get_credentials()
            self.display_creds(creds)
        elif filter_term.split()[0].lower() == "add":
            args = filter_term.split()[1:]
            if len(args) == 2:
                username, password = args
                self.db.add_credential(username, password)
            else:
                print("[!] Format is 'add username password'")
        elif filter_term.split()[0].lower() == "remove":
            args = filter_term.split()[1:]
            if len(args) != 1:
                print("[!] Format is 'remove <credID>'")
            else:
                self.db.remove_credentials(args)
        else:
            creds = self.db.get_credentials(filter_term=filter_term)
            self.display_creds(creds)

    def help_creds(self):
        help_string = """
        creds [add|remove|filter_term]
        By default prints all creds
        """
        print_help(help_string)

    def do_probes(self, line):
        filter_term = line.strip()
        host_id = None
        if filter_term:
            try:
                host_id = int(filter_term)
            except ValueError:
                hosts = self.db.get_hosts(filter_term=filter_term)
                if len(hosts) == 1:
                    host_id = hosts[0].id
                else:
                    print(f"[!] '{filter_term}' did not resolve to a single host")
                    return
        probes = self.db.get_probes(host_id=host_id)
        if not probes:
            print("No probes recorded")
            return
        data = [["ProbeID", "HostID", "Path", "Label", "Status", "Title"]]
        data.extend([[p.id, p.hostid, p.path, p.label, p.status_code, p.title or ""] for p in probes])
        print_table(data, title="Probes")

    @staticmethod
    def help_probes(self):
        help_string = """
        probes [host_id|filter_term]
        Lists confirmed service probe matches recorded by the http_services module.
        """
        print_help(help_string)

    def do_clear_database(self, line):
        if input("This will destroy all data in the current database, are you SURE you want to run this? (y/n): ") == "y":
            self.db.clear_database()

    @staticmethod
    def help_clear_database(self):
        help_string = """
        clear_database
        THIS COMPLETELY DESTROYS ALL DATA IN THE CURRENTLY CONNECTED DATABASE
        """
        print_help(help_string)
