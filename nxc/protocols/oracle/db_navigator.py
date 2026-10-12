from nxc.nxcdb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_creds(self, creds):
        data = [["CredID", "Total Logins", "Username", "Password"]]
        for cred in creds:
            total_logins = self.db.get_loggedin_relations(cred_id=cred[0])
            data.append([cred[0], str(len(total_logins)) + " Host(s)", cred[1], cred[2]])
        print_table(data, title="Credentials")

    def display_hosts(self, hosts):
        data = [["HostID", "Total Users", "Host", "Port", "Instance", "Version"]]
        for h in hosts:
            total_users = self.db.get_loggedin_relations(host_id=h[0])
            data.append([h[0], str(len(total_users)) + " User(s)", h[1], h[2], h[3], h[4]])
        print_table(data, title="Hosts")

    def do_hosts(self, line):
        filter_term = line.strip()
        if filter_term == "":
            self.display_hosts(self.db.get_hosts())
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)
            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [["HostID", "Host", "Port", "Instance", "Version"]]
                host_id_list = [h[0] for h in hosts]
                data += [[h[0], h[1], h[2], h[3], h[4]] for h in hosts]
                print_table(data, title="Host")

                login_data = [["CredID", "UserName", "Password"]]
                for host_id in host_id_list:
                    for link in self.db.get_loggedin_relations(host_id=host_id):
                        _, cred_id, _ = link
                        for cred in self.db.get_credentials(filter_term=cred_id):
                            cred_data = [cred[0], cred[1], cred[2]]
                            if cred_data not in login_data:
                                login_data.append(cred_data)
                if len(login_data) > 1:
                    print_table(login_data, title="Credential(s) with Logins")

    @staticmethod
    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'Host', 'Port', 'Instance', 'Version' |
        """
        print_help(help_string)

    def do_creds(self, line):
        filter_term = line.strip()
        if filter_term == "":
            self.display_creds(self.db.get_credentials())
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
            if len(creds) != 1:
                self.display_creds(creds)
            elif len(creds) == 1:
                cred_data = [["CredID", "UserName", "Password"]]
                cred_id_list = []
                for cred in creds:
                    cred_id_list.append(cred[0])
                    cred_data.append([cred[0], cred[1], cred[2]])
                print_table(cred_data, title="Credential(s)")

                access_data = [["HostID", "Host", "Port", "Instance", "Version"]]
                for cred_id in cred_id_list:
                    for link in self.db.get_loggedin_relations(cred_id=cred_id):
                        _, _, host_id = link
                        access_data += [[h[0], h[1], h[2], h[3], h[4]] for h in self.db.get_hosts(host_id)]
                if len(access_data) > 1:
                    print_table(access_data, title="Access to Host(s)")

    @staticmethod
    def help_creds(self):
        help_string = """
        creds [add|remove|filter_term]
        By default prints all creds
        Table format:
        | 'CredID', 'Total Logins', 'Username', 'Password' |
        Subcommands:
            add - format: "add username password"
            remove - format: "remove <credID>"
            filter_term - filters creds with filter_term
        """
        print_help(help_string)
