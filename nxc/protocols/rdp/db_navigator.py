from nxc.nxcdb import DatabaseNavigator, print_help, print_table


class navigator(DatabaseNavigator):
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

    def display_hosts(self, hosts):
        data = [["HostID", "Host", "Hostname", "Port", "Domain", "Server OS", "NLA"]]
        host_id_list = []

        for row in hosts:
            print(row)
            host_id = row[0]
            host = row[1]
            hostname = row[2]
            port = row[3]
            domain = row[4]
            serveros = row[5]
            nla = bool(row[6])

            host_id_list.append(host_id)
            data.append([host_id, host, hostname, port, domain, serveros, nla])

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
                data = [["HostID", "Host", "Hostname", "Port", "Domain", "Server OS", "NLA"]]
                host_id_list = []

                for host in hosts:
                    host_id = host[0]
                    host_id_list.append(host_id)
                    host = host[1]
                    hostname = host[2]
                    port = host[3]
                    domain = host[4]
                    serveros = host[5]
                    nla = host[6]
                    
                    data.append([host_id, host, hostname, port, domain, serveros, nla])
                print_table(data, title="Host")

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'Host', 'Hostname', 'Port', 'Domain', 'Server OS', 'NLA' |
        Subcommands:
        filter_term - filters hosts with filter_term
            If a single host is returned (e.g. `hosts 15`, it prints the following tables:
                Host | 'HostID', 'Host', 'Hostname', 'Port', 'Domain', 'Server OS', 'NLA' |
            Otherwise, it prints the default host table from a `like` query on the `ip` and `hostname` columns
        """
        print_help(help_string)