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
        data = [["HostID", "Host", "Version", "Escape"]]
        host_id_list = []

        for host in hosts:
            host_id = host[0]
            host_id_list.append(host_id)
            ip = host[1]
            version = host[2]
            escape = bool(host[3])

            data.append([host_id, ip, version, escape])
            
        print_table(data, title="Hosts")
    
    def do_hosts(self, line):
        filter_term = line.strip()

        if filter_term == "":
            hosts = self.db.get_hosts()
            self.display_hosts(hosts)
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)
            print(hosts)
            if len(hosts) > 1:
                self.display_hosts(hosts)
            elif len(hosts) == 1:
                data = [["HostID", "Host", "Version", "Escape"]]
                host_id_list = []

                for host in hosts:
                    host_id = host[0]
                    host_id_list.append(host_id)
                    ip = host[1]
                    version = host[2]
                    escape = bool(host[3])

                    data.append([host_id, ip, version, escape])
                print_table(data, title="Host")

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Table format:
        | 'HostID', 'Host', 'Version', 'Escape' |
        Subcommands:
        filter_term - filters hosts with filter_term
            If a single host is returned (e.g. `hosts 15`, it prints the following tables:
                Host | 'HostID', 'IP', 'Version', 'Escape' |
            Otherwise, it prints the default host table from a `like` query on the `ip` and `hostname` columns
        """
        print_help(help_string)