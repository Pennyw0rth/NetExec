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
                data = [["HostID", "IP", "Hostname", "Port", "Supported version", "Root escape"]]
                host_id_list = []
                print(hosts)
                for host in hosts:
                    host_id_list.append(host[0])
                    data.append([host[0], host[1], host[2], host[3], host[4], host[5]])

                print_table(data, title="Host(s)")

    def display_hosts(self, hosts):
        data = [["HostID", "IP", "Hostname", "Port", "Supported version", "Root escape"]]

        for host in hosts:
            host_id = host[0]
            ip = host[1]
            hostname = host[2]
            port = host[3]
            supported_version = host[4]
            root_escape = host[5]

            data.append([host_id, ip, hostname, port, supported_version, root_escape])
        print_table(data, title="Hosts")
