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

    def display_shares(self, shares):
        """
        shares: list of rows (tuples) -> expects columns:
        (id, host, read_perm, write_perm, exec_perm, storage, share, access)
        """
        data = [["ID", "Host", "R", "W", "X", "Storage", "Share", "Access"]]
        for row in shares:
            (
                sid, host, r, w, x,
                storage_str, share_path, access_str
            ) = row
            # boolean format
            data.append([
                sid, host,
                "True" if r else "False",
                "True" if w else "False",
                "True" if x else "False",
                storage_str,
                share_path,
                access_str,
            ])
        print_table(data, title="Shares")

    def do_shares(self, line):
        """
        Shares [host_filter]
        List shares, optionally filtreli olarak.
        """
        host_filter = line.strip()
        if host_filter:
            q = self.db.SharesTable.select().where(
                self.db.SharesTable.c.host.like(f"%{host_filter}%")
            )
            shares = self.db.db_execute(q).all()
        else:
            q = self.db.SharesTable.select()
            shares = self.db.db_execute(q).all()
        
        if shares:
            self.display_shares(shares)
        else:
            print("No shares found.")

    def help_shares(self):
        help_string = """
        shares [host_filter]
        Lists all shares. Optionally filters by host substring.
        Columns:
         ID, Host, Read (True/False), Write, Execute, Storage ("used / total"), Share path, Access list
        """
        print_help(help_string)