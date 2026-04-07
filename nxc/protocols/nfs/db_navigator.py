from nxc.nxcdb import DatabaseNavigator, print_help, print_table, write_csv


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

        for host in hosts:
            data.append([host[0], host[1], host[2], bool(host[3])])

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
                data = [["HostID", "Host", "Version", "Escape"]]
                for host in hosts:
                    data.append([host[0], host[1], host[2], bool(host[3])])
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
        filter_term = line.strip() or None
        shares = self.db.get_shares(filter_term=filter_term)

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

    def do_export(self, line):
        if not line:
            print("[-] not enough arguments")
            return
        line = line.split()
        command = line[0].lower()

        if command == "shares":
            if len(line) < 3:
                print("[-] invalid arguments, export shares <simple|detailed> <filename>")
                return

            filename = line[2]
            mode = line[1].lower()
            shares = self.db.get_shares()

            if mode == "simple":
                csv_header = ("id", "host", "read", "write", "exec", "storage", "share", "access")
                write_csv(filename, csv_header, shares)
                print("[+] NFS shares exported")
            elif mode == "detailed":
                csv_header = ("id", "host", "version", "read", "write", "exec", "storage", "share", "access")
                formatted = []
                for row in shares:
                    host_row = self.db.get_hosts(row[1])
                    entry = (
                        row[0],  # id
                        row[1],  # host
                        host_row[0][2] if host_row else "",  # version
                        row[2],  # read
                        row[3],  # write
                        row[4],  # exec
                        row[5],  # storage
                        row[6],  # share
                        row[7],  # access
                    )
                    formatted.append(entry)
                write_csv(filename, csv_header, formatted)
                print("[+] NFS shares exported")
            else:
                print(f"[-] No such export option: {line[1]}")
        else:
            print(f"[-] Export command '{command}' is not supported for NFS. Supported: shares")

    def help_export(self):
        help_string = """
        export shares <simple|detailed> <filename>
            simple   - exports: id, host, read, write, exec, storage, share, access
            detailed - exports: id, host, version, read, write, exec, storage, share, access
        """
        print_help(help_string)
