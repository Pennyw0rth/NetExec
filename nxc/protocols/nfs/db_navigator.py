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

        if command == "hosts":
            if len(line) < 2:
                print("[-] invalid arguments, export hosts <filename>")
                return
            filename = line[2]
            hosts = self.db.get_hosts()
            csv_header = ("id", "ip", "hostname", "port", "version", "root_escape")
            write_csv(filename, csv_header, hosts)
            print("[+] NFS hosts exported")
        elif command == "shares":
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
                # hosts columns: (id, ip, hostname, port, nfs_version, root_escape)
                version_by_ip = {host[1]: host[4] for host in self.db.get_hosts()}
                formatted = []
                for row in shares:
                    entry = (
                        row[0],  # id
                        row[1],  # host
                        version_by_ip.get(row[1], ""),  # nfs_version
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
            print(f"[-] Export command '{command}' is not supported for NFS. Supported: hosts, shares")

    def help_export(self):
        help_string = """
        export hosts <filename>
            exports: id, ip, hostname, port, version, root_escape
        export shares <simple|detailed> <filename>
            simple   - exports: id, host, read, write, exec, storage, share, access
            detailed - exports: id, host, version, read, write, exec, storage, share, access
        """
        print_help(help_string)
