from nxc.nxcdb import DatabaseNavigator, print_table, print_help


class navigator(DatabaseNavigator):
    def display_hosts(self, hosts):
        data = [["HostID", "IP", "Hostname", "Domain", "OS", "DC"]]

        for host in hosts:
            host_id = host[0]
            ip = host[1]
            hostname = host[2]
            domain = host[3]
            os_info = host[4] if host[4] else ""
            dc = host[5] if len(host) > 5 else ""

            data.append([host_id, ip, hostname, domain, os_info, dc])
        print_table(data, title="Hosts")

    def display_users(self, users):
        data = [["UserID", "Domain", "Username", "CredType", "RID"]]

        for user in users:
            user_id = user[0]
            domain = user[1]
            username = user[2]
            credtype = user[4] if len(user) > 4 else ""
            rid = user[5] if len(user) > 5 else ""

            data.append([user_id, domain, username, credtype, rid])
        print_table(data, title="Users")

    def display_groups(self, groups):
        data = [["GroupID", "Domain", "Name", "RID", "Type"]]

        for group in groups:
            group_id = group[0]
            domain = group[1]
            name = group[2]
            rid = group[3] if len(group) > 3 else ""
            group_type = group[4] if len(group) > 4 else ""

            data.append([group_id, domain, name, rid, group_type])
        print_table(data, title="Groups")

    def display_shares(self, shares):
        data = [["ShareID", "HostID", "Name", "Type", "Remark"]]

        for share in shares:
            share_id = share[0]
            host_id = share[1]
            name = share[2]
            share_type = share[3] if len(share) > 3 else ""
            remark = share[4] if len(share) > 4 else ""

            data.append([share_id, host_id, name, share_type, remark])
        print_table(data, title="Shares")

    def do_hosts(self, line):
        filter_term = line.strip()
        if filter_term == "":
            hosts = self.db.get_hosts()
        else:
            hosts = self.db.get_hosts(filter_term=filter_term)
        self.display_hosts(hosts)

    def help_hosts(self):
        help_string = """
        hosts [filter_term]
        By default prints all hosts
        Can filter by IP address
        """
        print_help(help_string)

    def do_users(self, line):
        filter_term = line.strip()
        if filter_term == "":
            users = self.db.get_users()
        else:
            users = self.db.get_users(filter_term=filter_term)
        self.display_users(users)

    def help_users(self):
        help_string = """
        users [filter_term]
        By default prints all users
        Can filter by username
        """
        print_help(help_string)

    def do_groups(self, line):
        filter_term = line.strip()
        if filter_term == "":
            groups = self.db.get_groups()
        else:
            groups = self.db.get_groups(filter_term=filter_term)
        self.display_groups(groups)

    def help_groups(self):
        help_string = """
        groups [filter_term]
        By default prints all groups
        Can filter by group name
        """
        print_help(help_string)

    def do_shares(self, line):
        filter_term = line.strip()
        if filter_term == "":
            shares = self.db.get_shares()
        else:
            shares = self.db.get_shares(filter_term=filter_term)
        self.display_shares(shares)

    def help_shares(self):
        help_string = """
        shares [filter_term]
        By default prints all shares
        Can filter by share name
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
