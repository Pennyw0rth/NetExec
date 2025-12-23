from nxc.nxcdb import DatabaseNavigator, print_table, print_help
from termcolor import colored
import functools

help_header = functools.partial(colored, color="cyan", attrs=["bold"])
help_kw = functools.partial(colored, color="green", attrs=["bold"])


class navigator(DatabaseNavigator):

    def help_hosts(self):
        help_string = """
        By default prints all hosts
        Table format:
        | 'HostID', 'IP', 'Port', 'Hostname', 'Domain', 'OS', 'NLA' |
        Subcommands:
            nla - list hosts with NLA disabled
         """
        print_help(help_string)

    def display_hosts(self, hosts):
        data = [
            [
                "HostID",
                "IP",
                "Port",
                "Hostname",
                "Domain",
                "OS",
                "NLA",
            ]
        ]

        for host in hosts:
            host_id = host[0]
            ip = host[1]
            port = host[2]
            hostname = host[3]
            domain = host[4]

            try:
                os = host[5].decode()
            except Exception:
                os = host[5]

            nla = host[6]

            data.append(
                [
                    host_id,
                    ip,
                    port,
                    hostname,
                    domain,
                    os,
                    nla
                ]
            )
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
                data = [
                    [
                        "HostID",
                        "IP",
                        "Port",
                        "Hostname",
                        "Domain",
                        "OS",
                        "NLA",
                    ]
                ]

                for host in hosts:
                    host_id = host[0]
                    ip = host[1]
                    port = host[2]
                    hostname = host[3]
                    domain = host[4]

                    try:
                        os = host[5].decode()
                    except Exception:
                        os = host[5]

                    nla = host[6]

                    data.append(
                        [
                            host_id,
                            ip,
                            port,
                            hostname,
                            domain,
                            os,
                            nla
                        ]
                    )
                print_table(data, title="Host")

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
