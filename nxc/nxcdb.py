import cmd
import csv
import sys
import os
import argparse
from os import listdir
from os.path import exists
from os.path import join as path_join
from textwrap import dedent
from requests import get, post, ConnectionError
from terminaltables import AsciiTable
from termcolor import colored

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.paths import CONFIG_PATH, WORKSPACE_DIR
from nxc.database import create_db_engine, open_config, get_workspace, get_db, write_configfile, create_workspace, set_workspace


class UserExitedProto(Exception):
    pass


def print_table(data, title=None):
    print()
    table = AsciiTable(data)
    if title:
        table.title = title
    print(table.table)
    print()


def write_csv(filename, headers, entries):
    """Writes a CSV file with the provided parameters."""
    with open(os.path.expanduser(filename), "w") as export_file:
        csv_file = csv.writer(
            export_file,
            delimiter=";",
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
            escapechar="\\",
        )
        csv_file.writerow(headers)
        for entry in entries:
            csv_file.writerow(entry)


def write_list(filename, entries):
    """Writes a file with a simple list"""
    with open(os.path.expanduser(filename), "w") as export_file:
        for line in entries:
            export_file.write(line + "\n")


def complete_import(text, line):
    """Tab-complete 'import' commands"""
    commands = ("empire", "metasploit")
    mline = line.partition(" ")[2]
    offs = len(mline) - len(text)
    return [s[offs:] for s in commands if s.startswith(mline)]


def complete_export(text, line):
    """Tab-complete 'creds' commands."""
    commands = (
        "creds",
        "plaintext",
        "hashes",
        "shares",
        "local_admins",
        "signing",
        "keys",
    )
    mline = line.partition(" ")[2]
    offs = len(mline) - len(text)
    return [s[offs:] for s in commands if s.startswith(mline)]


def print_help(help_string):
    print(dedent(help_string))


class DatabaseNavigator(cmd.Cmd):
    def __init__(self, main_menu, database, proto):
        cmd.Cmd.__init__(self)
        self.main_menu = main_menu
        self.config = main_menu.config
        self.proto = proto
        self.db = database
        self.prompt = f"nxcdb ({main_menu.workspace})({proto}) > "

    def do_exit(self, line):
        self.db.shutdown_db()
        sys.exit()

    @staticmethod
    def help_exit():
        help_string = """
        Exits
        """
        print_help(help_string)

    def do_back(self, line):
        raise UserExitedProto

    def do_export(self, line):
        if not line:
            print("[-] not enough arguments")
            return
        line = line.split()
        command = line[0].lower()
        # Need to use if/elif/else to keep compatibility with py3.8/3.9
        # Reference DB Function nxc/protocols/smb/database.py
        # Users
        if command == "creds":
            if len(line) < 3:
                print("[-] invalid arguments, export creds <simple|detailed|hashcat> <filename>")
                return

            filename = line[2]
            creds = self.db.get_credentials()
            csv_header = (
                "id",
                "domain",
                "username",
                "password",
                "credtype",
                "pillaged_from",
            )

            if line[1].lower() == "simple":
                write_csv(filename, csv_header, creds)
            elif line[1].lower() == "detailed":
                formatted_creds = []

                for cred in creds:
                    entry = [
                        cred[0],  # ID
                        cred[1],  # Domain
                        cred[2],  # Username
                        cred[3],  # Password/Hash
                        cred[4],  # Cred Type
                    ]
                    if cred[5] is None:
                        entry.append("")
                    else:
                        entry.append(self.db.get_hosts(cred[5])[0][2])
                    formatted_creds.append(entry)
                write_csv(filename, csv_header, formatted_creds)
            elif line[1].lower() == "hashcat":
                usernames = []
                passwords = []
                for cred in creds:
                    if cred[4] == "hash":
                        usernames.append(cred[2])
                        passwords.append(cred[3])
                output_list = [":".join(combination) for combination in zip(usernames, passwords)]
                write_list(filename, output_list)
            else:
                print(f"[-] No such export option: {line[1]}")
                return
            print("[+] Creds exported")
        # Hosts
        elif command == "hosts":
            if len(line) < 3:
                print("[-] invalid arguments, export hosts <simple|detailed|signing> <filename>")
                return

            csv_header_simple = (
                "id",
                "ip",
                "hostname",
                "domain",
                "os",
                "dc",
                "smbv1",
                "signing",
            )
            csv_header_detailed = (
                "id",
                "ip",
                "hostname",
                "domain",
                "os",
                "dc",
                "smbv1",
                "signing",
                "spooler",
                "zerologon",
                "petitpotam",
            )
            filename = line[2]

            if line[1].lower() == "simple":
                hosts = self.db.get_hosts()
                simple_hosts = [host[:8] for host in hosts]
                write_csv(filename, csv_header_simple, simple_hosts)
            # TODO: maybe add more detail like who is an admin on it, shares discovered, etc
            elif line[1].lower() == "detailed":
                hosts = self.db.get_hosts()
                write_csv(filename, csv_header_detailed, hosts)
            elif line[1].lower() == "signing":
                hosts = self.db.get_hosts("signing")
                signing_hosts = [host[1] for host in hosts]
                write_list(filename, signing_hosts)
            else:
                print(f"[-] No such export option: {line[1]}")
                return
            print("[+] Hosts exported")
        # Shares
        elif command == "shares":
            if len(line) < 3:
                print("[-] invalid arguments, export shares <simple|detailed> <filename>")
                return

            shares = self.db.get_shares()
            csv_header = ("id", "host", "userid", "name", "remark", "read", "write")
            filename = line[2]

            if line[1].lower() == "simple":
                write_csv(filename, csv_header, shares)
                print("[+] shares exported")
            # Detailed view gets hostname, usernames, and true false statement
            elif line[1].lower() == "detailed":
                formatted_shares = []
                for share in shares:
                    user = self.db.get_users(share[2])[0]
                    share_host = self.db.get_hosts(share[1])[0][2] if self.db.get_hosts(share[1]) else "ERROR"

                    entry = (
                        share[0],  # shareID
                        share_host,  # hosts
                        f"{user[1]}\\{user[2]}",  # userID
                        share[3],  # name
                        share[4],  # remark
                        bool(share[5]),  # read
                        bool(share[6]),  # write
                    )
                    formatted_shares.append(entry)
                write_csv(filename, csv_header, formatted_shares)
                print("[+] Shares exported")
            else:
                print(f"[-] No such export option: {line[1]}")
                return
        # Local Admin
        elif command == "local_admins":
            if len(line) < 3:
                print("[-] invalid arguments, export local_admins <simple|detailed> <filename>")
                return

            # These values don't change between simple and detailed
            local_admins = self.db.get_admin_relations()
            csv_header = ("id", "userid", "host")
            filename = line[2]

            if line[1].lower() == "simple":
                write_csv(filename, csv_header, local_admins)
            elif line[1].lower() == "detailed":
                formatted_local_admins = []
                for entry in local_admins:
                    user = self.db.get_users(filter_term=entry[1])[0]

                    formatted_entry = (
                        entry[0],  # Entry ID
                        f"{user[1]}/{user[2]}",  # DOMAIN/Username
                        self.db.get_hosts(filter_term=entry[2])[0][2],  # Hostname
                    )
                    # Can't modify a tuple which is what self.db.get_admin_relations() returns
                    formatted_local_admins.append(formatted_entry)
                write_csv(filename, csv_header, formatted_local_admins)
            else:
                print(f"[-] No such export option: {line[1]}")
                return
            print("[+] Local Admins exported")
        elif command == "dpapi":
            if len(line) < 3:
                print("[-] invalid arguments, export dpapi <simple|detailed> <filename>")
                return

            # These values don't change between simple and detailed
            dpapi_secrets = self.db.get_dpapi_secrets()
            csv_header = (
                "id",
                "host",
                "dpapi_type",
                "windows_user",
                "username",
                "password",
                "url",
            )
            filename = line[2]

            if line[1].lower() == "simple":
                write_csv(filename, csv_header, dpapi_secrets)
            elif line[1].lower() == "detailed":
                formatted_dpapi_secret = []
                for entry in dpapi_secrets:
                    formatted_entry = (
                        entry[0],  # Entry ID
                        self.db.get_hosts(filter_term=entry[1])[0][2],  # Hostname
                        entry[2],  # DPAPI type
                        entry[3],  # Windows User
                        entry[4],  # Username
                        entry[5],  # Password
                        entry[6],  # URL
                    )
                    # Can't modify a tuple which is what self.db.get_admin_relations() returns
                    formatted_dpapi_secret.append(formatted_entry)
                write_csv(filename, csv_header, formatted_dpapi_secret)
            else:
                print(f"[-] No such export option: {line[1]}")
                return
            print("[+] DPAPI secrets exported")
        elif command == "keys":
            keys = self.db.get_keys() if line[1].lower() == "all" else self.db.get_keys(key_id=int(line[1]))
            writable_keys = [key[2] for key in keys]
            filename = line[2]
            write_list(filename, writable_keys)
        elif command == "wcc":
            if len(line) < 3:
                print("[-] invalid arguments, export wcc <simple|detailed> <filename>")
                return

            csv_header_simple = (
                "id",
                "ip",
                "hostname",
                "check",
                "status",
            )
            csv_header_detailed = ("id", "ip", "hostname", "check", "description", "status", "reasons")
            filename = line[2]
            host_mapping = {}
            check_mapping = {}

            hosts = self.db.get_hosts()
            checks = self.db.get_checks()
            check_results = self.db.get_check_results()
            rows = []

            for result_id, hostid, checkid, secure, reasons in check_results:
                row = [result_id]
                if hostid in host_mapping:
                    row.extend(host_mapping[hostid])
                else:
                    for host_id, ip, hostname, _, _, _, _, _, _, _, _ in hosts:
                        if host_id == hostid:
                            row.extend([ip, hostname])
                            host_mapping[hostid] = [ip, hostname]
                            break
                if checkid in check_mapping:
                    row.extend(check_mapping[checkid])
                else:
                    for check in checks:
                        check_id, name, description = check
                        if check_id == checkid:
                            row.extend([name, description])
                            check_mapping[checkid] = [name, description]
                            break
                row.extend(("OK" if secure else "KO", reasons))
                rows.append(row)

            if line[1].lower() == "simple":
                simple_rows = [(row[0], row[1], row[2], row[3], row[5]) for row in rows]
                write_csv(filename, csv_header_simple, simple_rows)
            elif line[1].lower() == "detailed":
                write_csv(filename, csv_header_detailed, rows)
            elif line[1].lower() == "signing":
                hosts = self.db.get_hosts("signing")
                signing_hosts = [host[1] for host in hosts]
                write_list(filename, signing_hosts)
            else:
                print(f"[-] No such export option: {line[1]}")
                return
            print("[+] WCC exported")
        else:
            print("[-] Invalid argument, specify creds, hosts, local_admins, shares, wcc or dpapi")

    @staticmethod
    def help_export():
        help_string = """
        export [creds|hosts|local_admins|shares|signing|keys] [simple|detailed|*] [filename]
        Exports information to a specified file
        
        * hosts has an additional third option from simple and detailed: signing - this simply writes a list of ips of
        hosts where signing is enabled
        * keys' third option is either "all" or an id of a key to export
            export keys [all|id] [filename]
        """
        print_help(help_string)

    def do_import(self, line):
        if not line:
            return

        if line == "empire":
            headers = {"Content-Type": "application/json"}
            # Pull the username and password from the config file
            payload = {
                "username": self.config.get("Empire", "username"),
                "password": self.config.get("Empire", "password"),
            }
            # Pull the host and port from the config file
            base_url = f"https://{self.config.get('Empire', 'api_host')}:{self.config.get('Empire', 'api_port')}"

            try:
                r = post(
                    base_url + "/api/admin/login",
                    json=payload,
                    headers=headers,
                    verify=False,
                )
                if r.status_code == 200:
                    token = r.json()["token"]
                    url_params = {"token": token}
                    r = get(
                        base_url + "/api/creds",
                        headers=headers,
                        params=url_params,
                        verify=False,
                    )
                    creds = r.json()

                    for cred in creds["creds"]:
                        if cred["credtype"] == "token" or cred["credtype"] == "krbtgt" or cred["username"].endswith("$"):
                            continue
                        self.db.add_credential(
                            cred["credtype"],
                            cred["domain"],
                            cred["username"],
                            cred["password"],
                        )
                    print("[+] Empire credential import successful")
                else:
                    print("[-] Error authenticating to Empire's RESTful API server!")
            except ConnectionError as e:
                print(f"[-] Unable to connect to Empire's RESTful API server: {e}")


class NXCDBMenu(cmd.Cmd):
    def __init__(self, config_path):
        cmd.Cmd.__init__(self)
        self.config_path = config_path
        self.conn = None
        self.p_loader = ProtocolLoader()
        self.protocols = self.p_loader.get_protocols()

        self.config = open_config(self.config_path)
        self.workspace = get_workspace(self.config)
        self.db = get_db(self.config)
        self.do_workspace(self.workspace)

    def do_proto(self, proto):
        if not proto:
            return

        proto_db_path = path_join(WORKSPACE_DIR, self.workspace, f"{proto}.db")
        if exists(proto_db_path):
            self.conn = create_db_engine(proto_db_path)
            db_nav_object = self.p_loader.load_protocol(self.protocols[proto]["nvpath"])
            db_object = self.p_loader.load_protocol(self.protocols[proto]["dbpath"])
            self.config.set("nxc", "last_used_db", proto)
            write_configfile(self.config, self.config_path)
            try:
                proto_menu = db_nav_object.navigator(self, db_object.database(self.conn), proto)
                proto_menu.cmdloop()
            except UserExitedProto:
                pass

    @staticmethod
    def help_proto():
        help_string = """
        proto [smb|mssql|winrm]
            *unimplemented protocols: ftp, rdp, ldap, ssh
        Changes nxcdb to the specified protocol
        """
        print_help(help_string)

    def do_workspace(self, line):
        line = line.strip()
        if not line:
            subcommand = ""
            self.help_workspace()
        else:
            subcommand = line.split()[0]

        if subcommand == "create":
            new_workspace = line.split()[1].strip()
            print(f"[*] Creating workspace '{new_workspace}'")
            create_workspace(new_workspace, self.p_loader)
            self.do_workspace(new_workspace)
        elif subcommand == "list":
            print("[*] Enumerating Workspaces")
            for workspace in listdir(path_join(WORKSPACE_DIR)):
                if workspace == self.workspace:
                    print(f" * {colored(workspace, 'green')}")
                else:
                    print(f"   {workspace}")
        elif exists(path_join(WORKSPACE_DIR, line)):
            self.config.set("nxc", "workspace", line)
            write_configfile(self.config, self.config_path)
            self.workspace = line
            self.prompt = f"nxcdb ({line}) > "

    @staticmethod
    def help_workspace():
        help_string = """
        workspace [create <targetName> | workspace list | workspace <targetName>]
        """
        print_help(help_string)

    @staticmethod
    def do_exit(line):
        sys.exit()

    @staticmethod
    def do_EOF(line):
        sys.exit()


    @staticmethod
    def help_exit():
        help_string = """
        Exits
        """
        print_help(help_string)
    

def main():
    if not exists(CONFIG_PATH):
        print("[-] Unable to find config file")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="NXCDB is a database navigator for NXC",
    )
    parser.add_argument(
        "-gw",
        "--get-workspace",
        action="store_true",
        help="get the current workspace",
    )
    parser.add_argument(
        "-cw",
        "--create-workspace",
        help="create a new workspace",
    )
    parser.add_argument(
        "-sw",
        "--set-workspace",
        help="set the current workspace",
    )
    args = parser.parse_args()

    if args.create_workspace:
        create_workspace(args.create_workspace)
        sys.exit()
    if args.set_workspace:
        set_workspace(CONFIG_PATH, args.set_workspace)
        sys.exit()
    if args.get_workspace:
        current_workspace = get_workspace(open_config(CONFIG_PATH))
        for workspace in listdir(path_join(WORKSPACE_DIR)):
            if workspace == current_workspace:
                print(f" * {colored(workspace, 'green')}")
            else:
                print(f"   {workspace}")
        sys.exit()

    try:
        nxcdbnav = NXCDBMenu(CONFIG_PATH)
        nxcdbnav.cmdloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
