import re
from nxc.helpers.misc import CATEGORY
from impacket.dcerpc.v5 import tsts as TSTS
from contextlib import suppress


class NXCModule:
    """
    Search for KeePass-related files and process

    Module by @d3lb3
    Inspired by @harmj0y https://raw.githubusercontent.com/GhostPack/KeeThief/master/PowerShell/KeePassConfig.ps1

    Refactored by @lodos2005
    """

    name = "keepass_discover"
    description = "Search for KeePass-related files and process."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.search_type = "DEFAULT"
        self.search_path = "Users,Program Files,Program Files (x86)"

    def options(self, context, module_options):
        r"""
        SEARCH_TYPE     Specify what to search, between:
                          PROCESS     Look for running KeePass.exe process only
                          FILES       Look for KeePass-related files in default locations
                          DEEP_FILES  Look for KeePass-related files by spidering SEARCH_PATH (slow)
                          DEFAULT     Look for running process and files in default locations (default)
                          ALL         Look for running process and deep search for files

        SEARCH_PATH     Comma-separated remote locations on C$ where to search for KeePass-related files (used by DEEP_FILES and ALL_DEEP).
                        Default: Users,Program Files,Program Files (x86)
        """
        if "SEARCH_PATH" in module_options:
            self.search_path = module_options["SEARCH_PATH"]

        if "SEARCH_TYPE" in module_options:
            self.search_type = module_options["SEARCH_TYPE"].upper()

    def on_admin_login(self, context, connection):
        if self.search_type in ("PROCESS", "DEFAULT", "ALL"):
            self.check_processes(context, connection)

        if self.search_type in ("FILES", "DEEP_FILES", "DEFAULT", "ALL"):
            self.fast_file_search(context, connection)

        if self.search_type in ("DEEP_FILES", "ALL"):
            self.deep_file_search(context, connection)

    def check_processes(self, context, connection):
        context.log.display("Searching for KeePass processes via Tasklist")
        try:
            with TSTS.LegacyAPI(connection.conn, connection.remoteName, kerberos=connection.kerberos) as legacy:
                handle = legacy.hRpcWinStationOpenServer()
                processes = legacy.hRpcWinStationGetAllProcesses(handle)

            if not processes:
                context.log.display("Could not enumerate processes, tasklist empty or error.")
            else:
                found_procs = [p for p in processes if p["ImageName"] and re.match(r"kee.*", p["ImageName"], re.IGNORECASE)]
                if found_procs:
                    for p in found_procs:
                        context.log.highlight(f'Found process "{p["ImageName"]}" with PID {p["UniqueProcessId"]} (user SID {p["pSid"]})')
                else:
                    context.log.display("No KeePass-related process was found")
        except Exception as e:
            context.log.fail(f"Error enumerating processes: {e}")

    def fast_file_search(self, context, connection):
        context.log.display("Searching for KeePass files in default locations (fast search)")

        known_paths = [
            r"Program Files\KeePass Password Safe 2\KeePass.config.xml",
            r"Program Files\KeePass Password Safe 2\KeePass.config.enforced.xml",
            r"Program Files (x86)\KeePass Password Safe 2\KeePass.config.xml",
            r"Program Files (x86)\KeePass Password Safe 2\KeePass.config.enforced.xml",
        ]

        user_folders = []
        try:
            users = connection.conn.listPath("C$", r"\Users\*")
            user_folders = [user.get_longname() for user in users if user.get_longname() not in (".", "..")]
        except Exception as e:
            context.log.debug(f"Could not list users from C$\\Users: {e}")

        for user in user_folders:
            known_paths.extend([
                rf"Users\{user}\AppData\Local\VirtualStore\Program Files\KeePass Password Safe 2\KeePass.config.xml",
                rf"Users\{user}\AppData\Roaming\KeePass\KeePass.config.xml",
                rf"Users\{user}\AppData\Local\KeePass\KeePass.config.xml",
                rf"Users\{user}\AppData\Roaming\KeePassDatabase\KeePass.config.xml",
                rf"Users\{user}\AppData\Roaming\KeePassDatabase\KeePass.config.enforced.xml",
                rf"Users\{user}\.config\KeePass\KeePass.config.xml"
            ])

        found_files = []
        for path in known_paths:
            with suppress(Exception):
                connection.conn.listPath("C$", path.replace("/", "\\"))
                full_path = f"C:\\{path}"
                found_files.append(full_path)

        for user in user_folders:
            for folder in ["Documents", "Desktop"]:
                try:
                    files = connection.spider("C$", folder=rf"Users\{user}\{folder}", pattern=["*.kdbx"], silent=True)
                    found_files.extend([f"C:\\{f}" for f in files])
                except Exception as e:
                    context.log.debug(f"Error spidering for .kdbx in C$\\Users\\{user}\\{folder}: {e}")
        if found_files:
            for f in found_files:
                context.log.highlight(f"Found {f}")
            found_xml = any(".config" in f for f in found_files)
            if not found_xml:
                context.log.fail("No config settings file found !!!")
        else:
            context.log.display("No KeePass-related files were found in default locations")

    def deep_file_search(self, context, connection):
        context.log.display(f"Searching for KeePass files on C$ in '{self.search_path}' (deep search)")

        paths = self.search_path.split(",")
        all_found_files = []

        for path in paths:
            folder_path = path.strip().replace("\\", "/")
            if folder_path.startswith("C:/"):
                folder_path = folder_path[3:]
            elif folder_path.startswith("/"):
                folder_path = folder_path[1:]

            try:
                found = connection.spider("C$", folder=folder_path, pattern=["KeePass.config.xml", "KeePass.exe", "*.kdbx"], silent=True)
                all_found_files.extend([f"C:\\{f}" for f in found])
            except Exception as e:
                context.log.debug(f"Error spidering {path} on C$: {e}")

        if all_found_files:
            found_xml = False
            for file_path in all_found_files:
                if "KeePass.config.xml" in file_path or "KeePass.config.enforced.xml" in file_path:
                    found_xml = True
                context.log.highlight(f"Found {file_path}")

            if not found_xml:
                context.log.fail("No config settings file found !!!")
        else:
            context.log.display("No KeePass-related files were found")
