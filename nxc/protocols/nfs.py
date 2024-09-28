from nxc.connection import connection
from nxc.logger import NXCAdapter
from pyNfsClient import Portmap, Mount, NFSv3, NFS_PROGRAM, NFS_V3, ACCESS3_READ, ACCESS3_MODIFY, ACCESS3_EXECUTE
import re
import uuid


class nfs(connection):
    def __init__(self, args, db, host):
        self.protocol = "nfs"
        self.port = 111
        self.portmap = None
        self.mnt_port = None
        self.mount = None
        self.auth = {
            "flavor": 1,
            "machine_name": uuid.uuid4().hex.upper()[0:6],
            "uid": 0,
            "gid": 0,
            "aux_gid": [],
        }
        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "NFS",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def create_conn_obj(self):
        """Initializes and connects to the portmap and mounted folder"""
        try:
            # Portmap Initialization
            self.portmap = Portmap(self.host, timeout=self.args.nfs_timeout)
            self.portmap.connect()

            # Mount Initialization
            self.mnt_port = self.portmap.getport(Mount.program, Mount.program_version)
            self.mount = Mount(host=self.host, port=self.mnt_port, timeout=self.args.nfs_timeout, auth=self.auth)
            self.mount.connect()

            # Change logging port to the NFS port
            self.port = self.mnt_port
            self.proto_logger()
        except Exception as e:
            self.logger.fail(f"Error during Initialization: {e}")
            return False
        return True

    def enum_host_info(self):
        try:
            # Dump all registered programs
            programs = self.portmap.dump()

            self.nfs_versions = set()
            for program in programs:
                if program["program"] == NFS_PROGRAM:
                    self.nfs_versions.add(program["version"])
            return self.nfs_versions
        except Exception as e:
            self.logger.debug(f"Error checking NFS version: {self.host} {e}")

    def print_host_info(self):
        self.logger.display(f"Target supported NFS versions: ({', '.join(str(x) for x in self.nfs_versions)})")
        return True

    def disconnect(self):
        """Disconnect mount and portmap if they are connected"""
        try:
            self.mount.disconnect()
            self.portmap.disconnect()
            self.logger.info(f"Disconnect successful: {self.host}:{self.port}")
        except Exception as e:
            self.logger.fail(f"Error during disconnect: {e}")

    def list_dir(self, nfs, file_handle, path, recurse=1):
        """Process entries in NFS directory recursively"""
        def process_entries(entries, path, recurse):
            try:
                contents = []
                for entry in entries:
                    if "name" in entry and entry["name"] not in [b".", b".."]:
                        item_path = f'{path}/{entry["name"].decode("utf-8")}'  # Constructing file path
                        if entry.get("name_attributes", {}).get("present", False):
                            entry_type = entry["name_attributes"]["attributes"].get("type")
                            if entry_type == 2 and recurse > 0:  # Recursive directory listing. Entry type shows file format. 1 is file, 2 is folder.
                                dir_handle = entry["name_handle"]["handle"]["data"]
                                contents += self.list_dir(nfs, dir_handle, item_path, recurse=recurse - 1)
                            else:
                                contents.append(item_path)

                    if entry["nextentry"]:
                        # Processing next entries recursively
                        contents += process_entries(entry["nextentry"], path, recurse)

                return contents
            except Exception as e:
                self.logger.debug(f"Error on Listing Entries for NFS Shares: {self.host}:{self.port} {e}")

        if recurse == 0:
            return [path + "/"]

        items = self.nfs3.readdirplus(file_handle, auth=self.auth)
        if "resfail" in items:
            raise Exception("Insufficient Permissions")
        else:
            entries = items["resok"]["reply"]["entries"]

        return process_entries(entries, path, recurse)

    def export_info(self, export_nodes):
        """Enumerates all NFS shares and their access range"""
        result = []
        for node in export_nodes:
            ex_dir = node.ex_dir.decode()
            # Collect the names of the groups associated with this export node
            group_names = self.group_names(node.ex_groups)
            result.append(f"{ex_dir} {', '.join(group_names)}")

            # If there are more export nodes, process them recursively. More than one share.
            if node.ex_next:
                result.extend(self.export_info(node.ex_next))
        return result

    def group_names(self, groups):
        """Enumerates all access range of the share(s)"""
        result = []
        for group in groups:
            result.append(group.gr_name.decode())

            # If there are more IP's, process them recursively.
            if group.gr_next:
                result.extend(self.group_names(group.gr_next))

        return result

    def shares(self):
        self.auth["uid"] = self.args.shares
        self.logger.display(f"Enumerating NFS Shares with UID {self.args.shares}")
        try:
            # Connect to NFS
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            output_export = str(self.mount.export())
            reg = re.compile(r"ex_dir=b'([^']*)'")
            shares = list(reg.findall(output_export))

            # Mount shares and check permissions
            self.logger.highlight(f"{'Permissions':<15}{'Share':<15}")
            self.logger.highlight(f"{'-----------':<15}{'-----':<15}")
            for share in shares:
                try:
                    mnt_info = self.mount.mnt(share, self.auth)
                    file_handle = mnt_info["mountinfo"]["fhandle"]

                    read_perm, write_perm, exec_perm = self.get_permissions(file_handle)
                    self.mount.umnt(self.auth)
                    self.logger.highlight(f"{'r' if read_perm else '-'}{'w' if write_perm else '-'}{('x' if exec_perm else '-'):<12} {share:<15}")
                except Exception as e:
                    self.logger.fail(f"{share} - {e}")
                    self.logger.highlight(f"{'---':<15}{share:<15}")

        except Exception as e:
            self.logger.fail(f"Error on Enumeration NFS Shares: {self.host}:{self.port} {e}")
        finally:
            self.nfs3.disconnect()

    def get_permissions(self, file_handle):
        """Check permissions for the file handle"""
        try:
            read_perm = self.nfs3.access(file_handle, ACCESS3_READ, self.auth).get("resok", {}).get("access", 0) is ACCESS3_READ
        except Exception:
            read_perm = False
        try:
            write_perm = self.nfs3.access(file_handle, ACCESS3_MODIFY, self.auth).get("resok", {}).get("access", 0) is ACCESS3_MODIFY
        except Exception:
            write_perm = False
        try:
            exec_perm = self.nfs3.access(file_handle, ACCESS3_EXECUTE, self.auth).get("resok", {}).get("access", 0) is ACCESS3_EXECUTE
        except Exception:
            exec_perm = False
        return read_perm, write_perm, exec_perm

    def enum_shares(self, max_uid=0):
        try:
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            contents = []
            # Mounting NFS Shares
            output_export = str(self.mount.export())
            pattern_name = re.compile(r"ex_dir=b'([^']*)'")
            matches_name = pattern_name.findall(output_export)
            output_name = list(matches_name)

            self.list_exported_shares(max_uid, contents, output_name, recurse_depth=self.args.enum_shares)
        except Exception as e:
            self.logger.debug(f"Error on Listing NFS Shares Directories: {self.host}:{self.port} {e}")
            self.logger.debug("It is probably unknown format or can not access as anonymously.")
        finally:
            self.nfs3.disconnect()

    def list_exported_shares(self, max_uid, contents, output_name, recurse_depth):
        if max_uid:
            self.logger.display(f"Enumerating NFS Shares to UID {max_uid}")
        else:
            self.logger.display(f"Enumerating NFS Shares with UID {max_uid}")
        white_list = []
        for uid in range(max_uid + 1):
            self.auth["uid"] = uid
            for export in output_name:
                try:
                    if export in white_list:
                        self.logger.debug(f"Skipping {export} as it is already listed.")
                        continue
                    else:
                        mount_info = self.mount.mnt(export, self.auth)
                        contents = self.list_dir(self.nfs3, mount_info["mountinfo"]["fhandle"], export, recurse_depth)
                        white_list.append(export)
                        self.logger.success(export)
                        for content in contents:
                            self.logger.highlight(f"\tUID: {self.auth['uid']} {content}")
                except Exception as e:
                    if not max_uid:  # To avoid mess in the debug logs
                        if "RPC_AUTH_ERROR: AUTH_REJECTEDCRED" in str(e):
                            self.logger.fail(f"{export} - RPC Access denied")
                        elif "RPC_AUTH_ERROR: AUTH_TOOWEAK" in str(e):
                            self.logger.fail(f"{export} - Kerberos authentication required")
                        elif "Insufficient Permissions" in str(e):
                            self.logger.fail(f"{export} - Insufficient Permissions for share listing")
                        else:
                            self.logger.exception(f"{export} - {e}")

    def uid_brute(self, max_uid=None):
        if not max_uid:
            max_uid = int(self.args.uid_brute)
        self.enum_shares(max_uid)
