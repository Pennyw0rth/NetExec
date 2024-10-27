from nxc.connection import connection
from nxc.logger import NXCAdapter
from nxc.helpers.logger import highlight
from pyNfsClient import Portmap, Mount, NFSv3, NFS_PROGRAM, NFS_V3, ACCESS3_READ, ACCESS3_MODIFY, ACCESS3_EXECUTE, NFSSTAT3
import re
import uuid
import math
import os


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

    def disconnect(self):
        """Disconnect mount and portmap if they are connected"""
        try:
            self.mount.disconnect()
            self.portmap.disconnect()
            self.logger.info(f"Disconnect successful: {self.host}:{self.port}")
        except Exception as e:
            self.logger.fail(f"Error during disconnect: {e}")

    def list_dir(self, file_handle, path, recurse=1):
        """Process entries in NFS directory recursively with UID autodection"""
        def process_entries(entries, path, uid, recurse):
            try:
                contents = []
                for entry in entries:
                    if "name" in entry and entry["name"] not in [b".", b".."]:
                        item_path = f'{path}/{entry["name"].decode("utf-8")}'  # Constructing file path
                        if entry.get("name_attributes", {}).get("present", False):
                            if entry["name_attributes"]["attributes"]["type"] == 2 and recurse > 0:  # Recursive directory listing. Entry type shows file format. 1 is file, 2 is folder.
                                dir_handle = entry["name_handle"]["handle"]["data"]
                                contents += self.list_dir(dir_handle, item_path, recurse=recurse - 1)
                            else:
                                file_handle = entry["name_handle"]["handle"]["data"]
                                attrs = self.nfs3.getattr(file_handle, auth=self.auth)
                                file_size = attrs["attributes"]["size"]
                                file_size = convert_size(file_size)
                                uid = attrs["attributes"]["uid"]
                                read_perm, write_perm, exec_perm = self.get_permissions(entry["name_handle"]["handle"]["data"])
                                contents.append({"path": item_path, "read": read_perm, "write": write_perm, "execute": exec_perm, "filesize": file_size, "uid": uid})

                    if entry["nextentry"]:
                        # Processing next entries recursively
                        contents += process_entries(entry["nextentry"], path, uid, recurse)

                return contents
            except Exception as e:
                self.logger.debug(f"Error on Listing Entries for NFS Shares: {self.host}:{self.port} {e}")

        attrs = self.nfs3.getattr(file_handle, auth=self.auth)
        self.auth["uid"] = attrs["attributes"]["uid"]

        if recurse == 0:
            read_perm, write_perm, exec_perm = self.get_permissions(file_handle)
            return [{"path": f"{path}/", "read": read_perm, "write": write_perm, "execute": exec_perm, "filesize": "-", "uid": self.auth["uid"]}]

        items = self.nfs3.readdirplus(file_handle, auth=self.auth)
        if "resfail" in items:
            raise Exception("Insufficient Permissions")
        else:
            entries = items["resok"]["reply"]["entries"]

        return process_entries(entries, path, self.auth["uid"], recurse)

    def export_info(self, export_nodes):
        """Enumerates all NFS shares and their access range"""
        networks = []
        for node in export_nodes:

            # Collect the names of the groups associated with this export node
            group_names = self.group_names(node.ex_groups)
            networks.append(group_names)

            # If there are more export nodes, process them recursively. More than one share.
            if node.ex_next:
                networks.extend(self.export_info(node.ex_next))

        return networks

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
        self.logger.display("Enumerating NFS Shares")
        try:
            # Connect to NFS
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            output_export = str(self.mount.export())
            networks = self.export_info(self.mount.export())

            reg = re.compile(r"ex_dir=b'([^']*)'")  # Get share names
            shares = list(reg.findall(output_export))

            # Mount shares and check permissions
            self.logger.highlight(f"{'UID':<11}{'Perms':<9}{'Storage Usage':<17}{'Share':<30} {'Access List':<15}")
            self.logger.highlight(f"{'---':<11}{'-----':<9}{'-------------':<17}{'-----':<30} {'-----------':<15}")
            for share, network in zip(shares, networks):
                try:
                    mnt_info = self.mount.mnt(share, self.auth)
                    self.logger.debug(f"Mounted {share} - {mnt_info}")
                    if mnt_info["status"] != 0:
                        self.logger.fail(f"Error mounting share {share}: {NFSSTAT3[mnt_info['status']]}")
                        continue
                    file_handle = mnt_info["mountinfo"]["fhandle"]

                    info = self.nfs3.fsstat(file_handle, self.auth)
                    free_space = info["resok"]["fbytes"]
                    total_space = info["resok"]["tbytes"]
                    used_space = total_space - free_space

                    # Autodetectting the uid needed for the share
                    attrs = self.nfs3.getattr(file_handle, auth=self.auth)
                    self.auth["uid"] = attrs["attributes"]["uid"]

                    read_perm, write_perm, exec_perm = self.get_permissions(file_handle)
                    self.mount.umnt(self.auth)
                    self.logger.highlight(f"{self.auth['uid']:<11}{'r' if read_perm else '-'}{'w' if write_perm else '-'}{('x' if exec_perm else '-'):<7}{convert_size(used_space)}/{convert_size(total_space):<9} {share:<30} {', '.join(network) if network else 'No network':<15}")
                except Exception as e:
                    self.logger.fail(f"Failed to list share: {share} - {e}")

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

    def enum_shares(self):
        try:
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            # Mounting NFS Shares
            output_export = str(self.mount.export())
            reg = re.compile(r"ex_dir=b'([^']*)'")
            shares = list(reg.findall(output_export))
            networks = self.export_info(self.mount.export())

            self.logger.display("Enumerating NFS Shares Directories")
            for share, network in zip(shares, networks):
                try:
                    mount_info = self.mount.mnt(share, self.auth)
                    self.logger.debug(f"Mounted {share} - {mount_info}")
                    if mount_info["status"] != 0:
                        self.logger.fail(f"Error mounting share {share}: {NFSSTAT3[mount_info['status']]}")
                        continue

                    fhandle = mount_info["mountinfo"]["fhandle"]
                    contents = self.list_dir(fhandle, share, self.args.enum_shares)

                    self.logger.success(share)
                    if contents:
                        self.logger.highlight(f"{'UID':<11}{'Perms':<9}{'File Size':<15}{'File Path':<45} {'Access List':<15}")
                        self.logger.highlight(f"{'---':<11}{'-----':<9}{'---------':<15}{'---------':<45} {'-----------':<15}")
                    for content in contents:
                        self.logger.highlight(f"{content['uid']:<11}{'r' if content['read'] else '-'}{'w' if content['write'] else '-'}{'x' if content['execute'] else '-':<7}{content['filesize']:<14} {content['path']:<45} {', '.join(network) if network else 'No network':<15}")
                except Exception as e:
                    if "RPC_AUTH_ERROR: AUTH_REJECTEDCRED" in str(e):
                        self.logger.fail(f"{share} - RPC Access denied")
                    elif "RPC_AUTH_ERROR: AUTH_TOOWEAK" in str(e):
                        self.logger.fail(f"{share} - Kerberos authentication required")
                    elif "Insufficient Permissions" in str(e):
                        self.logger.fail(f"{share} - Insufficient Permissions for share listing")
                    else:
                        self.logger.exception(f"{share} - {e}")
        except Exception as e:
            self.logger.debug(f"Error on Listing NFS Shares Directories: {self.host}:{self.port} {e}")
            self.logger.debug("It is probably unknown format or can not access as anonymously.")
        finally:
            self.nfs3.disconnect()

    def get_file(self):
        """Downloads a file from the NFS share"""
        remote_file_path = self.args.get_file[0]
        remote_dir_path, file_name = os.path.split(remote_file_path)
        local_file_path = self.args.get_file[1]

        # Do a bit of smart handling for the local file path
        if local_file_path.endswith("/"):
            local_file_path += file_name

        self.logger.display(f"Downloading {remote_file_path} to {local_file_path}")
        try:
            # Connect to NFS
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            # Mount the NFS share
            mnt_info = self.mount.mnt(remote_dir_path, self.auth)

            # Update the UID for the file
            attrs = self.nfs3.getattr(mnt_info["mountinfo"]["fhandle"], auth=self.auth)
            self.auth["uid"] = attrs["attributes"]["uid"]
            dir_handle = mnt_info["mountinfo"]["fhandle"]

            # Get the file handle and file size
            dir_data = self.nfs3.lookup(dir_handle, file_name, auth=self.auth)
            file_handle = dir_data["resok"]["object"]["data"]

            # Handle files over the default chunk size of 1024 * 1024
            offset = 0
            eof = False

            # Loop until we have read the entire file
            with open(local_file_path, "wb+") as local_file:
                while not eof:
                    file_data = self.nfs3.read(file_handle, offset, auth=self.auth)

                    if "resfail" in file_data:
                        raise Exception("Insufficient Permissions")

                    else:
                        # Get the data and append it to the total file data
                        data = file_data["resok"]["data"]
                        eof = file_data["resok"]["eof"]

                        # Update the offset to read the next chunk
                        offset += len(data)
                        # Write the file data to the local file
                        local_file.write(data)

            self.logger.highlight(f"File successfully downloaded to {local_file_path} from {remote_file_path}")

            # Unmount the share
            self.mount.umnt(self.auth)
        except Exception as e:
            self.logger.fail(f'Error retrieving file "{file_name}" from "{remote_dir_path}": {e}')
            if os.path.exists(local_file_path) and os.path.getsize(local_file_path) == 0:
                os.remove(local_file_path)

    def put_file(self):
        """Uploads a file to the NFS share"""
        local_file_path = self.args.put_file[0]
        remote_file_path = self.args.put_file[1]
        file_name = ""

        # Check if local file is exist
        if not os.path.isfile(local_file_path):
            self.logger.fail(f"{local_file_path} does not exist.")
            return

        # Do a bit of smart handling for the file paths
        file_name = local_file_path.split("/")[-1] if "/" in local_file_path else local_file_path
        if not remote_file_path.endswith("/"):
            remote_file_path += "/"

        self.logger.display(f"Uploading from {local_file_path} to {remote_file_path}")
        try:
            # Connect to NFS
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            # Mount the NFS share to create the file
            mnt_info = self.mount.mnt(remote_file_path, self.auth)
            dir_handle = mnt_info["mountinfo"]["fhandle"]

            # Update the UID from the directory
            attrs = self.nfs3.getattr(dir_handle, auth=self.auth)
            self.auth["uid"] = attrs["attributes"]["uid"]

            # Checking if file_name already exists on remote file path
            lookup_response = self.nfs3.lookup(dir_handle, file_name, auth=self.auth)

            # If success, file_name does not exist on remote machine. Else, trying to overwrite it.
            if lookup_response["resok"] is None:
                # Create file
                self.logger.display(f"Trying to create {remote_file_path}{file_name}")
                res = self.nfs3.create(dir_handle, file_name, create_mode=1, mode=0o777, auth=self.auth)
                if res["status"] != 0:
                    raise Exception(NFSSTAT3[res["status"]])
                else:
                    file_handle = res["resok"]["obj"]["handle"]["data"]
                self.logger.success(f"{file_name} successfully created")
            else:
                # Asking the user if they want to overwrite the file
                ans = input(highlight(f"[!] {file_name} already exists on {remote_file_path}. Do you want to overwrite it? [Y/n] ", "red"))
                if ans.lower() in ["y", "yes", ""]:
                    self.logger.display(f"{file_name} already exists on {remote_file_path}. Trying to overwrite it...")
                    file_handle = lookup_response["resok"]["object"]["data"]
                else:
                    self.logger.fail(f"Uploading was not successful. The {file_name} is exist on {remote_file_path}")
                    return

            try:
                with open(local_file_path, "rb") as file:
                    file_data = file.read().decode()

                # Write the data to the remote file
                self.logger.display(f"Trying to write data from {local_file_path} to {remote_file_path}")
                self.nfs3.write(file_handle, 0, len(file_data), file_data, 1, auth=self.auth)
                self.logger.success(f"Data from {local_file_path} successfully written to {remote_file_path}")
            except Exception as e:
                self.logger.fail(f"Could not write to {local_file_path}: {e}")

            # Unmount the share
            self.mount.umnt(self.auth)
        except Exception as e:
            self.logger.fail(f"Error writing file to share {remote_file_path}: {e}")
        else:
            self.logger.highlight(f"File {local_file_path} successfully uploaded to {remote_file_path}")


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 1)
    return f"{s}{size_name[i]}"
