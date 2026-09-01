from io import BytesIO

from termcolor import colored
from nxc.connection import connection
from nxc.logger import NXCAdapter
from nxc.helpers.logger import highlight
from nxc.config import host_info_colors
from pyNfsClient import (
    Portmap,
    Mount,
    NFSv3,
    NFSv4,
)
from pyNfsClient.nfs4_const import NFSSTAT4
from pyNfsClient.rpcsec_gss import RPCSECGSSAuth
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
        if args.nfs_auth in ("krb5", "krb5i", "krb5p"):
            args.kerberos = True
        self.protocol = "nfs"
        self.port = args.port or (2049 if args.nfs_version == 4 else 111)
        self.portmap = None
        self.mnt_port = None
        self.mount = None
        self.nfs = None
        self.auth = {
            "flavor": 1,
            "machine_name": uuid.uuid4().hex.upper()[0:6],
            "uid": 0,
            "gid": 0,
            "aux_gid": [],
        }
        self.rpc_auth = self.auth if args.nfs_auth == "sys" else None
        self.authenticated = False
        self.credentials = None
        self.root_escape = None
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

    def uses_kerberos(self):
        return self.args.nfs_auth in ("krb5", "krb5i", "krb5p")

    def connect_nfs(self):
        if self.nfs is not None and self.nfs.client is not None:
            return self.nfs
        if self.args.nfs_version == 4:
            self.nfs = NFSv4(self.host, self.args.port or 2049, self.args.nfs_timeout, self.rpc_auth)
        else:
            self.nfs = NFSv3(self.host, self.portmap.getport(NFS_PROGRAM, NFS_V3), self.args.nfs_timeout, self.rpc_auth)
        self.nfs.connect()
        self.conn = self.nfs
        self.port = self.nfs.port
        return self.nfs

    def connect_mount(self):
        if self.mount is not None and self.mount.client is not None:
            return self.mount
        self.mnt_port = self.portmap.getport(Mount.program, Mount.program_version)
        self.mount = Mount(self.host, self.mnt_port, self.args.nfs_timeout, None if self.args.nfs_auth == "none" else self.auth)
        self.mount.connect()
        return self.mount

    def root_handle(self, share):
        if self.args.nfs_version == 3:
            return self.connect_mount().mnt(share)
        file_handle = self.nfs.root_filehandle(auth=self.rpc_auth)
        for component in filter(None, share.replace("\\", "/").split("/")):
            response = self.nfs.lookup(file_handle, component, auth=self.rpc_auth)
            if response["status"] != 0:
                return {"status": response["status"]}
            file_handle = response["resok"]["object"]["data"]
        return {"status": 0, "mountinfo": {"fhandle": file_handle}}

    def selected_root_handle(self):
        if self.root_escape and not self.args.share:
            self.logger.success(f"Successful escape on share: {self.escape_share}")
            return self.escape_fh
        if not self.args.share and self.args.nfs_version == 3:
            self.logger.fail("No root escape possible, please specify a share")
            return None
        mount_info = self.root_handle(self.args.share or "/")
        if mount_info["status"] != 0:
            self.logger.fail(f"Could not open share {self.args.share or '/'}: {self.status_name(mount_info['status'])}")
            return None
        return mount_info["mountinfo"]["fhandle"]

    def exports(self):
        if self.args.nfs_version == 4:
            return [("/", ["Everyone"])]
        self.connect_mount()
        return list(zip(re.findall(r"ex_dir=b'([^']*)'", str(self.mount.export())), self.export_info(self.mount.export()), strict=True))

    def unmount(self):
        if self.args.nfs_version == 3:
            self.mount.umnt()

    def status_name(self, status):
        return NFSSTAT3.get(status, NFSSTAT4.get(status, f"NFS status {status}"))

    def create_conn_obj(self):
        """Connect directly to NFSv4 or discover the NFSv3 services."""
        try:
            if self.args.nfs_version == 3:
                self.port = self.args.port or 111
                self.portmap = Portmap(self.host, timeout=self.args.nfs_timeout, port=self.args.port or 111)
                self.portmap.connect()
            else:
                self.connect_nfs()
            self.proto_logger()
        except Exception as e:
            self.logger.info(f"Error during Initialization: {e}")
            return False
        return True

    def enum_host_info(self):
        self.nfs_versions = {self.args.nfs_version}
        if self.args.nfs_version == 3:
            try:
                self.nfs_versions = set()
                for program in self.portmap.dump():
                    if program["program"] == NFS_PROGRAM:
                        self.nfs_versions.add(program["version"])
            except Exception as e:
                self.logger.fail(f"Error checking NFS version: {self.host} {e}")
        if self.args.nfs_version == 3 and NFS_V3 not in self.nfs_versions:
            self.logger.debug("NFSv3 not supported, skipping root escape check")
        elif not self.uses_kerberos():
            try:
                self.connect_nfs()
                self.root_escape = self.try_root_escape()
            except Exception as e:
                self.logger.debug(f"Root escape check failed: {e}")
                self.root_escape = None
        self.db.add_host(self.host, self.hostname, self.port, self.nfs_versions, self.root_escape)

    def print_host_info(self):
        root_escape_str = colored(f"root escape:{'unknown' if self.root_escape is None else self.root_escape}", host_info_colors[1 if self.root_escape else 0], attrs=["bold"])
        self.logger.display(f"Supported NFS versions: ({', '.join(str(x) for x in sorted(self.nfs_versions))}) NFSv{self.args.nfs_version} {self.args.nfs_auth} ({root_escape_str})")

    def disconnect(self):
        """Release the raw NFS, MOUNT, and rpcbind connections."""
        failure = None
        if isinstance(self.rpc_auth, RPCSECGSSAuth) and self.nfs is not None:
            if hasattr(self.nfs, "opened"):
                for file_handle in tuple(self.nfs.opened):
                    try:
                        self.nfs.close_handle(file_handle, auth=self.rpc_auth)
                    except Exception as e:
                        failure = failure or e
            try:
                self.rpc_auth.destroy(self.nfs, NFS_PROGRAM, self.args.nfs_version)
            except Exception as e:
                failure = failure or e
        for rpc in (self.nfs, self.mount, self.portmap):
            if rpc is not None:
                try:
                    rpc.disconnect()
                except Exception as e:
                    failure = failure or e
        if failure is None:
            self.logger.info(f"Disconnect successful: {self.host}:{self.port}")
        else:
            self.logger.fail(f"Error during disconnect: {failure}")

    def login(self):
        if not self.uses_kerberos():
            return True
        if self.args.use_kcache:
            return self.kerberos_login(self.args.domain, self.args.username[0] if self.args.username else "", kdcHost=self.args.kdcHost, useCache=True)
        if not self.args.username:
            self.logger.fail(f"{self.args.nfs_auth} requires credentials or --use-kcache")
            return False
        return super().login() or self.authenticated

    def plaintext_login(self, domain, username, password):
        if not self.uses_kerberos():
            return True
        return self.kerberos_login(domain, username, password=password)

    def hash_login(self, domain, username, ntlm_hash):
        if not self.uses_kerberos():
            self.logger.fail("NT hashes only apply to Kerberos NFS authentication")
            return False
        return self.kerberos_login(domain, username, ntlm_hash=ntlm_hash)

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        from pyNfsClient.kerberos import KerberosInitiator

        lmhash, nthash = ntlm_hash.split(":", 1) if ":" in ntlm_hash else ("", ntlm_hash)
        self.credentials = {
            "realm": domain,
            "username": username,
            "password": password,
            "lmhash": lmhash,
            "nthash": nthash,
            "aes_key": aesKey,
            "ccache": os.environ.get("KRB5CCNAME") if useCache else None,
            "use_cache": useCache,
            "kdc_host": kdcHost,
            "service": "nfs",
        }
        try:
            if self.nfs is not None:
                self.nfs.disconnect()
            self.nfs = None
            self.rpc_auth = None
            self.connect_nfs()
            self.rpc_auth = RPCSECGSSAuth.establish(self.nfs, NFS_PROGRAM, self.args.nfs_version, KerberosInitiator(self.host, self.credentials), self.args.nfs_auth)
            self.nfs.auth = self.rpc_auth
            self.root_escape = self.try_root_escape()
        except Exception as e:
            self.logger.fail(f"{domain}\\{username} ({self.args.nfs_auth}): {e}")
            return False
        self.domain = domain
        self.username = username
        self.password = password
        self.authenticated = True
        self.db.add_host(self.host, self.hostname, self.port, self.nfs_versions, self.root_escape)
        self.logger.success(f"{domain}\\{username} ({self.args.nfs_auth})")
        return True

    def list_dir(self, file_handle, path, recurse=1):
        """Process entries in NFS directory recursively with UID autodection"""
        def process_entries(entries, path, uid, recurse):
            try:
                contents = []
                for entry in entries:
                    if self.args.nfs_auth == "sys":
                        self.auth.update(directory_auth)
                    if "name" in entry and entry["name"] not in [b".", b".."]:
                        item_path = f'{path}/{entry["name"].decode("utf-8")}'  # Constructing file path
                        if entry.get("name_attributes", {}).get("present", False):
                            if entry["name_attributes"]["attributes"]["type"] == 2 and recurse > 0:  # Recursive directory listing. Entry type shows file format. 1 is file, 2 is folder.
                                dir_handle = entry["name_handle"]["handle"]["data"]
                                contents += self.list_dir(dir_handle, item_path, recurse=recurse - 1)
                            else:
                                file_handle = entry["name_handle"]["handle"]["data"]
                                attrs = self.update_auth(file_handle)
                                file_size = attrs["attributes"]["size"]
                                file_size = convert_size(file_size)
                                uid = attrs["attributes"]["uid"]
                                read_perm, write_perm, exec_perm = self.get_permissions(entry["name_handle"]["handle"]["data"])
                                contents.append({"path": item_path, "read": read_perm, "write": write_perm, "execute": exec_perm, "filesize": file_size, "uid": uid})

                    if entry["nextentry"]:
                        # Processing next entries recursively
                        contents += process_entries(entry["nextentry"], path, uid, recurse)

                if self.args.nfs_auth == "sys":
                    self.auth.update(directory_auth)
                return contents
            except Exception as e:
                self.logger.debug(f"Error on Listing Entries for NFS Shares: {self.host}:{self.port} {e}")

        attrs = self.update_auth(file_handle)
        directory_auth = dict(self.auth)

        if recurse == 0:
            read_perm, write_perm, exec_perm = self.get_permissions(file_handle)
            return [{"path": f"{path}/", "read": read_perm, "write": write_perm, "execute": exec_perm, "filesize": "-", "uid": attrs["attributes"]["uid"]}]

        items = self.nfs.readdirplus(file_handle, auth=self.rpc_auth)
        if "resfail" in items:
            raise Exception("Insufficient Permissions")
        else:
            entries = items["resok"]["reply"]["entries"]

        return process_entries(entries, path, attrs["attributes"]["uid"], recurse)

    def export_info(self, export_nodes):
        """Enumerates all NFS shares and their access range"""
        networks = []
        for node in export_nodes:

            # Collect the names of the groups associated with this export node
            group_names = self.group_names(node.ex_groups) or ["Everyone"]
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
            self.connect_nfs()

            # Mount shares and check permissions
            self.logger.highlight(f"{'UID':<11} {'Perms':<9}{'Storage Usage':<17}{'Share':<30} {'Access List':<15}")
            self.logger.highlight(f"{'---':<11} {'-----':<9}{'-------------':<17}{'-----':<30} {'-----------':<15}")
            for share, network in self.exports():
                try:
                    mnt_info = self.root_handle(share)
                    self.logger.debug(f"Mounted {share} - {mnt_info}")
                    if mnt_info["status"] != 0:
                        self.logger.debug(f"Error mounting share {share}: {self.status_name(mnt_info['status'])}")
                        self.logger.highlight(f"{'-':<11}{'---':<9}{'---'}/{'---':<12} {share:<30} {', '.join(network) if network else 'No network':<15}")
                    else:
                        file_handle = mnt_info["mountinfo"]["fhandle"]

                        info = self.nfs.fsstat(file_handle, auth=self.rpc_auth)
                        free_space = info["resok"]["fbytes"]
                        total_space = info["resok"]["tbytes"]
                        used_space = total_space - free_space

                        # Autodetectting the uid needed for the share
                        attrs = self.update_auth(file_handle)

                        read_perm, write_perm, exec_perm = self.get_permissions(file_handle)
                        self.unmount()
                        self.db.add_share(self.host, (read_perm, write_perm, exec_perm), (convert_size(used_space), "/", convert_size(total_space)), share, network)
                        self.logger.highlight(f"{attrs['attributes']['uid']:<11} {'r' if read_perm else '-'}{'w' if write_perm else '-'}{('x' if exec_perm else '-'):<7}{convert_size(used_space) + '/' + convert_size(total_space):<16} {share:<30} {', '.join(network) if network else 'No network':<15}")
                except Exception as e:
                    self.logger.fail(f"Failed to list share: {share} - {e}")

        except Exception as e:
            self.logger.fail(f"Error on Enumeration NFS Shares: {self.host}:{self.port} {e}")

    def get_permissions(self, file_handle):
        """Check permissions for the file handle"""
        try:
            read_perm = self.nfs.access(file_handle, ACCESS3_READ, auth=self.rpc_auth).get("resok", {}).get("access", 0) == ACCESS3_READ
        except Exception:
            read_perm = False
        try:
            write_perm = self.nfs.access(file_handle, ACCESS3_MODIFY, auth=self.rpc_auth).get("resok", {}).get("access", 0) == ACCESS3_MODIFY
        except Exception:
            write_perm = False
        try:
            exec_perm = self.nfs.access(file_handle, ACCESS3_EXECUTE, auth=self.rpc_auth).get("resok", {}).get("access", 0) == ACCESS3_EXECUTE
        except Exception:
            exec_perm = False
        return read_perm, write_perm, exec_perm

    def enum_shares(self):
        try:
            self.connect_nfs()

            self.logger.display("Enumerating NFS Shares Directories")
            for share, network in self.exports():
                try:
                    mount_info = self.root_handle(share)
                    self.logger.debug(f"Mounted {share} - {mount_info}")
                    if mount_info["status"] != 0:
                        self.logger.fail(f"Error mounting share {share}: {self.status_name(mount_info['status'])}")
                        continue

                    fhandle = mount_info["mountinfo"]["fhandle"]
                    contents = self.list_dir(fhandle, share, self.args.enum_shares)

                    self.logger.success(share)
                    if contents:
                        self.logger.highlight(f"{'UID':<11} {'Perms':<9}{'File Size':<15}{'File Path':<45} {'Access List':<15}")
                        self.logger.highlight(f"{'---':<11} {'-----':<9}{'---------':<15}{'---------':<45} {'-----------':<15}")
                    for content in contents:
                        self.logger.highlight(f"{content['uid']:<11} {'r' if content['read'] else '-'}{'w' if content['write'] else '-'}{'x' if content['execute'] else '-':<7}{content['filesize']:<14} {content['path']:<45} {', '.join(network) if network else 'No network':<15}")
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
            self.connect_nfs()

            mount_fh = self.selected_root_handle()
            if mount_fh is None:
                return

            # Iterate over the path until we hit the file
            curr_fh = mount_fh
            for sub_path in remote_file_path.lstrip("/").split("/"):
                # Update the UID for the next object and get the handle
                self.update_auth(curr_fh)
                res = self.nfs.lookup(curr_fh, sub_path, auth=self.rpc_auth)

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
                    file_data = self.nfs.read(curr_fh, offset, auth=self.rpc_auth)

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
            self.unmount()
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

        # Do a bit of smart handling for the remote file path
        if remote_file_path.endswith("/"):
            file_name = os.path.basename(local_file_path)

        self.logger.display(f"Uploading from {local_file_path} to {remote_file_path}")
        try:
            self.connect_nfs()

            mount_fh = self.selected_root_handle()
            if mount_fh is None:
                return

            # Iterate over the path
            curr_fh = mount_fh
            # If target dir is "" or "/" without filter we would get one item with [""]
            for sub_path in list(filter(None, remote_dir_path.lstrip("/").split("/"))):
                self.update_auth(curr_fh)
                res = self.nfs.lookup(curr_fh, sub_path, auth=self.rpc_auth)

                # If the path does not exist, create it
                if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                    self.logger.display(f"Creating directory '/{sub_path}/'")
                    res = self.nfs.mkdir(curr_fh, sub_path, 0o777, auth=self.rpc_auth)
                    if res["status"] != 0:
                        self.logger.fail(f"Error creating directory '/{sub_path}/': {self.status_name(res['status'])}")
                        return
                    else:
                        curr_fh = res["resok"]["obj"]["handle"]["data"]
                        continue

                curr_fh = res["resok"]["object"]["data"]

            # Update the UID and GID from the directory
            self.update_auth(curr_fh)

            # Checking if file_name already exists on remote file path
            lookup_response = self.nfs.lookup(curr_fh, file_name, auth=self.rpc_auth)

            # If success, file_name does not exist on remote machine. Else, trying to overwrite it.
            if lookup_response["resok"] is None:
                # Create file
                self.logger.display(f"Trying to create {remote_file_path}")
                res = self.nfs.create(curr_fh, file_name, create_mode=1, mode=0o777, auth=self.rpc_auth)
                if res["status"] != 0:
                    raise Exception(self.status_name(res["status"]))
                else:
                    file_handle = res["resok"]["obj"]["handle"]["data"]
                    self.update_auth(file_handle)
                self.logger.success(f"'{file_name}' successfully created")
            else:
                # Asking the user if they want to overwrite the file
                ans = input(highlight(f"[!] '{file_name}' already exists on '{remote_file_path}'. Do you want to overwrite it? [Y/n] ", "red"))
                if ans.lower() in ["y", "yes", ""]:
                    self.logger.display(f"'{file_name}' already exists on '{remote_file_path}'. Trying to overwrite it...")
                    file_handle = lookup_response["resok"]["object"]["data"]
                else:
                    return

            # Update the UID and GID for the file
            self.update_auth(file_handle)

            # Use wtpref as the chunk size
            res = self.nfs.fsinfo(file_handle, auth=self.rpc_auth)
            if res["status"] != 0:
                self.logger.fail(f"Error getting FSINFO for {remote_file_path}: {self.status_name(res['status'])}")
                return
            chunk_size = res["resok"]["wtpref"]

            self.logger.display(f"Transferring data from '{local_file_path}' to '{remote_file_path}'")
            try:
                offset = 0
                with open(local_file_path, "rb") as file:
                    while chunk := file.read(chunk_size):
                        # Write the data to the remote file
                        res = self.nfs.write(file_handle, offset, len(chunk), chunk, 1, auth=self.rpc_auth)
                        if res["status"] != 0:
                            self.logger.fail(f"Error writing to '{remote_file_path}': {self.status_name(res['status'])}")
                            return
                        offset += len(chunk)

                self.logger.success(f"Data from '{local_file_path}' successfully written to '{remote_file_path}' with permissions 777")
            except Exception as e:
                self.logger.fail(f"Could not write to '{local_file_path}': {e}")

            # Unmount the share
            self.unmount()
        except Exception as e:
            self.logger.fail(f"Error writing file to share {remote_file_path}: {e}")
        else:
            self.logger.highlight(f"File {local_file_path} successfully uploaded to {remote_file_path}")

    def chmod(self):
        try:
            self.connect_nfs()

            mount_fh = self.selected_root_handle()
            if mount_fh is None:
                return

            # Iterate over the path
            curr_fh = mount_fh
            privs = int(self.args.chmod[0], 8)
            filepath = self.args.chmod[1]
            file_path, file_name = os.path.split(filepath)

            # If target dir is "" or "/" without filter we would get one item with [""]
            for sub_path in list(filter(None, file_path.lstrip("/").split("/"))):
                self.update_auth(curr_fh)
                res = self.nfs.lookup(curr_fh, sub_path, auth=self.rpc_auth)

                # If the path does not exist, create it
                if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                    self.logger.fail(f"Directory '{sub_path}' does not exist on path '{file_path}/'")

                curr_fh = res["resok"]["object"]["data"]

            # Update the UID and GID from the directory
            self.update_auth(curr_fh)

            # Checking if file_name already exists on remote file path
            lookup_response = self.nfs.lookup(curr_fh, file_name, auth=self.rpc_auth)

            if "resfail" in lookup_response and lookup_response["status"] == NFS3ERR_NOENT:
                self.logger.fail(f"File '{file_name}' does not exist on path '{file_path}/'")
                return

            current_privs = self.nfs.getattr(lookup_response["resok"]["object"]["data"], auth=self.rpc_auth)["attributes"]["mode"]
            res = self.nfs.setattr(lookup_response["resok"]["object"]["data"], mode=privs, auth=self.rpc_auth)
            if "resfail" in res:
                self.logger.fail(f"Failed to change permissions for '{filepath}': {self.status_name(res['status'])}")
            else:
                self.logger.success(f"Permissions for '{filepath}' successfully changed from {format(current_privs, 'o')} to {format(privs, 'o')}")
        except Exception as e:
            self.logger.fail(f"Error occurred while processing path: {e}")

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
        dir_data = self.format_directory(self.nfs.readdirplus(mount_fh, auth=self.rpc_auth))
        filesystem = FileID.unknown
        for entry in dir_data:
            # Check if "." is already the root directory
            if entry["name"] == b".":
                if entry["name_handle"]["handle"]["data"][0] in [2, 0x80]:
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
        if len(mount_fh) < 4 or mount_fh[2] not in fsid_lens:
            return []
        fh_fsid_type = mount_fh[2]
        fh_fsid_len = fsid_lens[fh_fsid_type]
        if len(mount_fh) < 4 + fh_fsid_len:
            return []
        root_handles = []

        # Generate possible root handles
        # General syntax: 4 byte header + fsid + fileid
        # Format for the file id see: https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/exportfs.h#L25
        fh = bytearray(mount_fh)
        if filesystem in [FileID.ext, FileID.unknown]:
            root_handles.append(bytes(fh[:3] + b"\x02" + fh[4:4+fh_fsid_len] + b"\x02\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x02\x00\x00\x00"))  # ruff: ignore[missing-whitespace-around-arithmetic-operator]
            root_handles.append(bytes(fh[:3] + b"\x02" + fh[4:4+fh_fsid_len] + b"\x80\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x80\x00\x00\x00"))  # ruff: ignore[missing-whitespace-around-arithmetic-operator]
        if filesystem in [FileID.btrfs, FileID.unknown]:
            # Iterate over btrfs subvolumes, use 16 as default similar to the guys from nfs-security-tooling
            for i in range(16):
                subvolume = i.to_bytes(1, "big") + b"\x01\x00\x00"
                root_handles.append(bytes(fh[:3] + b"\x4d" + fh[4:4+fh_fsid_len] + b"\x00\x01\x00\x00" + b"\x00\x00\x00\x00" + subvolume + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"))  # ruff: ignore[missing-whitespace-around-arithmetic-operator]

        return root_handles

    def try_root_escape(self) -> bool | None:
        """
        With an established connection look for a share that can be escaped to the root filesystem.
        If successfull, self.escape_share and self.escape_fh will be populated.

        Returns
        -------
            bool: True if root escape was successful
        """
        if not self.nfs:
            raise Exception("NFS connection is not established")

        shares = [share for share, network in self.exports()]
        evaluated = False
        self.logger.debug(f"Trying root escape on shares: {shares}")
        for share in shares:
            mount_info = self.root_handle(share)
            if mount_info["status"] != 0:
                self.logger.debug(f"Root escape: can't list directory {share}: {self.status_name(mount_info['status'])}")
                self.unmount()
                continue
            mount_fh = mount_info["mountinfo"]["fhandle"]
            try:
                possible_root_fhs = self.get_root_handles(mount_fh)
                for fh in possible_root_fhs:
                    attributes = self.nfs.getattr(fh, auth=self.rpc_auth)
                    directory = self.nfs.readdir(fh, auth=self.rpc_auth)
                    evaluated = True
                    if attributes["status"] == 0 and directory["status"] == 0:
                        self.logger.info(f"Root escape successful on share '{share}' with handle: {fh.hex()}")
                        self.escape_share = share
                        self.escape_fh = fh
                        self.unmount()
                        return True
            except Exception as e:
                self.logger.debug(f"Error trying root escape on share '{share}': {e}")
            self.unmount()
        return False if evaluated else None

    def ls(self):
        self.connect_nfs()

        # Remove leading or trailing slashes
        self.args.ls = self.args.ls.lstrip("/").rstrip("/")

        mount_fh = self.selected_root_handle()
        if mount_fh is None:
            return

        # We got a path to look up
        curr_fh = mount_fh
        is_file = False     # If the last path is a file

        # If ls is "" or "/" without filter we would get one item with [""]
        for sub_path in list(filter(None, self.args.ls.split("/"))):
            # Update UID and GID for the path
            self.update_auth(curr_fh)
            res = self.nfs.lookup(curr_fh, sub_path, auth=self.rpc_auth)

            if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                self.logger.fail(f"Unknown path: {self.args.ls!r}")
                return
            elif "resfail" in res:
                self.logger.fail(f"Error on looking up path '{sub_path}': {self.status_name(res['status'])}")
                return
            # If file then break and only display file
            if res["resok"]["obj_attributes"]["attributes"]["type"] == NF3REG:
                is_file = True
                break
            curr_fh = res["resok"]["object"]["data"]

        # Update the UID and GID for the file/dir
        self.update_auth(curr_fh)

        dir_listing = self.nfs.readdirplus(curr_fh, auth=self.rpc_auth)
        if dir_listing["status"] != 0:
            self.logger.fail(f"Error on listing directory: {self.status_name(dir_listing['status'])}")
            return
        content = self.format_directory(dir_listing)

        # If there are more entries than we could receive, get cookie from last entry and continue
        while not dir_listing["resok"]["reply"]["eof"]:
            cookie_verf = dir_listing["resok"]["cookieverf"]
            cookie = content[-1]["cookie"]
            dir_listing = self.nfs.readdirplus(curr_fh, cookie=cookie, cookie_verf=cookie_verf, auth=self.rpc_auth)
            more_content = self.format_directory(dir_listing)
            content.extend(more_content)

        # Sometimes the NFS Server does not return the attributes for the files
        # However, they can still be looked up individually is missing
        for item in content:
            if not item["name_attributes"]["present"]:
                try:
                    res = self.nfs.lookup(curr_fh, item["name"].decode(), auth=self.rpc_auth)
                    item["name_attributes"]["attributes"] = res["resok"]["obj_attributes"]["attributes"]
                    item["name_attributes"]["present"] = True
                    item["name_handle"]["handle"] = res["resok"]["object"]
                    item["name_handle"]["present"] = True
                except Exception as e:
                    self.logger.debug(f"Error on getting attributes for {item['name'].decode()}: {e}")

        # If the requested path is a file, we filter out all other files
        path = f"{(self.args.share or '').rstrip('/')}/{self.args.ls}"
        if is_file:
            content = [x for x in content if x["name"].decode() == sub_path]
            path = path.rsplit("/", 1)[0]   # Remove the file from the path
        self.print_directory(content, path)

    def cat(self):
        self.connect_nfs()

        # Remove leading or trailing slashes
        self.args.cat = self.args.cat.lstrip("/").rstrip("/")

        mount_fh = self.selected_root_handle()
        if mount_fh is None:
            return

        # We got a path to look up
        curr_fh = mount_fh
        is_file = False     # If the last path is a file

        # If ls is "" or "/" without filter we would get one item with [""]
        for sub_path in list(filter(None, self.args.cat.split("/"))):
            # Update UID and GID for the path
            self.update_auth(curr_fh)
            res = self.nfs.lookup(curr_fh, sub_path, auth=self.rpc_auth)

            if "resfail" in res and res["status"] == NFS3ERR_NOENT:
                self.logger.fail(f"Unknown path: {self.args.cat!r}")
                return
            elif "resfail" in res:
                self.logger.fail(f"Error on looking up path '{sub_path}': {self.status_name(res['status'])}")
                return

            curr_fh = res["resok"]["object"]["data"]

            # If file then break and only display file
            if res["resok"]["obj_attributes"]["attributes"]["type"] == NF3REG:
                is_file = True
                break

        # Update the UID and GID for the file/dir
        self.update_auth(curr_fh)

        if not is_file:
            self.logger.fail(f"Path '{self.args.cat}' is not a file!")
            return

        buf = BytesIO()
        # Handle files over the default chunk size of 1024 * 1024
        offset = 0
        eof = False
        while not eof:
            file_data = self.nfs.read(curr_fh, offset, auth=self.rpc_auth)

            if "resfail" in file_data:
                self.logger.fail(f"Failed to retrieve data for '{self.args.cat}': {self.status_name(file_data['status'])}")
                return

            else:
                # Get the data and append it to the total file data
                data = file_data["resok"]["data"]
                eof = file_data["resok"]["eof"]

                # Update the offset to read the next chunk
                offset += len(data)
                # Write the file data to the local file
                buf.write(data)

        try:
            for line in buf.getvalue().decode().splitlines():
                self.logger.highlight(line)
        except UnicodeDecodeError as e:
            self.logger.fail(f"File is not in UTF-8: {e}")

    def print_directory(self, content, path):
        """
        Highlight log the content of the directory provided by a READDIRPLUS call.
        Expects an FORMATED output of self.format_directory.
        """
        # Sort items linux-like by name
        content = sorted(content, key=lambda x: x["name"].lower())
        self.logger.highlight(f"{'UID':<11} {'Perms':<7}{'File Size':<14}{'File Path'}")
        self.logger.highlight(f"{'---':<11} {'-----':<7}{'---------':<14}{'---------'}")
        directory_auth = dict(self.auth)
        for item in content:
            if self.args.nfs_auth == "sys":
                self.auth.update(directory_auth)
            if not item["name_attributes"]["present"] or not item["name_handle"]["present"]:
                uid = "-"
                perms = "----"
                file_size = "-"
            else:
                uid = item["name_attributes"]["attributes"]["uid"]
                is_dir = "d" if item["name_attributes"]["attributes"]["type"] == 2 else "-"
                self.update_auth(item["name_handle"]["handle"]["data"])
                read_perm, write_perm, exec_perm = self.get_permissions(item["name_handle"]["handle"]["data"])
                perms = f"{is_dir}{'r' if read_perm else '-'}{'w' if write_perm else '-'}{'x' if exec_perm else '-'}"
                file_size = convert_size(item["name_attributes"]["attributes"]["size"])
            try:
                self.logger.highlight(f"{uid:<11} {perms:<7}{file_size:<14}{path.rstrip('/') + '/' + item['name'].decode()}")
            except UnicodeDecodeError:
                self.logger.highlight(f"{uid:<11} {perms:<7}{file_size:<14}{path.rstrip('/') + '/' + item['name'].decode('CP437')}")
        if self.args.nfs_auth == "sys":
            self.auth.update(directory_auth)

    def format_directory(self, raw_directory):
        """Convert the chained directory entries to a list of the entries"""
        if "resfail" in raw_directory:
            self.logger.debug("Insufficient Permissions, NFS returned 'resfail'")
            return []
        if not raw_directory["resok"]["reply"]["entries"]:
            return []
        items = []
        nextentry = raw_directory["resok"]["reply"]["entries"][0]
        while nextentry:
            entry = nextentry
            nextentry = entry["nextentry"][0] if entry["nextentry"] else None
            entry.pop("nextentry")
            items.append(entry)
        return items

    def update_auth(self, file_handle):
        """Update the UID and GID for the file handle"""
        attrs = self.nfs.getattr(file_handle, auth=self.rpc_auth)
        self.logger.debug(f"Updating auth with UID: {attrs['attributes']['uid']} and GID: {attrs['attributes']['gid']}")
        if self.args.nfs_auth == "sys" and isinstance(attrs["attributes"]["uid"], int):
            self.auth["uid"] = attrs["attributes"]["uid"]
        if self.args.nfs_auth == "sys" and isinstance(attrs["attributes"]["gid"], int):
            self.auth["gid"] = attrs["attributes"]["gid"]
        return attrs


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = math.floor(math.log(size_bytes, 1024))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 1)
    return f"{s}{size_name[i]}"
