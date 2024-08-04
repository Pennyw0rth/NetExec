from nxc.connection import connection
from nxc.logger import NXCAdapter
from pyNfsClient import Portmap, Mount, NFSv3, NFS_PROGRAM, NFS_V3
import socket
import re

class nfs(connection):
    def __init__(self, args, db, host):
        self.protocol = "nfs"
        self.port = 111
        self.portmap = None
        self.mnt_port = None
        self.mount = None
        self.auth = {"flavor": 1,
            "machine_name": "host1",
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
    
    def plaintext_login(self, username, password):
        # Uses Anonymous access for now
        try:
            if self.initialization():
                self.logger.success("Initialization is successfull!")
        except Exception as e:
            self.logger.fail("Initialization is failed.")
            self.logger.debug(f"Error Plaintext login: {self.host}:{self.port} {e}")
        finally:
            self.disconnection()
    
    def create_conn_obj(self):
        """Creates and connects a socket to the NFS host"""
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((self.host, self.port))
            self.logger.info(f"Connection target successful: {self.host}:{self.port}")
        except Exception as e:
            self.logger.debug(f"Error connecting to NFS host: {self.host}:{self.port} {e}")
            return False
        return True
        
    def enum_host_info(self):
        self.initialization()
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
        finally:
            self.disconnection()
        
    def print_host_info(self):
        self.logger.display(f"Target supported NFS versions {self.nfs_versions}")
        return True
        
    def disconnection(self):
        """Disconnect mount and portmap if they are connected"""
        try:
            self.mount.disconnect()
            self.portmap.disconnect()
            self.logger.info(f"Disconnection successful: {self.host}:{self.port}")
        except Exception as e:
            self.logger.debug(f"Error during disconnection: {e}")
        
    def initialization(self):
        """Initializes and connects to the portmap and mounted folder"""
        try:
            # Portmap Initialization
            self.portmap = Portmap(self.host, timeout=3600)
            self.portmap.connect()
            
            # Mount Initialization
            self.mnt_port = self.portmap.getport(Mount.program, Mount.program_version)
            self.mount = Mount(host=self.host, port=self.mnt_port, timeout=3600, auth=self.auth)
            self.mount.connect()
            
            return self.portmap, self.mnt_port, self.mount
        except Exception as e:
            self.logger.debug(f"Error during Initialization: {e}")
        
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
                        recurse += 1
                        contents += process_entries(entry["nextentry"], path, recurse)
                
                return contents
            except Exception as e:
                self.logger.debug(f"Error on Listing Entries for NFS Shares: {self.host}:{self.port} {e}")
        try:
            if recurse == 0:
                return [path + "/"]

            items = self.nfs3.readdirplus(file_handle, auth=self.auth)
            entries = items["resok"]["reply"]["entries"]

            return process_entries(entries, path, recurse)
        except Exception:
            pass  # To avoid mess in the debug logs

    def export_info(self, export_nodes):
        """Filters all NFS shares and their access range"""
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
        """Findings all access range of the share(s)"""
        result = []
        for group in groups:
            result.append(group.gr_name.decode())
            
            # If there are more IP's, process them recursively.
            if group.gr_next:
                result.extend(self.group_names(group.gr_next))

        return result
    
    def shares(self):
        try:
            self.initialization()
            for mount in self.export_info(self.mount.export()):
                self.logger.highlight(mount)
        except Exception as e:
            self.logger.debug(f"Error on Enumeration NFS Shares: {self.host}:{self.port} {e}")
        finally:
            self.disconnection()

    def shares_list(self, max_uid=0):
        def export_list(max_uid):
            white_list = []
            for uid in range(max_uid + 1):
                self.auth["uid"] = uid
                for export in output_name:
                    try:
                        if export in white_list:
                            continue
                        else:
                            mount_info = self.mount.mnt(export, self.auth)
                            nonlocal contents  # The nonlocal keyword allows a variable defined in an outer (non-global) scope. To be referenced and modified in an inner scope.
                            contents += self.list_dir(self.nfs3, mount_info["mountinfo"]["fhandle"], export)
                            white_list.append(export)
                            for shares in contents:
                                self.logger.highlight(f"UID: {uid} {shares}")
                            contents = []
                    except Exception:
                        if not max_uid:  # To avoid mess in the debug logs
                            self.logger.fail(f"Can not reach file(s) on {export} with UID: {uid}")
        
        try:
            self.initialization()
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, 3600, self.auth)
            self.nfs3.connect()
            
            contents = []
            # Mounting NFS Shares
            output_export = str(self.mount.export())
            pattern_name = re.compile(r"ex_dir=b'([^']*)'")
            matches_name = pattern_name.findall(output_export)      
            output_name = list(matches_name)
            
            export_list(max_uid)

        except Exception as e:
            
            self.logger.debug(f"Error on Listing NFS Shares Directories: {self.host}:{self.port} {e}")
            self.logger.debug("It is probably unknown format or can not access as anonymously.")
        finally:
            self.nfs3.disconnect()
            self.disconnection()

    def uid_brute(self, max_uid=None):
        if not max_uid:
            max_uid = int(self.args.uid_brute)
        self.shares_list(max_uid)
