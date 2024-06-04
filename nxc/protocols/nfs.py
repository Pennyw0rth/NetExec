from nxc.connection import connection
from nxc.logger import NXCAdapter
from pyNfsClient import Portmap, Mount, NFSv3, NFS_PROGRAM, NFS_V3
import socket
import re


class nfs(connection):
    def __init__(self, args, db, host):
        # Setting up NFS protocol attributes
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
        # Initializing logger for NFS protocol
        self.logger = NXCAdapter(
            extra={
                "protocol": "NFS",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )
    
    def plaintext_login(self, username, password):
        # Doing as Anonymously now.
        try:
            if self.initialization():
                self.logger.success("Initialization is successfull!")
        except Exception as e:
            self.logger.fail("Initialization is failed.")
            self.logger.debug(f"Error Plaintext login: {self.host}:{self.port} {e}")
        finally:
            self.disconnection()
    
    def create_conn_obj(self):
        # Creating and connecting socket to NFS host
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
        # Enumerating host information
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
        # Printing host banner information
        self.logger.display(f"Target supported NFS versions {self.nfs_versions}")
        return True
        
    def disconnection(self):
        try:
            # Disconnecting from NFS host
            if self.mount():
                self.mount.disconnect()
            if self.portmap():
                self.portmap.disconnect()
            self.logger.info(f"Disconnection successful: {self.host}:{self.port}")
        except Exception as e:
            self.logger.debug(f"Error during disconnection: {e}")
        
    def initialization(self):
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
        
    def listdir(self, nfs, file_handle, path, recurse=1):
        # Process entries in NFS directory recursively.
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
                                contents += self.listdir(nfs, dir_handle, item_path, recurse=recurse - 1)
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
        except Exception as e:
            self.logger.debug(f"Error on Listing NFS Shares Directories: {self.host}:{self.port} {e}")

    def export_info(self, export_nodes):
        # This func for finding filtering all NFS shares and their access range. Using for shares func.
        
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
        # This func for finding all access range of the share(s). Using for shares func.
        
        result = []
        for group in groups:
            result.append(group.gr_name.decode())
            
            # If there are more IP's, process them recursively.
            if group.gr_next:
                result.extend(self.group_names(group.gr_next))

        return result
    
    def shares(self):
        try:
            # Initializing NFS services
            self.initialization()
            
            # Exporting NFS Shares
            for mount in self.export_info(self.mount.export()):
                self.logger.highlight(mount)

        except Exception as e:
            self.logger.debug(f"Error on Enumeration NFS Shares: {self.host}:{self.port} {e}")
        finally:
            self.disconnection()
                
    def shares_list(self):
        try:
            self.initialization()
            
            # NFS Initialization
            nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
            self.nfs3 = NFSv3(self.host, nfs_port, 3600, self.auth)
            self.nfs3.connect()
            
            contents = []
            # Mounting NFS Shares
            output_export = str(self.mount.export())
            pattern_name = re.compile(r"ex_dir=b'([^']*)'")
            matches_name = pattern_name.findall(output_export)      
            output_name = list(matches_name)
            
            # Searching files and folders as recursivly on every shares.
            for export in output_name:
                try:
                    mount_info = self.mount.mnt(export, self.auth)
                    contents += self.listdir(self.nfs3, mount_info["mountinfo"]["fhandle"], export)
                except Exception as e:
                    self.logger.fail(f"Can not reaching file(s) on {export}")
                    self.logger.debug(f"Error on Enum NFS Share {export}: {self.host}:{self.port} {e}")
                    self.logger.debug("It is probably unknown format or can not access as anonymously.")
                    continue
                
            for shares in contents:
                self.logger.highlight(shares)
                
        except Exception as e:
            self.logger.debug(f"Error on Listing NFS Shares: {self.host}:{self.port} {e}")
        finally:
            self.nfs3.disconnect()
            self.disconnection()
