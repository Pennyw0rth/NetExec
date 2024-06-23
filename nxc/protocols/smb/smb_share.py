from nxc.protocols import smb
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SharedFile
from impacket.dcerpc.v5 import transport, lsat, lsad
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.functions.constants import SE_OBJECT_TYPE
from winacl.dtyp.ace import FILE_ACCESS_MASK
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from termcolor import colored
from typing import List


class SMB_Share_Enumeration:
    def __init__(self, nxc_conn: smb, smb_conn: SMBConnection):
        self.nxc_conn = nxc_conn
        self.smb_conn = smb_conn
        self.logger = nxc_conn.logger

    def enumerate_path(self, path: str):
        self.share = path.split(":")[0]
        self.path = path.split(":")[1]
        self.shares = [share["shi1_netname"][:-1] for share in self.nxc_conn.conn.listShares()]
        if self.share not in self.shares:
            self.logger.fail(f"Share {self.share} not found")
            return
        else:
            self.logger.display(f"Enumerating ACLs on share: {self.share}")
            self.enumerate_files(self.share, self.path, recursive=True)

    def enumerate_files(self, share, path: str, recursive: bool = False):
        """Recursive function that enumerates the directories"""
        self.logger.debug(f"Trying to enumrate files in {path}")
        if path[-2:] not in ["\\", "/"]:
            path += "/"
        path.replace("\\", "/")
        try:
            file_list: List[SharedFile] = self.smb_conn.listPath(share, path + "*")
            for file in file_list:
                if (
                    file.is_directory()
                    and not file.is_system()
                    and file.get_longname() not in [".", ".."]
                    and recursive
                ):
                    next_path = path + file.get_longname() + "/"
                    self.enumerate_files(share, next_path, recursive=True)
                if not file.is_directory() and not file.is_system():
                    self.logger.debug(f"File Found {file.get_longname()}")
                    self.get_security_descriptor(file, share, path)
        except SessionError as e:
            self.logger.error(e)


    def get_security_descriptor(self, file, share, path, filters=None):
        """Retrieving the security descriptor of a certain file on a share"""
        tree_id = self.smb_conn.connectTree(share)
        dce = self.get_dce_from_smb()
        desired_access = 0x00020000 # READ_CONTROL
        share_mode = 0x00000001 # FILE_SHARE_READ
        create_options = 0x00000040 # FILE_NON_DIRECTORY_FILE
        file_attrs = 0
        create_disposition = 0x00000001 # FILE_DIRECTORY_FILE
        file_full_path = path + file.get_longname()
        try:
            file_id = self.smb_conn.createFile(
                tree_id,
                file_full_path,
                desiredAccess=desired_access,
                shareMode=share_mode,
                creationOption=create_options,
                creationDisposition=create_disposition,
                fileAttributes=file_attrs,
                impersonationLevel=0x00000002, # Impersonation
            )
            
            security_descriptor = self.smb_conn._SMBConnection.query_sec_info(tree_id, file_id)
            security_descriptor_obj = SECURITY_DESCRIPTOR.from_bytes(
                security_descriptor, object_type=SE_OBJECT_TYPE.SE_FILE_OBJECT
            )

            if filters:
                for _filter, values in filters.items():
                    if _filter == "owner" and str(security_descriptor_obj.Owner) not in values:
                        return
                    if _filter == "group" and str(security_descriptor_obj.Group) not in values:
                        return
                    if _filter == "ace_sid":
                        sids = [str(_ace.Sid) for _ace in security_descriptor_obj.Dacl.aces]
                        for sid in values:
                            if sid in sids:
                                continue
                            else:
                                return
                    if _filter == "ace_mask":
                        masks = [FILE_ACCESS_MASK(_ace.Mask).name for _ace in security_descriptor_obj.Dacl.aces]
                        for mask in values:
                            if mask in masks:
                                continue
                            else:
                                return

            self.logger.success(file_full_path)
            # Also get the user's group to mark it as Owned
            # self.smb_conn._SMBConnection._SMB__userName
            username = self.smb_conn._SMBConnection._SMB__userName
            
            owner = self.lookup_sid(dce, str(security_descriptor_obj.Owner))
            if owner == username:
                owner = owner + colored("Pwn3d!", "red")
            group = self.lookup_sid(dce, str(security_descriptor_obj.Group))
            self.logger.highlight(f"\t Owner: {owner}")
            self.logger.highlight(f"\t Group: {group}")
            self.logger.highlight(f"\t SACL: {security_descriptor_obj.Sacl}")
            
            if security_descriptor_obj.Dacl is not None:
                self.logger.highlight("\t ACEs:")
                for ace in security_descriptor_obj.Dacl.aces:
                    ace_sid_name = self.lookup_sid(dce, str(ace.Sid))
                    mask_formatted = FILE_ACCESS_MASK(ace.Mask).name
                    if mask_formatted is None:
                        continue
                    owned = colored(" (Own3d!)", "red") if ace_sid_name == username else ""
                    self.logger.highlight(f"\t\t {ace_sid_name} - {mask_formatted}{owned}")
        except SessionError as e:
            self.logger.debug(e)

    def get_dce_from_smb(self):
        string_binding = rf"ncacn_np:{self.nxc_conn.remoteName}[\pipe\lsarpc]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_dport(self.nxc_conn.port)
        rpctransport.setRemoteHost(self.nxc_conn.host)
        rpctransport.set_credentials(self.nxc_conn.username, self.nxc_conn.password, self.nxc_conn.domain, self.nxc_conn.lmhash, self.nxc_conn.nthash)
        return rpctransport.get_dce_rpc()

    def lookup_sid(self, dce, sid):
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        policy_response = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policy_handle = policy_response["PolicyHandle"]
        sid_response = lsat.hLsarLookupSids(dce, policy_handle, [sid],lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        sid_name = sid_response["TranslatedNames"]["Names"][0]["Name"]
        dce.disconnect()
        return sid_name
    