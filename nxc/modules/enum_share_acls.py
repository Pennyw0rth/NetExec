# Module by @syl
# https://twitter.com/5yrull

from impacket.smbconnection import SessionError
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.functions.constants import SE_OBJECT_TYPE
from winacl.dtyp.ace import FILE_ACCESS_MASK


AVAILABLE_FILTERS = ["ace_mask", "ace_sid", "owner", "group"]


def get_security_descriptor(file, smb_connection, context, share_name, file_path, filters=None):
    """Retrieving the security descriptor of a certain file on a share"""
    tree_id = smb_connection.connectTree(share_name)
    desired_access = 0x00020000 # READ_CONTROL
    share_mode = 0x00000001 # FILE_SHARE_READ
    create_options = 0x00000040 # FILE_NON_DIRECTORY_FILE
    file_attrs = 0
    create_disposition = 0x00000001 # FILE_DIRECTORY_FILE
    file_full_path = file_path + file.get_longname()
    try:
        file_id = smb_connection.createFile(
            tree_id,
            file_full_path,
            desiredAccess=desired_access,
            shareMode=share_mode,
            creationOption=create_options,
            creationDisposition=create_disposition,
            fileAttributes=file_attrs,
            impersonationLevel=0x00000002, # Impersonation
        )
        
        security_descriptor = smb_connection._SMBConnection.query_sec_info(tree_id, file_id)
        security_descriptor_obj = SECURITY_DESCRIPTOR.from_bytes(
            security_descriptor, object_type=SE_OBJECT_TYPE.SE_FILE_OBJECT
        )

        # Instead printing the ACLs, print the human readable thing like,
        # SID 4959245 has read access to the file policy.xt
        # SID 4839959 has read/write access to the file policy.txt
        # SID 4839959 has full access to the file policy.txt
        
        # Filters aren't working as of now
        if filters:
            for _filter, values in filters.items():
                if _filter == "owner":
                    if security_descriptor_obj.Owner not in values:
                        return
                elif _filter == "group":
                    if security_descriptor_obj.Group not in values:
                        return
                elif _filter == "ace_mask":
                    ace_mask_matched = False
                    for _ace in security_descriptor_obj.Dacl.aces:
                        for value in values:
                            mask = getattr(FILE_ACCESS_MASK, value)
                            if mask == _ace.Mask:
                                ace_mask_matched = True
                                break
                        if ace_mask_matched:
                            break
                    if not ace_mask_matched:
                        return
                elif _filter == "ace_sid":
                    for _ace in security_descriptor_obj.Dacl.aces:
                        if str(_ace.Sid) not in values:
                            return

        context.log.success(f"Obtained security descriptor for: {file_full_path}")
        context.log.highlight("\t Owner:", security_descriptor_obj.Owner)
        context.log.highlight("\t Group:", security_descriptor_obj.Group)
        context.log.highlight("\t SACL:", security_descriptor_obj.Sacl)
        
        if security_descriptor_obj.Dacl is not None:
            context.log.highlight(f"\t ACEs[{len(security_descriptor_obj.Dacl.aces)}]: ")
            for ace in security_descriptor_obj.Dacl.aces:
                if "\r\n" in str(ace):
                    ace_formatted = str(ace).split("\r\n")[:-1]
                    [context.log.highlight(f"\t\t {i}") for i in ace_formatted]
                    context.log.highlight("\t\t " + len(ace_formatted[0]) * "=")
                    
    except SessionError as e:
        context.log.debug(e)

def enumerate_files(smb_connection, share_name, current_path, context, filters=None):
    """Recursive function that enumerates the directories"""
    try:
        file_list = smb_connection.listPath(share_name, current_path + "*")
        for file in file_list:
            if (
                file.is_directory()
                and not file.is_system()
                and file.get_longname() not in [".", ".."]
            ):
                next_path = current_path + file.get_longname() + "/"
                context.log.debug(f"Trying to enumrate files in {next_path}")
                enumerate_files(smb_connection, share_name, next_path, context, filters)
            if not file.is_directory() and not file.is_system():
                context.log.debug(f"File Found {file.get_longname()}")
                get_security_descriptor(file, smb_connection, context, share_name, current_path, filters)
    except SessionError as e:
        context.log.debug(e)


class NXCModule:
    """
    A module to enumerate the ACLs of the files in a share.

    Module by @syl, thanks to @Skelsec and @NeffIsBack
    """
    name = "enum_share_acls"
    description = ""
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.server = None
        self.file_path = None
        self.lnk_path = None
        self.lnk_name = None
        self.cleanup = None

    def options(self, context, module_options):
        """
        group-mem: Specify group-mem to call the module
        GROUP: Specify the GROUP option to query for that group's members
        Usage:
            nxc smb 127.0.0.1 -u administrator -p 'Password123!' -M enum_share_acls -o FILTER="ace_mask=FILE_ALL_ACCESS,ace_sid=S-1-5-32-544"
            nxc smb 127.0.0.1 -u administrator -p 'Password123!' -M enum_share_acls -o FILTER="ace_mask=FILE_ALL_ACCESS|READ_CONTROL,ace_sid=S-1-5-32-544"
            nxc smb 127.0.0.1 -u administrator -p 'Password123!' -M enum_share_acls -o FILTER="owner=S-1-5-32-544"
        """
        self.FILTER = None
        if "FILTER" in module_options:
            self.FILTER = module_options["FILTER"]

    def parse_filters(self):
        parsed_filters = self.FILTER.split(",")
        filters_dict = {}
        masks = [m.name for m in FILE_ACCESS_MASK]
        for _filter in parsed_filters:
            
            splitted_filter = _filter.split("=")

            if splitted_filter[0] not in AVAILABLE_FILTERS:
                return None, f"{_filter} filter isn't available, please choose between {AVAILABLE_FILTERS}"
            
            for __filter in AVAILABLE_FILTERS:
                if __filter in _filter:
                    filters_dict[__filter] = splitted_filter[1]
                    if "|" in filters_dict[__filter]:
                        filters_dict[__filter] = filters_dict[__filter].split("|")
                    else:
                        filters_dict[__filter] = [splitted_filter[1],]

        # Verify the filters
        if "ace_mask" in filters_dict:
            for mask_name in filters_dict["ace_mask"]:
                if mask_name not in masks:
                    return None, f"{mask_name} ace_mask isn't valid, please choose between {mask_name}"
        return filters_dict, None
    
    def on_login(self, context, connection):
        shares = connection.shares()
        smb_connection = connection.conn
        filters = None
        if self.FILTER:
            filters, err = self.parse_filters()
            if err is not None:
                context.log.error(err)
        for share in shares:
            share_name = share["name"]
            context.log.display(f"Enumerating ACLs on share: {share_name}")
            enumerate_files(smb_connection, share_name, "/", context, filters)
