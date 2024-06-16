# Module by @syl
# https://twitter.com/5yrull
# S-1-5-21-3750225908-897271529-2201778708-1103
# 'S-1-5-21-3750225908-897271529-2201778708'
# (Pdb) resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
# (Pdb) domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
# (Pdb) domainSid
# 'S-1-5-21-3750225908-897271529-2201778708'
# (Pdb) lsat.hLsarLookupSids(dce, policyHandle, ['S-1-5-21-3750225908-897271529-2201778708-1103'],lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
# <impacket.dcerpc.v5.lsat.LsarLookupSidsResponse object at 0x7f041cba9d50>
# (Pdb) resp = lsat.hLsarLookupSids(dce, policyHandle, ['S-1-5-21-3750225908-897271529-2201778708-1103'],lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
# (Pdb) resp
# <impacket.dcerpc.v5.lsat.LsarLookupSidsResponse object at 0x7f041cba9de0>
# (Pdb) resp.__dict__
# {'_isNDR64': False, 'fields': {'ReferencedDomains': <impacket.dcerpc.v5.lsat.PLSAPR_REFERENCED_DOMAIN_LIST object at 0x7f041cba9ea0>, 'TranslatedNames': <impacket.dcerpc.v5.lsat.LSAPR_TRANSLATED_NAMES object at 0x7f041cba9450>, 'MappedCount': <impacket.dcerpc.v5.ndr.NDRULONG object at 0x7f041cba9270>, 'ErrorCode': <impacket.dcerpc.v5.ndr.NDRULONG object at 0x7f041cba8460>}}
# (Pdb) resp.TranslatedNames
# *** AttributeError: 'LsarLookupSidsResponse' object has no attribute 'TranslatedNames'
# (Pdb) resp["TranslatedNames"]
# <impacket.dcerpc.v5.lsat.LSAPR_TRANSLATED_NAMES object at 0x7f041cba9450>
# (Pdb) resp["TranslatedNames"].__dict__
# {'_isNDR64': False, 'fields': {'Entries': <impacket.dcerpc.v5.ndr.NDRULONG object at 0x7f041cba9960>, 'Names': <impacket.dcerpc.v5.lsat.PLSAPR_TRANSLATED_NAME_ARRAY object at 0x7f041cba9a80>}}
# (Pdb) resp["TranslatedNames"]["Names"]
# [<impacket.dcerpc.v5.lsat.LSAPR_TRANSLATED_NAME object at 0x7f041cba8a60>]
# (Pdb) resp["TranslatedNames"]["Names"][0].__dict_
# *** AttributeError: 'LSAPR_TRANSLATED_NAME' object has no attribute '__dict_'
# (Pdb) resp["TranslatedNames"]["Names"][0].__dict__
# {'_isNDR64': False, 'fields': {'Use': <impacket.dcerpc.v5.samr.SID_NAME_USE object at 0x7f041cba8c70>, 'Name': <impacket.dcerpc.v5.dtypes.RPC_UNICODE_STRING object at 0x7f041cba8be0>, 'DomainIndex': <impacket.dcerpc.v5.ndr.NDRLONG object at 0x7f041cba8ca0>}}
# (Pdb) resp["TranslatedNames"]["Names"][0]["name"]
# *** KeyError: 'name'
# (Pdb) resp["TranslatedNames"]["Names"][0]["Name"]
# 'George.Hotz'
# (Pdb) 

from impacket.smbconnection import SessionError
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.functions.constants import SE_OBJECT_TYPE
from winacl.dtyp.ace import FILE_ACCESS_MASK
from termcolor import colored

def get_dce_from_smb(conn):
    string_binding = rf"ncacn_np:{conn.remoteName}[\pipe\lsarpc]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_dport(conn.port)
    rpctransport.setRemoteHost(conn.host)
    rpctransport.set_credentials(conn.username, conn.password, conn.domain, conn.lmhash, conn.nthash)
    return rpctransport.get_dce_rpc()

def lookup_sid(dce, sid):
    dce.connect()
    dce.bind(lsat.MSRPC_UUID_LSAT)
    policy_response = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
    policy_handle = policy_response["PolicyHandle"]
    sid_response = lsat.hLsarLookupSids(dce, policy_handle, [sid],lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
    sid_name = sid_response["TranslatedNames"]["Names"][0]["Name"]
    dce.disconnect()
    return sid_name

AVAILABLE_FILTERS = ["ace_mask", "ace_sid", "owner", "group"]
READ_CONTROL = 0x00020000
FILE_SHARE_READ = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_DIRECTORY_FILE = 0x00000001
IMPERSONATION = 0x00000002

class SMBACLEnumerator:
    
    AVAILABLE_FILTERS = ["ace_mask", "ace_sid", "owner", "group"]
    
    def __init__(self, connection, context, module_options) -> None:
        self.connection = connection
        self.smb_connection = connection.conn
        self.context = context
        self.module_options = module_options
        self.filters = self.parse_filters(self.module_options)
        self.shares = self.get_shares()
        
    def get_shares(self):
        shares = self.connection.shares()
    
    def parse_filters(self, options: dict) -> dict:
        ...
        
    def get_security_descriptor() -> None:
        ...

# def get_security_descriptor(file, smb_connection, context, share_name, file_path, filters=None):
#     """
#     Retrieve the security descriptor of a file on a share.

#     Parameters
#     ----------
#         file: File object.
#         smb_connection: SMB connection instance.
#         context: Context for logging.
#         share_name: Name of the SMB share.
#         file_path: Path of the file.
#         filters: Optional filters for security descriptor components.

#     Returns
#     -------
#         None: If the file does not meet the filter criteria.
#     """
#     file_full_path = file_path + file.get_longname()
#     tree_id = smb_connection.connectTree(share_name)
#     file_id = create_file(smb_connection, tree_id, file_full_path)

#     try:
#         security_descriptor = smb_connection._SMBConnection.query_sec_info(tree_id, file_id)
#         security_descriptor_obj = parse_security_descriptor(security_descriptor)

#         if filters and not passes_filters(security_descriptor_obj, filters):
#             return

#         log_security_descriptor(context, file_full_path, security_descriptor_obj)
#     except SessionError as e:
#         context.log.debug(e)


# def create_file(smb_connection, tree_id, file_full_path):
#     """Create a file in the SMB share and return its ID."""
#     return smb_connection.createFile(
#         tree_id,
#         file_full_path,
#         desiredAccess=READ_CONTROL,
#         shareMode=FILE_SHARE_READ,
#         creationOption=FILE_NON_DIRECTORY_FILE,
#         creationDisposition=FILE_DIRECTORY_FILE,
#         fileAttributes=0,
#         impersonationLevel=IMPERSONATION,
#     )


# def parse_security_descriptor(security_descriptor):
#     """Parse the security descriptor from bytes to an object."""
#     return SECURITY_DESCRIPTOR.from_bytes(
#         security_descriptor, object_type=SE_OBJECT_TYPE.SE_FILE_OBJECT
#     )


# def passes_filters(security_descriptor_obj, filters):
#     """
#     Check if the security descriptor object passes the given filter criteria.

#     Parameters
#     ----------
#         security_descriptor_obj: The security descriptor object.
#         filters: Dictionary of filter criteria.

#     Returns
#     -------
#         bool: True if the descriptor passes all filters, False otherwise.
#     """
#     for filter_type, values in filters.items():
#         if filter_type == "owner" and str(security_descriptor_obj.Owner) not in values:
#             return False
#         if filter_type == "group" and str(security_descriptor_obj.Group) not in values:
#             return False
#         if filter_type == "ace_sid":
#             sids = [str(ace.Sid) for ace in security_descriptor_obj.Dacl.aces]
#             if not any(sid in sids for sid in values):
#                 return False
#         if filter_type == "ace_mask":
#             masks = [FILE_ACCESS_MASK(ace.Mask).name for ace in security_descriptor_obj.Dacl.aces]
#             if not any(mask in masks for mask in values):
#                 return False
#     return True


def log_security_descriptor(context, file_path, descriptor_obj):
    """
    Log details about the security descriptor.

    Parameters
    ----------
        context: Context for logging.
        file_path: Path of the file.
        descriptor_obj: The security descriptor object.
    """
    context.log.success(file_path)
    context.log.highlight(f"\t Owner: {descriptor_obj.Owner}")
    context.log.highlight(f"\t Group: {descriptor_obj.Group}")
    context.log.highlight(f"\t SACL: {descriptor_obj.Sacl}")

    if descriptor_obj.Dacl is not None:
        context.log.highlight(f"\t ACEs[{len(descriptor_obj.Dacl.aces)}]: ")
        for ace in descriptor_obj.Dacl.aces:
            ace_str = str(ace)
            if "\r\n" in ace_str:
                ace_formatted = ace_str.split("\r\n")[:-1]
                for line in ace_formatted:
                    context.log.highlight(f"\t\t {line}")
                context.log.highlight("\t\t " + len(ace_formatted[0]) * "=")
            else:
                context.log.highlight(f"\t\t {ace_str}")

def get_security_descriptor(conn, file, smb_connection, context, share_name, file_path, filters=None):
    """Retrieving the security descriptor of a certain file on a share"""
    tree_id = smb_connection.connectTree(share_name)
    dce = get_dce_from_smb(conn)
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

        context.log.success(file_full_path)
        # Also get the user's group to mark it as Owned
        # smb_connection._SMBConnection._SMB__userName
        username = smb_connection._SMBConnection._SMB__userName
        
        owner = lookup_sid(dce, str(security_descriptor_obj.Owner))
        if owner == username:
            owner = owner + colored("Pwn3d!", "red")
        group = lookup_sid(dce, str(security_descriptor_obj.Group))
        context.log.highlight(f"\t Owner: {owner}")
        context.log.highlight(f"\t Group: {group}")
        context.log.highlight(f"\t SACL: {security_descriptor_obj.Sacl}")
        
        if security_descriptor_obj.Dacl is not None:
            context.log.highlight("\t ACEs:")
            for ace in security_descriptor_obj.Dacl.aces:
                ace_sid_name = lookup_sid(dce, str(ace.Sid))
                mask_formatted = FILE_ACCESS_MASK(ace.Mask).name
                if mask_formatted is None:
                    continue
                owned = colored(" (Own3d!)", "red") if ace_sid_name == username else ""
                context.log.highlight(f"\t\t {ace_sid_name} - {mask_formatted}{owned}")
    except SessionError as e:
        context.log.debug(e)

def enumerate_files(conn, smb_connection, share_name, current_path, context, filters=None):
    """Recursive function that enumerates the directories"""
    try:
        print(f"{smb_connection=} {share_name=} {current_path=}")
        file_list = smb_connection.listPath(share_name, current_path + "*")
        for file in file_list:
            if (
                file.is_directory()
                and not file.is_system()
                and file.get_longname() not in [".", ".."]
            ):
                next_path = current_path + file.get_longname() + "/"
                context.log.debug(f"Trying to enumrate files in {next_path}")
                enumerate_files(conn, smb_connection, share_name, next_path, context, filters)
            if not file.is_directory() and not file.is_system():
                context.log.debug(f"File Found {file.get_longname()}")
                get_security_descriptor(conn, file, smb_connection, context, share_name, current_path, filters)
    except SessionError as e:
        context.log.error(e)


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
            enumerate_files(connection, smb_connection, share_name, "/", context, filters)
