import os
import ntpath
import shutil
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from impacket.smb3structs import FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE
from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.dtypes import OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION
from impacket.ldap.ldaptypes import ACCESS_MASK
from impacket.ldap import ldaptypes
from nxc.config import process_secret
from nxc.protocols.smb.samrfunc import LSAQuery


class NXCModule:
    """Module by @Marshall-Hallenbeck
    Do things with Group Policy Objects (GPOs) in Active Directory
    """

    name = "gpos"
    description = "Do things with Group Policy Objects (GPOs) in Active Directory"
    supported_protocols = ["smb"]

    def __init__(self):
        self.context = None
        self.module_options = None
        self.gpo_name = None
        self.fuzzy_search = False
        self.all_props = False
        self.download = True
        self.download_dest = "Retrieved_GPOs"

    def options(self, context, module_options):
        """
        NAME        Name of the GPO (default retrieve all GPOs)
        FUZZY       Fuzzy search for name of GPOs (using wildcards)
        ALL_PROPS   Retrieve all properties of the GPO (default is name, guid, and sysfile path)
        DOWNLOAD    Download the GPOs to the local machine (default is True)
        DEST        Destination folder for downloaded GPOs (default is "Retrieved_GPOs")
        LIST_PERMISSIONS List permissions for the GPOs (default is False)
        """
        self.gpo_name = module_options.get("NAME")
        self.fuzzy_search = module_options.get("FUZZY")
        self.all_props = module_options.get("ALL_PROPS")
        self.download = module_options.get("DOWNLOAD", True)
        self.download_dest = module_options.get("DEST", "Retrieved_GPOs")
        self.list_permissions = module_options.get("LIST_PERMISSIONS", False)

    def on_login(self, context, connection):
        context.log.display("Searching for GPOs via SMB in SYSVOL share")

        # list the contents of SYSVOL to find the domain folder
        policies = connection.conn.listPath("SYSVOL", f"{connection.domain}\\Policies\\*")
        context.log.debug(f"Found policies path: {connection.domain}\\Policies")
        context.log.debug(f"Found folders in policies path: {policies}")

        gpos_found = []

        for item in policies:
            item_name = item.get_longname()
            context.log.debug(f"Item: {item}, Item name: {item_name}")
            # make sure it's a directory and not ./.. and check if it's a GUID folder (typical format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})
            if item_name not in [".", ".."] and item.is_directory() and item_name.startswith("{") and item_name.endswith("}"):
                gpo_guid = item_name
                gpo_path = os.path.join(f"{connection.domain}", "Policies", f"{gpo_guid}")

                gpos_found.append((gpo_guid, gpo_path))

                tid = connection.conn.connectTree("SYSVOL")
                context.log.debug(f"TID: {tid}")
                fid = connection.conn.openFile(tid, gpo_path, shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, creationOption=0, desiredAccess=FILE_READ_ATTRIBUTES)
                context.log.debug(f"FID: {fid}")

                if self.list_permissions:
                    self.get_folder_security_info(context, connection, gpo_guid, gpo_path)

                connection.conn.closeFile(tid, fid)
                connection.conn.disconnectTree(tid)

                if self.gpo_name:
                    # try to find the GPO's display name by checking for gpt.ini
                    display_name = self.get_gpo_display_name(context, connection, gpo_path)

                    # filter by display name if specified
                    if self.gpo_name:
                        match = self.gpo_name.lower() in display_name.lower() if self.fuzzy_search else self.gpo_name.lower() == display_name.lower()

                        if not match:
                            continue

                    context.log.success(f"GPO Found: '{display_name}'")
                    context.log.highlight(f"Display Name: {display_name}")
                    context.log.highlight(f"GUID: {gpo_guid}")
                    context.log.highlight(f"GPO Path: \\\\SYSVOL\\{gpo_path}")
                else:
                    # if no GPO name filter, just show all
                    display_name = self.get_gpo_display_name(context, connection, gpo_path)
                    context.log.success(f"GPO Found: '{display_name}'")
                    context.log.highlight(f"Display Name: {display_name}")
                    context.log.highlight(f"GUID: {gpo_guid}")
                    context.log.highlight(f"GPO Path: \\\\SYSVOL\\{gpo_path}")

                if self.download:
                    context.log.display(f"Downloading GPO {gpo_guid} from SYSVOL share")
                    self.download_gpo(context, connection, gpo_path, self.download_dest, gpo_guid)

        context.log.success(f"GPOs Found: {len(gpos_found)}")

    def get_gpo_display_name(self, context, connection, gpo_path):
        """Try to get the display name of a GPO by reading gpt.ini file directly into memory"""
        try:
            ini_path = f"{gpo_path}\\GPT.ini"
            context.log.debug(f"GPT.ini path: {ini_path}")
            ini_content = bytearray()

            # read the file directly into memory through a callback
            def callback(data):
                ini_content.extend(data)

            connection.conn.getFile("SYSVOL", ini_path, callback)
            display_name = "Unknown"
            ini_text = ini_content.decode("utf-8", errors="replace")

            for line in ini_text.splitlines():
                if line.lower().startswith("displayname="):
                    display_name = line.strip().split("=", 1)[1]
                    break

            return display_name
        except Exception as e:
            context.log.debug(f"Could not read GPO display name: {e}")
            # extract GUID from path as fallback name
            return ntpath.basename(gpo_path)

    def download_gpo(self, context, smb_conn, sysvol_path, dest_folder, guid):
        """Download a GPO from the SYSVOL share using the appropriate method"""
        context.log.debug(f"Downloading GPO {guid} from {sysvol_path} to {dest_folder}")

        # save the original share to reset it later, since we need to download from SYSVOL
        original_share = smb_conn.args.share

        try:
            smb_conn.args.share = "SYSVOL"
            smb_conn.download_folder(sysvol_path, dest_folder, recursive=True)
            context.log.success(f"GPO {guid} downloaded to {dest_folder}")
        except Exception as e:
            context.log.fail(f"Error downloading GPO {guid}: {e}")
            # clean up the directory if it was created and download failed
            if os.path.exists(dest_folder):
                try:
                    shutil.rmtree(dest_folder)
                except Exception as cleanup_error:
                    context.log.debug(f"Error cleaning up directory: {cleanup_error}")

            context.log.highlight("To manually download this GPO, use the following command:")
            context.log.highlight(f"nxc smb {smb_conn.host} -u '{smb_conn.username}' -p '{process_secret(smb_conn.password)}' --share SYSVOL --get-folder '{sysvol_path}' '{dest_folder}' --recursive")
        finally:
            # reset the share to the original share
            smb_conn.args.share = original_share

    def parse_aces(self, context, sd):
        """Parse ACEs from security descriptor and display all permissions"""
        if not sd["Dacl"]:
            context.log.highlight("  No DACL found - no access restrictions")
            return

        ace_count = sd["Dacl"]["AceCount"]
        context.log.highlight(f"  DACL: {ace_count} ACEs (Access Control Entries)")

        context.log.debug(f"DACL AceCount: {ace_count}")
        context.log.debug(f"DACL Data: {sd['Dacl']}")

        for i in range(ace_count):
            try:
                ace = sd["Dacl"]["Data"][i]
                ace_type = ace["TypeName"]

                # ACCESS_MASK is accessed from the ACE's Ace field
                # based on ldaptypes structure: ace['Ace']['Mask']['Mask']
                access_mask = int(ace["Ace"]["Mask"]["Mask"])

                sid = ace["Ace"]["Sid"].formatCanonical()
                context.log.debug(f"ACE {i} mask: 0x{access_mask:08x}")

                # create a lookup dictionary mapping ACCESS_MASK constants to permission names
                mask_lookup = {
                    ACCESS_MASK.GENERIC_READ: "GENERIC_READ",
                    ACCESS_MASK.GENERIC_WRITE: "GENERIC_WRITE",
                    ACCESS_MASK.GENERIC_EXECUTE: "GENERIC_EXECUTE",
                    ACCESS_MASK.GENERIC_ALL: "GENERIC_ALL",
                    ACCESS_MASK.MAXIMUM_ALLOWED: "MAXIMUM_ALLOWED",
                    ACCESS_MASK.ACCESS_SYSTEM_SECURITY: "ACCESS_SYSTEM_SECURITY",
                    ACCESS_MASK.SYNCHRONIZE: "SYNCHRONIZE",
                    ACCESS_MASK.WRITE_OWNER: "WRITE_OWNER",
                    ACCESS_MASK.WRITE_DACL: "WRITE_DACL",
                    ACCESS_MASK.READ_CONTROL: "READ_CONTROL",
                    ACCESS_MASK.DELETE: "DELETE",
                    # file system rights
                    0x00000001: "FILE_READ_DATA",
                    0x00000002: "FILE_WRITE_DATA",
                    0x00000004: "FILE_APPEND_DATA",
                    0x00000008: "FILE_READ_EA",
                    0x00000010: "FILE_WRITE_EA",
                    0x00000020: "FILE_EXECUTE",
                    0x00000040: "FILE_DELETE_CHILD",
                    0x00000080: "FILE_READ_ATTRIBUTES",
                    0x00000100: "FILE_WRITE_ATTRIBUTES"
                }

                # build permissions list using the lookup dictionary
                permissions = [mask_name for mask_value, mask_name in mask_lookup.items() if access_mask & mask_value]

                # if no specific permissions found, show the raw mask
                perm_str = ", ".join(permissions) if permissions else f"0x{access_mask:08x}"

                context.log.highlight(f"    ACE {i + 1}: {ace_type}")
                context.log.highlight(f"         SID: {sid} - {ace['Ace']['SidName']}")
                context.log.highlight(f"         Permissions: {perm_str}")
            except Exception as ace_error:
                context.log.debug(f"Error parsing ACE {i}: {ace_error}")
                context.log.debug(f"ACE object structure: {ace}")
                context.log.debug(f"ACE keys: {list(ace.keys()) if hasattr(ace, 'keys') else 'No keys'}")
                continue

    def get_folder_security_info(self, context, connection, gpo_guid, gpo_path):
        """Get security information for a GPO folder and analyze permissions"""
        rpc_transport = transport.SMBTransport(
            connection.host,
            connection.host,
            filename=r"\srvsvc",  # named pipe for SRVS service
            smb_connection=connection.conn
        )

        rpc_transport.set_credentials(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash,
            connection.aesKey,
        )
        rpc_transport.set_kerberos(connection.kerberos, connection.kdcHost)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        context.log.debug("Connected to SRVS")

        sec_info = (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

        # format paths correctly for Windows RPC (note null terminator!)
        share_name = "SYSVOL\x00"
        gpo_path_fixed = gpo_path.replace("/", "\\")
        rpc_path = f"\\{gpo_path_fixed}\x00"

        context.log.debug(f"Getting security info for GPO path: {rpc_path.rstrip(chr(0))}")

        sec_info = srvs.hNetrpGetFileSecurity(dce, share_name, rpc_path, sec_info)
        context.log.success(f"Retrieved security information ({len(sec_info)} bytes)")

        try:
            lsa_query = LSAQuery(
                connection.username,
                connection.password,
                connection.domain,
                connection.port,
                connection.host,
                connection.host,
                connection.kdcHost,
                connection.aesKey,
                connection.kerberos,
                logger=context.log,
            )
        except Exception as lsa_error:
            context.log.debug(f"Error creating LSAQuery: {lsa_error}")
            return

        sec_desc = ldaptypes.SR_SECURITY_DESCRIPTOR(sec_info)
        context.log.highlight(f"Security Descriptor for GPO {gpo_guid}:")

        context.log.debug(f"Security information: {sec_desc}")
        context.log.debug(f"Owner SID: {sec_desc['OwnerSid'].formatCanonical()}")
        context.log.debug(f"Group SID: {sec_desc['GroupSid'].formatCanonical()}")
        sid_names = lsa_query.lookup_sids([sec_desc["OwnerSid"].formatCanonical(), sec_desc["GroupSid"].formatCanonical()])
        context.log.debug(f"SID names: {sid_names}")

        for i, ace in enumerate(sec_desc["Dacl"]["Data"]):
            try:
                sec_desc["Dacl"]["Data"][i]["Ace"]["SidName"] = lsa_query.lookup_sids([ace["Ace"]["Sid"].formatCanonical()])[0]
                context.log.debug(f"{sec_desc['Dacl']['Data'][i]['Ace']['SidName']}")
            except DCERPCSessionError as e:
                sec_desc["Dacl"]["Data"][i]["Ace"]["SidName"] = "Unknown (potentially deleted user)"
                context.log.debug(f"Error looking up SID: {e}")
                continue

        if sec_desc["OwnerSid"]:
            context.log.highlight(f"  Owner SID: {sec_desc['OwnerSid'].formatCanonical()} - {sid_names[0]}")
        if sec_desc["GroupSid"]:
            context.log.highlight(f"  Group SID: {sec_desc['GroupSid'].formatCanonical()} - {sid_names[1]}")
        if sec_desc["Dacl"]:
            self.parse_aces(context, sec_desc)

        dce.disconnect()
