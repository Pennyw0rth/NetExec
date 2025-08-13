import os
import ntpath
import shutil
from nxc.config import process_secret


class NXCModule:
    """Module by @Marshall-Hallenbeck
    Retrieves Group Policy Objects (GPOs) in Active Directory
    TODO: Add LDAP method
    """
    
    name = "get_gpos"
    description = "Retrieves Group Policy Objects (GPOs) in Active Directory"
    supported_protocols = ["smb"]
    
    def __init__(self):
        self.context = None
        self.module_options = None
        self.gpo_name = None
        self.fuzzy_search = False
        self.all_props = False
        self.download = True
        self.download_dest = "GPOs"
        
    def options(self, context, module_options):
        """
        NAME        Name of the GPO (default retrieve all GPOs)
        FUZZY       Fuzzy search for name of GPOs (using wildcards)
        ALL_PROPS   Retrieve all properties of the GPO (default is name, guid, and sysfile path)
        DOWNLOAD    Download the GPOs to the local machine (default is True)
        DEST        Destination folder for downloaded GPOs (default is "GPOs")
        """
        self.gpo_name = module_options.get("NAME")
        self.fuzzy_search = module_options.get("FUZZY")
        self.all_props = module_options.get("ALL_PROPS")
        self.download = module_options.get("DOWNLOAD", "True").lower() == "true"
        self.download_dest = module_options.get("DEST", "GPOs")
        
    def on_login(self, context, connection):
        """Main entry point that determines which protocol method to use"""        
        return self.smb_method(context, connection)

    def smb_method(self, context, connection):
        """Find GPOs by browsing SYSVOL share"""
        context.log.display("Searching for GPOs via SMB in SYSVOL share")
                
        try:
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
                        dest_folder = os.path.join(self.download_dest, gpo_path, gpo_guid.strip("{}"))
                        context.log.display(f"Downloading GPO {gpo_guid} from SYSVOL share")
                        self.download_gpo(context, connection, gpo_path, dest_folder, gpo_guid)

            context.log.success(f"GPOs Found: {len(gpos_found)}")
        except Exception as e:
            context.log.fail(f"Error searching GPOs via SMB: {e}")
    
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