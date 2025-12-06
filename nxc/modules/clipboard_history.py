from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Extract Windows clipboard history data
    Module by NetExec Community
    """

    name = "clipboard_history"
    description = "Extract Windows 10+ clipboard history if enabled"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        USER    Target specific username (default: all users)
        """
        self.target_user = module_options.get("USER", None)

    def on_admin_login(self, context, connection):
        """Extract clipboard history from Windows systems"""
        try:
            context.log.display("Searching for clipboard history data...")
            
            # Clipboard history is stored in ActivitiesCache.db (Windows 10+)
            # Path: %LocalAppData%\Microsoft\Windows\Clipboard\
            
            try:
                users_list = connection.conn.listPath("C$", "Users\\*")
                usernames = [u.get_longname() for u in users_list if u.get_longname() not in [".", "..", "Public", "Default", "All Users"]]
                
                found_count = 0
                
                for username in usernames:
                    # Skip if targeting specific user
                    if self.target_user and username.lower() != self.target_user.lower():
                        continue
                    
                    # Check for clipboard history database
                    clipboard_paths = [
                        f"Users\\{username}\\AppData\\Local\\Microsoft\\Windows\\Clipboard",
                        f"Users\\{username}\\AppData\\Local\\ConnectedDevicesPlatform",
                    ]
                    
                    for clipboard_path in clipboard_paths:
                        try:
                            files = connection.conn.listPath("C$", clipboard_path + "\\*")
                            db_files = [f.get_longname() for f in files if f.get_longname().endswith('.db')]
                            
                            if db_files:
                                for db_file in db_files:
                                    context.log.success(f"Found clipboard database for {username}: {db_file}")
                                    context.log.display(f"  Path: C:\\{clipboard_path}\\{db_file}")
                                    found_count += 1
                        except Exception:
                            pass
                    
                    # Also check for clipboard cache files
                    try:
                        cache_path = f"Users\\{username}\\AppData\\Local\\Microsoft\\Windows\\Clipboard\\*"
                        cache_files = connection.conn.listPath("C$", cache_path)
                        
                        for cache_file in cache_files:
                            if cache_file.get_longname() not in [".", ".."]:
                                context.log.display(f"  Clipboard cache file: {cache_file.get_longname()}")
                    except Exception:
                        pass
                
                if found_count > 0:
                    context.log.highlight(f"Found clipboard data for {found_count} file(s)")
                    context.log.display("Note: Clipboard database files need to be downloaded and parsed locally")
                    context.log.display("Clipboard history requires Windows 10 version 1809+ with history enabled")
                else:
                    context.log.display("No clipboard history data found")
                    context.log.display("Note: Clipboard history must be enabled in Windows Settings")
                    
            except Exception as e:
                context.log.fail(f"Error enumerating users: {e}")
                
        except Exception as e:
            context.log.fail(f"Error extracting clipboard data: {e}")
            context.log.debug(f"Exception: {e}")
