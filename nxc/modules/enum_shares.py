from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enumerate shares with detailed permissions information
    Module by NetExec Community
    """

    name = "enum_shares"
    description = "Enumerate all shares with detailed read/write permissions"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        VERBOSE     Show detailed information for each share (default: False)
        """
        self.verbose = False
        if "VERBOSE" in module_options:
            self.verbose = True

    def on_login(self, context, connection):
        """Enumerate shares and their permissions"""
        try:
            shares = connection.conn.listShares()
            
            context.log.display(f"Enumerating shares on {connection.host}")
            readable_shares = []
            writable_shares = []
            
            for share in shares:
                share_name = share["shi1_netname"][:-1]
                share_remark = share["shi1_remark"][:-1] if share["shi1_remark"] else ""
                
                # Skip certain administrative shares if not verbose
                if not self.verbose and share_name.upper() in ["IPC$"]:
                    continue
                
                read_access = False
                write_access = False
                
                # Test read access
                try:
                    connection.conn.listPath(share_name, "*")
                    read_access = True
                    readable_shares.append(share_name)
                except Exception:
                    pass
                
                # Test write access
                try:
                    import uuid
                    temp_file = f"_nxc_test_{str(uuid.uuid4())[:8]}.txt"
                    connection.conn.putFile(share_name, temp_file, lambda: b"test")
                    connection.conn.deleteFile(share_name, temp_file)
                    write_access = True
                    writable_shares.append(share_name)
                except Exception:
                    pass
                
                # Format output
                permissions = []
                if read_access:
                    permissions.append("READ")
                if write_access:
                    permissions.append("WRITE")
                
                if permissions:
                    perm_str = ", ".join(permissions)
                    if write_access:
                        context.log.highlight(f"{share_name:<20} {perm_str:<15} {share_remark}")
                    else:
                        context.log.success(f"{share_name:<20} {perm_str:<15} {share_remark}")
                else:
                    if self.verbose:
                        context.log.display(f"{share_name:<20} {'NO ACCESS':<15} {share_remark}")
            
            # Summary
            context.log.display("")
            context.log.success(f"Found {len(readable_shares)} readable share(s)")
            if writable_shares:
                context.log.highlight(f"Found {len(writable_shares)} writable share(s): {', '.join(writable_shares)}")
                
        except Exception as e:
            context.log.fail(f"Error enumerating shares: {e}")
