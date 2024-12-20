import sys

class NXCModule:
    """
    Module for changing or resetting user passwords
    Module by Fagan Afandiyev

    This is NXC implementation of changepasswd.py from impacket
    """

    name = "change-password"
    description = "Change or reset user passwords via various protocols"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Module options for password change
        
        Supported options:
        - NEWPASS: New password to set
        - NEWHASH: New password hash (NTHASH or LMHASH:NTHASH)
        - OLDPASS: Current password (optional for reset)
        - USER: User whose password to change (default is current user)
        - RESET: Set to True to reset password with admin privileges
        """
        self.newpass = module_options.get("NEWPASS")
        self.newhash = module_options.get("NEWHASH")
        self.oldpass = module_options.get("OLDPASS")
        self.target_user = module_options.get("USER")
        self.reset = module_options.get("RESET", True)

        if not self.newpass and not self.newhash:
            context.log.error("Either NEWPASS or NEWHASH is required!")
            sys.exit(1)

    def on_login(self, context, connection):
        # Determine which user's password to change (prioritize TARGETUSER)
        target_username = self.target_user if self.target_user else connection.username
        target_domain = connection.domain

        # Prepare authentication details
        username = connection.username
        domain = connection.domain
        password = connection.password
        lmhash, nthash = "", ""

        if context.hash and ":" in context.hash[0]:
            hash_list = context.hash[0].split(":")
            nthash = hash_list[-1]
            lmhash = hash_list[0]
        elif context.hash:
            nthash = context.hash[0]
            lmhash = "00000000000000000000000000000000"

        # Prepare new password details
        new_password = None  # Start with None for new_password
        new_lmhash, new_nthash = "", ""
        
        if self.newpass:
            # If NEWPASS is provided, use it
            new_password = self.newpass

        if self.newhash:
            # If NEWHASH is provided, split the hash and set new password to None
            try:
                new_lmhash, new_nthash = self.newhash.split(":")
                new_password = None  # Don't set a plain password when using a hash
            except ValueError:
                new_lmhash = "00000000000000000000000000000000"
                new_nthash = self.newhash
                new_password = None  # Ensure no password is set for hash-only change

        # Use the appropriate protocol based on netexec's context
        protocol = "smb"

        try:
            if protocol == "smb":
                self._smb_samr_change(
                    context, connection, target_username, target_domain, username, domain, password,
                    lmhash, nthash, self.oldpass, new_password, new_lmhash, new_nthash
                )
            else:
                context.log.error(f"Unsupported protocol: {protocol}")
                sys.exit(1)
        except Exception as e:
            context.log.error(f"Password change failed: {e!s}")

    def _smb_samr_change(self, context, connection, target_username, target_domain,
                        username, domain, password, lmhash, nthash,
                        old_password, new_password, new_lmhash, new_nthash):
        """Change password using SMB-SAMR protocol"""
        from impacket.dcerpc.v5 import samr, epm, transport

        if not new_password and not new_lmhash and not new_nthash:
            context.log.error("New password or hash cannot be None or empty")
            return
        string_binding = epm.hept_map(connection.host, samr.MSRPC_UUID_SAMR, protocol="ncacn_np")
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.setRemoteHost(connection.host)

        if hasattr(rpc_transport, "set_credentials"):
            rpc_transport.set_credentials(username, password, domain, lmhash, nthash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            server_handle = samr.hSamrConnect(dce, connection.host + "\x00")["ServerHandle"]
            domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, target_domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
            user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (target_username,))["RelativeIds"]["Element"][0]
            user_handle = samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)["UserHandle"]
            if self.reset:
                samr.hSamrSetNTInternal1(dce, user_handle, new_password, new_nthash)
                context.log.success(f"Successfully reset password for {target_username}")
            else:
                try:
                    if new_password:
                        # If using new password
                        samr.hSamrUnicodeChangePasswordUser2(
                            dce, "\x00", target_username, old_password, new_password, "", ""
                        )
                    elif new_lmhash and new_nthash:
                        # If using hash (NEWHASH)
                        samr.hSamrSetNTInternal1(dce, user_handle, new_password, new_nthash)
                        context.log.success(f"Successfully changed password for {target_username}")
                except AttributeError as encode_error:
                    context.log.error(f"Encoding issue in new password: {encode_error!s}")
                    return
        except Exception as e:
            context.log.error(f"SMB-SAMR password change failed: {e!s}")
        finally:
            dce.disconnect()