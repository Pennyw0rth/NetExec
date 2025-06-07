import sys
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException


class NXCModule:
    """
    Module for changing or resetting user passwords
    Module by Fagan Afandiyev, termanix and NeffIsBack
    """

    name = "change-password"
    description = "Change or reset user passwords via various protocols"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Required (one of):
        NEWPASS     The new password of the user.
        NEWNTHASH   The new NT hash of the user.

        Optional:
        USER        The user account if the target is not the current user.

        Examples
        --------
        If STATUS_PASSWORD_MUST_CHANGE or STATUS_PASSWORD_EXPIRED (Change password for current user)
            netexec smb <DC_IP> -u username -p oldpass -M change-password -o NEWNTHASH='nthash'
            netexec smb <DC_IP> -u username -H oldnthash -M change-password -o NEWPASS='newpass'

        If want to change other user's password (with forcechangepassword priv or admin rights)
            netexec smb <DC_IP> -u username -p password -M change-password -o USER='target_user' NEWPASS='target_user_newpass'
            netexec smb <DC_IP> -u username -p password -M change-password -o USER='target_user' NEWNTHASH='target_user_newnthash'
        """
        self.newpass = module_options.get("NEWPASS")
        self.newhash = module_options.get("NEWNTHASH")
        self.target_user = module_options.get("USER")

        if not self.newpass and not self.newhash:
            context.log.fail("Either NEWPASS or NEWNTHASH is required!")
            sys.exit(1)

    def authenticate(self, context, connection, protocol, anonymous=False):
        # Authenticate to the target using DCE/RPC with either user credentials or a null session. Establishes a connection and binds to the SAMR service.
        try:
            # Map to the SAMR endpoint on the target
            string_binding = epm.hept_map(connection.host, samr.MSRPC_UUID_SAMR, protocol=protocol)
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(connection.host)

            if anonymous:
                rpctransport.set_credentials("", "", "", "", "", "")
                rpctransport.set_kerberos(False, None)
                context.log.info("Connecting with null session credentials.")
            else:
                rpctransport.set_credentials(
                    connection.username,
                    connection.password,
                    connection.domain,
                    connection.lmhash,
                    connection.nthash,
                    aesKey=connection.aesKey,
                )
                context.log.info(f"Connecting as {connection.domain}\\{connection.username}")

            # Connect to the DCE/RPC endpoint and bind to the SAMR service
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            context.log.info("[+] Successfully connected to DCE/RPC")
            dce.bind(samr.MSRPC_UUID_SAMR)
            context.log.info("[+] Successfully bound to SAMR")
            return dce
        except DCERPCException as e:
            context.log.fail(f"DCE/RPC Exception: {e!s}")
            raise

    def on_login(self, context, connection):
        self.context = context
        target_username = self.target_user or connection.username
        target_domain = connection.domain

        # Grab all creds from the connection to use for authentication
        self.oldpass = connection.password
        self.oldhash = connection.nthash

        new_lmhash, new_nthash = "", ""

        # Parse new hash values if provided
        if self.newhash:
            try:
                new_lmhash, new_nthash = self.newhash.split(":")
            except ValueError:
                new_nthash = self.newhash

        try:
            self.anonymous = False
            self.dce = self.authenticate(context, connection, protocol="ncacn_np", anonymous=self.anonymous)
        except Exception as e:
            # Handle specific errors like password expiration or must be change
            if "STATUS_PASSWORD_MUST_CHANGE" in str(e) or "STATUS_PASSWORD_EXPIRED" in str(e):
                context.log.warning("Password must be changed. Trying with null session.")
                self.anonymous = True
                self.dce = self.authenticate(context, connection, protocol="ncacn_ip_tcp", anonymous=self.anonymous)
            elif "STATUS_LOGON_FAILURE" in str(e):
                context.log.fail("Authentication failure: wrong credentials.")
                return False
            else:
                raise

        try:
            # Perform the SMB SAMR password change
            self._smb_samr_change(context, connection, target_username, target_domain, self.oldhash, self.newpass, new_nthash)
        except Exception as e:
            context.log.fail(f"Password change failed: {e}")

    def _smb_samr_change(self, context, connection, target_username, target_domain, oldHash, newPassword, newHash):
        try:
            # Reset the password for a different user
            if target_username != connection.username:
                user_handle = self._hSamrOpenUser(connection, target_username)
                samr.hSamrSetNTInternal1(self.dce, user_handle, newPassword, newHash)
                context.log.success(f"Successfully changed password for {target_username}")
            else:
                # Change password for the current user
                if newPassword:
                    # Change the password with new password
                    samr.hSamrUnicodeChangePasswordUser2(self.dce, "\x00", target_username, self.oldpass, newPassword, "", oldHash)
                else:
                    # Change the password with new hash
                    user_handle = self._hSamrOpenUser(connection, target_username)
                    samr.hSamrChangePasswordUser(self.dce, user_handle, self.oldpass, "", oldHash, "aad3b435b51404eeaad3b435b51404ee", newHash)
                    context.log.highlight("Note: Target user must change password at next logon.")
                context.log.success(f"Successfully changed password for {target_username}")
        except Exception as e:
            context.log.fail(f"SMB-SAMR password change failed: {e}")
        finally:
            self.dce.disconnect()

    def _hSamrOpenUser(self, connection, username):
        """Get handle to the user object"""
        try:
            # Connect to the target server and retrieve handles
            server_handle = samr.hSamrConnect(self.dce, connection.host + "\x00")["ServerHandle"]
            domain_sid = samr.hSamrLookupDomainInSamServer(self.dce, server_handle, connection.domain)["DomainId"]
            domain_handle = samr.hSamrOpenDomain(self.dce, server_handle, domainId=domain_sid)["DomainHandle"]
            user_rid = samr.hSamrLookupNamesInDomain(self.dce, domain_handle, (username,))["RelativeIds"]["Element"][0]
            return samr.hSamrOpenUser(self.dce, domain_handle, userId=user_rid)["UserHandle"]
        except Exception as e:
            self.context.log.fail(f"Failed to open user: {e}")
