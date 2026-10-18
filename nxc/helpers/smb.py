from impacket.smbconnection import SMBConnection


def get_smb_connection(context, connection, timeout=3):
    """SMB session reusing the credentials of the current connection, or None when it cannot be established.

    A certificate-only bind (--schannel) leaves no secret behind, and logging in without
    one would count as a bad password attempt on the target, so no session is attempted.
    """
    if not connection.has_reusable_secret:
        context.log.fail("Cannot open an SMB session: a certificate-only bind (--schannel) provides no password, hash or Kerberos ticket")
        return None

    smb = SMBConnection(remoteName=connection.remoteName, remoteHost=connection.host, sess_port=445, timeout=timeout)
    if connection.kerberos:
        smb.kerberosLogin(user=connection.username, password=connection.password, domain=connection.domain, lmhash=connection.lmhash, nthash=connection.nthash, aesKey=connection.aesKey, kdcHost=connection.kdcHost, useCache=connection.use_kcache)
    elif connection.nthash or connection.lmhash:
        smb.login(connection.username, "", connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)
    else:
        smb.login(connection.username, connection.password, connection.domain)
    return smb
