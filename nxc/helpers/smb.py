from impacket.smbconnection import SMBConnection


def get_smb_connection(connection, timeout=3):
    """SMB session reusing the credentials of the current connection.

    Callers must check connection.has_reusable_secret first: a certificate-only bind
    (--schannel) has no secret left, and the empty NTLM login below would count as a
    bad password attempt on the target.
    """
    smb = SMBConnection(remoteName=connection.remoteName, remoteHost=connection.host, sess_port=445, timeout=timeout)
    if connection.kerberos:
        smb.kerberosLogin(user=connection.username, password=connection.password, domain=connection.domain, lmhash=connection.lmhash, nthash=connection.nthash, aesKey=connection.aesKey, kdcHost=connection.kdcHost, useCache=connection.use_kcache)
    elif connection.nthash or connection.lmhash:
        smb.login(connection.username, "", connection.domain, lmhash=connection.lmhash, nthash=connection.nthash)
    else:
        smb.login(connection.username, connection.password, connection.domain)
    return smb
