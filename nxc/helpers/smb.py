from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.dtypes import OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION
from impacket.ldap import ldaptypes

from nxc.protocols.ldap.constants import ACCESS_MASK_TO_TEXT_LOOKUP


def get_share_security_descriptor(connection, share_name, path, sec_info_flags=None):
    r"""Get the security descriptor for a file/folder on an SMB share via SRVS RPC.

    Args:
        connection: An NXC SMB connection object with host, username, password, etc.
        share_name: The SMB share name (e.g. "SYSVOL").
        path: The path within the share (e.g. "domain.local\\Policies\\{GUID}").
        sec_info_flags: Security information flags to request. Defaults to
            OWNER | GROUP | DACL.

    Returns:
        An SR_SECURITY_DESCRIPTOR parsed from the raw response.
    """
    if sec_info_flags is None:
        sec_info_flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

    rpc_transport = transport.SMBTransport(
        connection.host,
        connection.host,
        filename=r"\srvsvc",
        smb_connection=connection.conn,
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

    # SRVS RPC requires null-terminated strings
    rpc_share = f"{share_name}\x00"
    rpc_path = f"\\{path.replace('/', chr(92))}\x00"

    raw = srvs.hNetrpGetFileSecurity(dce, rpc_share, rpc_path, sec_info_flags)
    dce.disconnect()

    return ldaptypes.SR_SECURITY_DESCRIPTOR(raw)


def parse_dacl_aces(sd, sid_resolver=None):
    """Parse ACEs from a security descriptor's DACL into structured data.

    Args:
        sd: An SR_SECURITY_DESCRIPTOR (from impacket ldaptypes).
        sid_resolver: Optional callable that takes a SID string and returns
            a human-readable name. If None, SID names are left as empty strings.

    Returns:
        A dict with keys:
            owner: {"sid": str, "name": str}
            group: {"sid": str, "name": str}
            aces: list of {"ace_type": str, "sid": str, "sid_name": str, "permissions": list[str], "raw_mask": int}
        If there is no DACL, the ``aces`` list will be empty.
    """
    owner_sid = sd["OwnerSid"].formatCanonical() if sd["OwnerSid"] else ""
    group_sid = sd["GroupSid"].formatCanonical() if sd["GroupSid"] else ""

    result = {
        "owner": {"sid": owner_sid, "name": sid_resolver(owner_sid) if sid_resolver and owner_sid else ""},
        "group": {"sid": group_sid, "name": sid_resolver(group_sid) if sid_resolver and group_sid else ""},
        "aces": [],
    }

    if not sd["Dacl"]:
        return result

    for i in range(sd["Dacl"]["AceCount"]):
        ace = sd["Dacl"]["Data"][i]
        ace_type = ace["TypeName"]
        access_mask = int(ace["Ace"]["Mask"]["Mask"])
        sid = ace["Ace"]["Sid"].formatCanonical()

        permissions = [mask_name for mask_value, mask_name in ACCESS_MASK_TO_TEXT_LOOKUP.items() if access_mask & mask_value]

        sid_name = ""
        if sid_resolver:
            sid_name = sid_resolver(sid)

        result["aces"].append({
            "ace_type": ace_type,
            "sid": sid,
            "sid_name": sid_name,
            "permissions": permissions,
            "raw_mask": access_mask,
        })

    return result
