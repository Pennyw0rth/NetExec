
from datetime import datetime, timezone
from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket


def parse_ldap_timestamp(ts):
    """Convert LDAP generalized time (e.g., '20240603160917.0Z')
    to a human-readable string
    """
    if not ts:
        return ""
    try:
        cleaned = ts.replace(".0Z", "").replace("Z", "")
        dt = datetime.strptime(cleaned, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return ts


def query_ldap_gpos(host, domain, username, password, lmhash, nthash, aes_key, kdc_host, kerberos, logger):
    """Query LDAP for GPO metadata
    Returns dict of {GUID: {displayName, ...}} or None on failure

    This function is standalone so it can be reused by other modules
    (e.g., a future list_gpos LDAP module)
    """
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    search_filter = "(objectClass=groupPolicyContainer)"
    attributes = ["cn", "displayName", "gPCFileSysPath", "versionNumber", "whenCreated", "whenChanged"]

    try:
        ldap_url = f"ldap://{host}"
        logger.debug(f"Connecting to LDAP at {ldap_url} for GPO metadata")
        ldap_connection = ldap_impacket.LDAPConnection(url=ldap_url, baseDN=base_dn, dstIp=host)

        if kerberos:
            ldap_connection.kerberosLogin(username, password, domain, lmhash, nthash, aes_key, kdcHost=kdc_host)
        else:
            ldap_connection.login(username, password, domain, lmhash, nthash)

        search_base = f"CN=Policies,CN=System,{base_dn}"
        logger.debug(f"Searching LDAP: base={search_base}, filter={search_filter}")
        resp = ldap_connection.search(
            searchFilter=search_filter,
            attributes=attributes,
            searchBase=search_base,
            sizeLimit=0,
        )

        gpo_map = {}
        for entry in resp:
            if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                continue

            attrs = {}
            for attribute in entry["attributes"]:
                attr_name = str(attribute["type"])
                vals = [str(val) for val in attribute["vals"].components]
                attrs[attr_name] = vals[0] if len(vals) == 1 else vals

            guid = attrs.get("cn", "").upper()
            if guid:
                if not guid.startswith("{"):
                    guid = f"{{{guid}}}"
                gpo_map[guid] = {
                    "displayName": attrs.get("displayName", "Unknown"),
                    "gPCFileSysPath": attrs.get("gPCFileSysPath", ""),
                    "versionNumber": attrs.get("versionNumber", "0"),
                    "whenCreated": attrs.get("whenCreated", ""),
                    "whenChanged": attrs.get("whenChanged", ""),
                }

        logger.debug(f"LDAP returned {len(gpo_map)} GPOs")
        return gpo_map

    except Exception as e:
        logger.debug(f"LDAP GPO query failed: {e}")
        return None
