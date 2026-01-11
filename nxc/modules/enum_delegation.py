#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5.samr import (
    UF_TRUSTED_FOR_DELEGATION,
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
)
from impacket.ldap import ldapasn1, ldaptypes

class NXCModule:
    """
    Enumerates all Active Directory delegation types:
    - Unconstrained Delegation
    - Constrained Delegation (with / without protocol transition)
    - Resource-Based Constrained Delegation (RBCD)

    NOTE: The current version of the RBCD search only checks for msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
    It does NOT enumerate ACLs that could allow configuring RBCD.

    To find principals that can ENABLE RBCD via ACLs, use this BloodHound query:

    MATCH (n:User)
    MATCH p=allShortestPaths((n)-[r:WriteAccountRestrictions|GenericAll|GenericWrite|Owns|WriteDacl]->(m:Computer))
    WHERE n.owned
    RETURN p

    Module by @pavel-usatenko

    Resources:
    - Inspired by HTB Academy: Kerberos Attacks
    - https://github.com/fortra/impacket/blob/master/examples/findDelegation.py
    - https://www.r-tec.net/r-tec-blog-resource-based-constrained-delegation.html

    """

    name = "enum_delegation"
    description = "Enumerate Unconstrained, Constrained and Resource-Based Constrained Delegation"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def sid_to_name(self, ldap_conn, base_dn, sid):
        try:
            res = ldap_conn.search(
                searchBase=base_dn,
                searchFilter=f"(objectSid={sid})",
                attributes=["sAMAccountName"]
            )
            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attr in item["attributes"]:
                        if str(attr["type"]) == "sAMAccountName":
                            return str(attr["vals"][0])
        except Exception:
            pass
        return sid  # fallback

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        ldap_conn = connection.ldap_connection
        base_dn = connection.baseDN

        context.log.highlight(
            "NOTE:\nRBCD enumeration only checks the "
            "msDS-AllowedToActOnBehalfOfOtherIdentity attribute.\n"
            "It does NOT enumerate ACLs that could allow configuring RBCD.\n\n"
            "To find principals that can ENABLE RBCD via ACLs, use this BloodHound query:\n\n"
            "MATCH (n:User) "
            "MATCH p=allShortestPaths((n)-[r:WriteAccountRestrictions|GenericAll|GenericWrite|Owns|WriteDacl]->(m:Computer)) "
            "WHERE n.owned "
            "RETURN p"
        )
        
        # LDAP filter covering:
        # - Unconstrained delegation
        # - Constrained delegation (with and without protocol transition)
        # - Resource-Based Constrained Delegation (RBCD)
        # Disabled accounts are explicitly excluded

        search_filter = (
            "(&(|"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
            "(msDS-AllowedToDelegateTo=*)"
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
            ")"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )

        # Only attributes required for delegation detection are requested
        attributes = [
            "sAMAccountName",
            "userAccountControl",
            "objectCategory",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ]

        context.log.info("Enumerating delegation settings via LDAP")

        try:
            resp = ldap_conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=999
            )
        except Exception as e:
            context.log.error(f"LDAP search failed: {e}")
            return

        found = False

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            sam = None
            uac = 0
            obj_type = "Unknown"
            delegation = None
            rights = []

            for attr in item["attributes"]:
                name = str(attr["type"])

                if name == "sAMAccountName":
                    sam = str(attr["vals"][0])

                elif name == "objectCategory":
                    # Extract object type (User / Computer) from DN-style value
                    obj_type = str(attr["vals"][0]).split("=")[1].split(",")[0]

                elif name == "userAccountControl":
                    # Delegation flags are stored as UAC bitmasks
                    uac = int(attr["vals"][0])

                    if uac & UF_TRUSTED_FOR_DELEGATION:
                        delegation = "Unconstrained"
                        rights.append("N/A")

                    elif uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                        delegation = "Constrained (Protocol Transition)"

                elif name == "msDS-AllowedToDelegateTo":
                    # Constrained delegation SPNs
                    if delegation is None:
                        delegation = "Constrained (No Protocol Transition)"
                    for val in attr["vals"]:
                        rights.append(str(val))

                elif name == "msDS-AllowedToActOnBehalfOfOtherIdentity":
                    # RBCD is stored as a security descriptor containing allowed SIDs
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(attr["vals"][0]))
                    for ace in sd["Dacl"].aces:
                        sid = ace["Ace"]["Sid"].formatCanonical()
                        name = self.sid_to_name(ldap_conn, base_dn, sid)
                        context.log.highlight(
                            f"[RBCD] {sam} ({obj_type}) ← {name}"
                        )
                        found = True

            # Output classic delegation results
            if delegation and sam:
                for r in rights:
                    context.log.highlight(
                        f"[{delegation}] {sam} ({obj_type}) → {r}"
                    )
                    found = True

        if not found:
            context.log.info("No delegation entries found")
