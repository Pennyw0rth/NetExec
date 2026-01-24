"""
RPC Enumeration helper for SMB protocol.

This module provides SAMR, LSA, and SRVS enumeration capabilities
using the existing SMB connection (via SMBTransport).

This avoids creating a separate RPC protocol and reuses the authenticated
SMB session, which is the correct approach since ncacn_np (named pipes)
runs over SMB.
"""

import contextlib
from impacket.dcerpc.v5 import transport, samr, lsat, lsad, srvs, wkst
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException


class RPCEnumerator:
    """RPC Enumeration helper using an existing SMB connection for rpcclient-like functionality."""

    def __init__(self, smb_connection, logger, host, hostname=None, domain=None):
        """Initialize with SMB connection, logger, host, hostname, and domain."""
        self.conn = smb_connection
        self.logger = logger
        self.host = host
        self.hostname = hostname or host
        self.domain = domain or ""

        # Cached DCE-RPC connections
        self._samr_dce = None
        self._lsa_dce = None
        self._srvs_dce = None
        self._wkst_dce = None

        # Cached handles
        self._server_handle = None
        self._domain_handle = None
        self._builtin_handle = None
        self._domain_sid = None
        self._machine_name = None

    def _get_smb_transport(self, pipe):
        """Create SMBTransport that reuses the existing SMB connection."""
        return transport.SMBTransport(self.conn.getRemoteName(), self.conn.getRemoteHost(), filename=pipe, smb_connection=self.conn)

    def get_samr_dce(self):
        """Get or create SAMR DCE-RPC connection."""
        if not self._samr_dce:
            rpctransport = self._get_smb_transport(r"\samr")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            self._samr_dce = dce
        return self._samr_dce

    def get_lsa_dce(self):
        """Get or create LSA DCE-RPC connection."""
        if not self._lsa_dce:
            rpctransport = self._get_smb_transport(r"\lsarpc")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)
            self._lsa_dce = dce
        return self._lsa_dce

    def get_srvs_dce(self):
        """Get or create SRVS DCE-RPC connection."""
        if not self._srvs_dce:
            rpctransport = self._get_smb_transport(r"\srvsvc")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            self._srvs_dce = dce
        return self._srvs_dce

    def get_wkst_dce(self):
        """Get or create WKST DCE-RPC connection."""
        if not self._wkst_dce:
            rpctransport = self._get_smb_transport(r"\wkssvc")
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            self._wkst_dce = dce
        return self._wkst_dce

    def close(self):
        """Close all DCE-RPC connections."""
        for dce in [self._samr_dce, self._lsa_dce, self._srvs_dce, self._wkst_dce]:
            if dce:
                with contextlib.suppress(Exception):
                    dce.disconnect()
        self._samr_dce = None
        self._lsa_dce = None
        self._srvs_dce = None
        self._wkst_dce = None

    def _open_samr_domain(self):
        """Open SAMR domain handle."""
        if self._domain_handle:
            return self._domain_handle

        dce = self.get_samr_dce()
        resp = samr.hSamrConnect(dce)
        self._server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, self._server_handle)
        domains = resp["Buffer"]["Buffer"]

        for d in domains:
            if d["Name"].lower() != "builtin":
                self._machine_name = d["Name"]
                break

        resp = samr.hSamrLookupDomainInSamServer(dce, self._server_handle, self._machine_name)
        self._domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, self._server_handle, domainId=self._domain_sid)
        self._domain_handle = resp["DomainHandle"]

        return self._domain_handle

    def _open_builtin_domain(self):
        """Open Builtin domain handle."""
        if self._builtin_handle:
            return self._builtin_handle

        dce = self.get_samr_dce()
        if not self._server_handle:
            resp = samr.hSamrConnect(dce)
            self._server_handle = resp["ServerHandle"]

        resp = samr.hSamrLookupDomainInSamServer(dce, self._server_handle, "Builtin")
        builtin_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, self._server_handle, domainId=builtin_sid)
        self._builtin_handle = resp["DomainHandle"]

        return self._builtin_handle

    # ==================== SAMR Operations ====================

    def enum_users(self):
        """Enumerate domain users."""
        self._open_samr_domain()
        dce = self.get_samr_dce()
        users_list = []
        enum_ctx = 0

        while True:
            try:
                resp = samr.hSamrEnumerateUsersInDomain(dce, self._domain_handle, samr.USER_NORMAL_ACCOUNT, enumerationContext=enum_ctx)
            except DCERPCException as e:
                if "STATUS_MORE_ENTRIES" in str(e):
                    resp = e.get_packet()
                else:
                    raise

            users_list.extend((user["RelativeId"], user["Name"]) for user in resp["Buffer"]["Buffer"])

            enum_ctx = resp["EnumerationContext"]
            if resp["ErrorCode"] != 0x105:  # STATUS_MORE_ENTRIES
                break

        return users_list

    def enum_groups(self):
        """Enumerate domain groups."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrEnumerateGroupsInDomain(dce, self._domain_handle)
        groups = resp["Buffer"]["Buffer"]

        return [(g["RelativeId"], g["Name"]) for g in groups]

    def query_display_info(self):
        """Query display info - detailed user listing."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrQueryDisplayInformation(dce, self._domain_handle, samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser)
        entries = resp["Buffer"]["UserInformation"]["Buffer"]

        return [{"index": e["Index"], "rid": e["Rid"], "acb": e["AccountControl"], "account": e["AccountName"], "fullname": e["FullName"], "description": e["AdminComment"]} for e in entries]

    def enum_local_groups(self):
        """Enumerate alias/local groups."""
        self._open_builtin_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrEnumerateAliasesInDomain(dce, self._builtin_handle)
        aliases = resp["Buffer"]["Buffer"]

        return [(a["RelativeId"], a["Name"]) for a in aliases]

    def query_user(self, user_input):
        """Query user by RID or name."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        # Determine if input is RID or name
        if user_input.startswith("0x"):
            rid = int(user_input, 16)
        elif user_input.isdigit():
            rid = int(user_input)
        else:
            resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [user_input])
            rid = resp["RelativeIds"]["Element"][0]["Data"]

        resp = samr.hSamrOpenUser(dce, self._domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
        info = resp["Buffer"]["All"]

        samr.hSamrCloseHandle(dce, user_handle)

        return info, rid

    def query_group(self, group_input):
        """Query group by RID or name. Tries domain groups first, then builtin aliases."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        if group_input.startswith("0x"):
            rid = int(group_input, 16)
            is_rid = True
        elif group_input.isdigit():
            rid = int(group_input)
            is_rid = True
        else:
            is_rid = False
            rid = None

        if not is_rid:
            try:
                resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [group_input])
                rid = resp["RelativeIds"]["Element"][0]["Data"]
            except DCERPCException:
                self._open_builtin_domain()
                resp = samr.hSamrLookupNamesInDomain(dce, self._builtin_handle, [group_input])
                rid = resp["RelativeIds"]["Element"][0]["Data"]
                resp = samr.hSamrOpenAlias(dce, self._builtin_handle, MAXIMUM_ALLOWED, rid)
                alias_handle = resp["AliasHandle"]
                resp = samr.hSamrQueryInformationAlias(dce, alias_handle)
                info = resp["Buffer"]["General"]
                members_resp = samr.hSamrGetMembersInAlias(dce, alias_handle)
                member_sids = members_resp["Members"]["Sids"]
                samr.hSamrCloseHandle(dce, alias_handle)
                # Resolve SIDs to names for builtin aliases
                member_names = self._resolve_sids_to_names(member_sids)
                return {"Name": info["Name"], "AdminComment": info["AdminComment"], "Attributes": 0, "MemberCount": info["MemberCount"]}, member_names

        resp = samr.hSamrOpenGroup(dce, self._domain_handle, MAXIMUM_ALLOWED, rid)
        group_handle = resp["GroupHandle"]

        resp = samr.hSamrQueryInformationGroup(dce, group_handle, samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
        info = resp["Buffer"]["General"]

        members_resp = samr.hSamrGetMembersInGroup(dce, group_handle)
        members = members_resp["Members"]["Members"]

        samr.hSamrCloseHandle(dce, group_handle)

        # Resolve member RIDs to names for domain groups
        member_names = self._resolve_rids_to_names(dce, self._domain_handle, members)

        return info, member_names

    def _resolve_rids_to_names(self, dce, domain_handle, members):
        """Resolve member RIDs to names."""
        member_names = []
        if not members:
            return member_names

        rids = []
        for m in members:
            if hasattr(m, "fields") and "Data" in m.fields:
                rids.append(m["Data"])
            elif isinstance(m, dict) and "Data" in m:
                rids.append(m["Data"])
            elif isinstance(m, int):
                rids.append(m)

        if rids:
            try:
                resp = samr.hSamrLookupIdsInDomain(dce, domain_handle, rids)
                names = resp["Names"]["Element"]
                for name in names:
                    if name["Data"]:
                        member_names.append(str(name["Data"]))
            except Exception:
                # Fallback to RIDs if lookup fails
                member_names = [str(r) for r in rids]

        return member_names

    def _resolve_sids_to_names(self, sids):
        """Resolve SIDs to names using LSA."""
        member_names = []
        if not sids:
            return member_names

        try:
            dce = self.get_lsa_dce()
            resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_LOOKUP_NAMES)
            policy_handle = resp["PolicyHandle"]

            sid_list = []
            for sid in sids:
                if hasattr(sid, "formatCanonical"):
                    sid_list.append(sid)
                elif hasattr(sid, "Data"):
                    sid_list.append(sid["Data"])

            if sid_list:
                resp = lsad.hLsarLookupSids(dce, policy_handle, sid_list, lsad.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
                names = resp["TranslatedNames"]["Names"]
                domains = resp["ReferencedDomains"]["Domains"]

                for name in names:
                    domain_idx = name["DomainIndex"]
                    account_name = name["Name"]
                    if domain_idx >= 0 and domain_idx < len(domains):
                        domain_name = domains[domain_idx]["Name"]
                        member_names.append(f"{domain_name}\\{account_name}")
                    else:
                        member_names.append(str(account_name))

            lsad.hLsarClose(dce, policy_handle)
        except Exception:
            # Fallback to SID strings if lookup fails
            for sid in sids:
                if hasattr(sid, "formatCanonical"):
                    member_names.append(sid.formatCanonical())
                else:
                    member_names.append(str(sid))

        return member_names

    def query_user_groups(self, user_input):
        """Query groups for a user."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        if user_input.startswith("0x"):
            rid = int(user_input, 16)
        elif user_input.isdigit():
            rid = int(user_input)
        else:
            resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [user_input])
            rid = resp["RelativeIds"]["Element"][0]["Data"]

        resp = samr.hSamrOpenUser(dce, self._domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        resp = samr.hSamrGetGroupsForUser(dce, user_handle)
        groups = resp["Groups"]["Groups"]

        samr.hSamrCloseHandle(dce, user_handle)

        results = []
        for g in groups:
            group_rid = g["RelativeId"]
            attrs = g["Attributes"]
            try:
                resp = samr.hSamrOpenGroup(dce, self._domain_handle, MAXIMUM_ALLOWED, group_rid)
                group_handle = resp["GroupHandle"]
                resp = samr.hSamrQueryInformationGroup(dce, group_handle, samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                group_name = resp["Buffer"]["General"]["Name"]
                samr.hSamrCloseHandle(dce, group_handle)
            except Exception:
                group_name = f"RID-{group_rid}"
            results.append({"rid": group_rid, "name": group_name, "attributes": attrs})

        return results

    def get_domain_info(self):
        """Get domain info."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrQueryInformationDomain(dce, self._domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
        return resp["Buffer"]["General"], self._machine_name

    def get_password_policy(self):
        """Get password policy."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrQueryInformationDomain(dce, self._domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        pwd_info = resp["Buffer"]["Password"]

        resp = samr.hSamrQueryInformationDomain(dce, self._domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
        lock_info = resp["Buffer"]["Lockout"]

        return pwd_info, lock_info

    def rid_cycle(self, max_rid=4000):
        """RID cycling enumeration."""
        dce = self.get_samr_dce()

        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]

        domain_name = None
        for d in domains:
            if d["Name"].lower() != "builtin":
                domain_name = d["Name"]
                break

        if not domain_name:
            return []

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]
        domain_sid_str = domain_sid.formatCanonical()

        resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
        domain_handle = resp["DomainHandle"]

        found = []
        type_names = {1: "User", 2: "Group", 4: "Alias", 5: "WellKnown", 9: "Computer"}

        for rid in range(500, max_rid + 1):
            try:
                resp = samr.hSamrLookupIdsInDomain(dce, domain_handle, [rid])
                names = resp["Names"]["Element"]
                uses = resp["Use"]["Element"]

                if names and names[0]["Data"]:
                    name = names[0]["Data"]
                    use = uses[0]["Data"] if uses else 0
                    type_name = type_names.get(use, f"Type{use}")
                    sid_str = f"{domain_sid_str}-{rid}"
                    found.append((rid, name, type_name, sid_str, use))
            except Exception:
                pass

        return found

    # ==================== LSA Operations ====================

    def lsa_query_policy(self):
        """LSA query."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
        policy_handle = resp["PolicyHandle"]

        resp = lsad.hLsarQueryInformationPolicy(dce, policy_handle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        info = resp["PolicyInformation"]["PolicyPrimaryDomainInfo"]

        domain_name = info["Name"]
        domain_sid = info["Sid"].formatCanonical() if info["Sid"] else None

        return domain_name, domain_sid

    def lsa_enum_accounts(self):
        """Enumerate SIDs."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
        policy_handle = resp["PolicyHandle"]

        resp = lsad.hLsarEnumerateAccounts(dce, policy_handle)
        sids = resp["EnumerationBuffer"]["Information"]

        return [sid_info["Sid"].formatCanonical() for sid_info in sids]

    def lsa_enum_privileges(self):
        """Enumerate privileges."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
        policy_handle = resp["PolicyHandle"]

        resp = lsad.hLsarEnumeratePrivileges(dce, policy_handle)
        privs = resp["EnumerationBuffer"]["Privileges"]

        return [p["Name"] for p in privs]

    def lsa_lookup_sids(self, sids):
        """Lookup SIDs to names."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, lsat.POLICY_LOOKUP_NAMES)
        policy_handle = resp["PolicyHandle"]

        results = []
        for sid in sids:
            try:
                resp = lsat.hLsarLookupSids(dce, policy_handle, [sid])
                names = resp["TranslatedNames"]["Names"]
                domains = resp["ReferencedDomains"]["Domains"]

                for n in names:
                    dom_idx = n["DomainIndex"]
                    dom = domains[dom_idx]["Name"] if dom_idx >= 0 else ""
                    results.append((sid, dom, n["Name"], n["Use"]))
            except Exception as e:
                results.append((sid, None, None, str(e)))

        return results

    def enum_trusts(self):
        """Enumerate trusted domains."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, MAXIMUM_ALLOWED)
        policy_handle = resp["PolicyHandle"]

        try:
            resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy_handle)
            trusts = resp["EnumerationBuffer"]["EnumerationBuffer"]
        except DCERPCException as e:
            if "STATUS_NO_MORE_ENTRIES" in str(e):
                return []
            raise

        results = []
        direction_map = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        type_map = {1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}

        for t in trusts:
            attrs = t["TrustAttributes"]
            attr_flags = []
            if attrs & 0x1:
                attr_flags.append("NON_TRANSITIVE")
            if attrs & 0x2:
                attr_flags.append("UPLEVEL_ONLY")
            if attrs & 0x4:
                attr_flags.append("QUARANTINED")
            if attrs & 0x8:
                attr_flags.append("FOREST_TRANSITIVE")
            if attrs & 0x20:
                attr_flags.append("WITHIN_FOREST")
            if attrs & 0x40:
                attr_flags.append("TREAT_AS_EXTERNAL")

            results.append({
                "name": t["Name"],
                "flat_name": t["FlatName"],
                "sid": t["Sid"].formatCanonical() if t["Sid"] else "N/A",
                "direction": direction_map.get(t["TrustDirection"], str(t["TrustDirection"])),
                "type": type_map.get(t["TrustType"], str(t["TrustType"])),
                "attributes": ",".join(attr_flags) if attr_flags else "NONE",
                "attributes_raw": attrs,
            })

        return results

    # ==================== SRVS Operations ====================

    def enum_shares_rpc(self):
        """Enumerate shares via RPC."""
        dce = self.get_srvs_dce()

        resp = srvs.hNetrShareEnum(dce, 1)
        shares = resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]

        results = []
        type_map = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}

        for s in shares:
            stype = s["shi1_type"] & 0xFFFF
            results.append({"name": s["shi1_netname"], "type": type_map.get(stype, "Unknown"), "type_raw": s["shi1_type"], "remark": s["shi1_remark"]})

        return results

    def get_share_info(self, share_name):
        """Get share info."""
        dce = self.get_srvs_dce()

        if not share_name.endswith("\x00"):
            share_name += "\x00"

        type_map = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}

        try:
            resp = srvs.hNetrShareGetInfo(dce, share_name, 2)
            info = resp["InfoStruct"]["ShareInfo2"]
            return {"name": info["shi2_netname"], "type": type_map.get(info["shi2_type"] & 0xFFFF, "Unknown"), "type_raw": info["shi2_type"], "remark": info["shi2_remark"], "permissions": info["shi2_permissions"], "max_uses": info["shi2_max_uses"], "current_uses": info["shi2_current_uses"], "path": info["shi2_path"]}
        except Exception:
            # Fallback to level 1
            resp = srvs.hNetrShareGetInfo(dce, share_name, 1)
            info = resp["InfoStruct"]["ShareInfo1"]
            return {"name": info["shi1_netname"], "type": type_map.get(info["shi1_type"] & 0xFFFF, "Unknown"), "type_raw": info["shi1_type"], "remark": info["shi1_remark"]}

    def enum_sessions(self):
        """Enumerate sessions."""
        dce = self.get_srvs_dce()

        resp = srvs.hNetrSessionEnum(dce, "\x00", "\x00", 10)
        sessions = resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]

        results = []
        for s in sessions:
            client = s["sesi10_cname"]
            username = s["sesi10_username"]
            results.append({"client": client if client else "", "username": username if username else "", "time": s["sesi10_time"] if s["sesi10_time"] else 0, "idle_time": s["sesi10_idle_time"] if s["sesi10_idle_time"] else 0})
        return results

    def server_info(self):
        """Get server info."""
        dce = self.get_srvs_dce()

        resp = srvs.hNetrServerGetInfo(dce, 101)
        info = resp["InfoStruct"]["ServerInfo101"]

        return {"name": info["sv101_name"], "comment": info["sv101_comment"], "version_major": info["sv101_version_major"], "version_minor": info["sv101_version_minor"], "type": info["sv101_type"]}

    def enum_connections(self, qualifier=None):
        """Enumerate connections."""
        dce = self.get_srvs_dce()

        all_connections = []

        if qualifier:
            resp = srvs.hNetrConnectionEnum(dce, qualifier, 1)
            connections = resp["InfoStruct"]["ConnectionInfo"]["Level1"]["Buffer"]
            for c in connections:
                all_connections.append({"conn_id": c["coni1_id"], "conn_type": c["coni1_type"], "num_opens": c["coni1_num_opens"], "num_users": c["coni1_num_users"], "time": c["coni1_time"], "username": c["coni1_username"] if c["coni1_username"] else "", "netname": c["coni1_netname"] if c["coni1_netname"] else ""})
        else:
            shares = self.enum_shares_rpc()
            for share in shares:
                share_name = share["name"]
                try:
                    resp = srvs.hNetrConnectionEnum(dce, share_name, 1)
                    connections = resp["InfoStruct"]["ConnectionInfo"]["Level1"]["Buffer"]
                    for c in connections:
                        all_connections.append({
                            "conn_id": c["coni1_id"],
                            "conn_type": c["coni1_type"],
                            "num_opens": c["coni1_num_opens"],
                            "num_users": c["coni1_num_users"],
                            "time": c["coni1_time"],
                            "username": c["coni1_username"] if c["coni1_username"] else "",
                            "netname": c["coni1_netname"] if c["coni1_netname"] else "",
                            "share": share_name,
                        })
                except Exception:
                    pass

        return all_connections

    def lsa_query_security(self):
        """Query LSA security object."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, MAXIMUM_ALLOWED)
        policy_handle = resp["PolicyHandle"]

        # hLsarQuerySecurityObject already returns raw bytes (does b''.join internally)
        sd_bytes = lsad.hLsarQuerySecurityObject(dce, policy_handle, 0x00000004)

        return sd_bytes

    # ==================== User Management ====================

    def create_user(self, username, password):
        """Create domain user."""
        dce = self._get_samr_dce_np()
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = next((d["Name"] for d in domains if d["Name"].lower() != "builtin"), None)

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        resp = samr.hSamrCreateUser2InDomain(dce, domain_handle, username, samr.USER_NORMAL_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE)
        user_handle = resp["UserHandle"]
        rid = resp["RelativeId"]

        samr.hSamrChangePasswordUser(dce, user_handle, oldPassword="", newPassword=password, oldPwdHashNT="31d6cfe0d16ae931b73c59d7e0c089c0", newPwdHashLM="", newPwdHashNT="")

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        user_rid = resp["RelativeIds"]["Element"][0]
        resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, user_rid)
        user_handle = resp["UserHandle"]

        user_control = samr.SAMPR_USER_INFO_BUFFER()
        user_control["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
        user_control["Control"]["UserAccountControl"] = samr.USER_NORMAL_ACCOUNT
        samr.hSamrSetInformationUser2(dce, user_handle, user_control)

        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()
        return rid

    def delete_user(self, username):
        """Delete domain user."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [username])
        rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenUser(dce, self._domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        samr.hSamrDeleteUser(dce, user_handle)

    def enable_user(self, username):
        """Enable user account."""
        dce = self._get_samr_dce_np()
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = next((d["Name"] for d in domains if d["Name"].lower() != "builtin"), None)

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserControlInformation)
        uac = resp["Buffer"]["Control"]["UserAccountControl"]

        if not (uac & samr.USER_ACCOUNT_DISABLED):
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            return False, uac

        new_uac = uac & ~samr.USER_ACCOUNT_DISABLED
        user_control = samr.SAMPR_USER_INFO_BUFFER()
        user_control["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
        user_control["Control"]["UserAccountControl"] = new_uac
        samr.hSamrSetInformationUser2(dce, user_handle, user_control)

        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()
        return True, (uac, new_uac)

    def disable_user(self, username):
        """Disable user account."""
        dce = self._get_samr_dce_np()
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = next((d["Name"] for d in domains if d["Name"].lower() != "builtin"), None)

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        resp = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserControlInformation)
        uac = resp["Buffer"]["Control"]["UserAccountControl"]

        if uac & samr.USER_ACCOUNT_DISABLED:
            samr.hSamrCloseHandle(dce, user_handle)
            dce.disconnect()
            return False, uac

        new_uac = uac | samr.USER_ACCOUNT_DISABLED
        user_control = samr.SAMPR_USER_INFO_BUFFER()
        user_control["tag"] = samr.USER_INFORMATION_CLASS.UserControlInformation
        user_control["Control"]["UserAccountControl"] = new_uac
        samr.hSamrSetInformationUser2(dce, user_handle, user_control)

        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()
        return True, (uac, new_uac)

    def _get_samr_dce_np(self):
        """Get SAMR DCE over named pipe (required for password operations)."""
        rpctransport = self._get_smb_transport(r"\samr")
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    # ==================== Password Operations ====================

    def change_password(self, username, old_password, new_password):
        """Change password with old password."""
        dce = self._get_samr_dce_np()
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = next((d["Name"] for d in domains if d["Name"].lower() != "builtin"), None)

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        samr.hSamrChangePasswordUser(dce, user_handle, oldPassword=old_password, newPassword=new_password)

        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()

    def reset_password(self, username, new_password):
        """Admin reset password."""
        from Cryptodome.Cipher import ARC4

        rpctransport = self._get_smb_transport(r"\samr")
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = next((d["Name"] for d in domains if d["Name"].lower() != "builtin"), None)

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])
        rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
        user_handle = resp["UserHandle"]

        session_key = dce.get_rpc_transport().get_smb_connection().getSessionKey()
        sam_user_pass = samr.SAMPR_USER_PASSWORD()
        encoded_pass = new_password.encode("utf-16le")
        plen = len(encoded_pass)
        sam_user_pass["Buffer"] = b"A" * (512 - plen) + encoded_pass
        sam_user_pass["Length"] = plen
        pwd_buff = sam_user_pass.getData()

        rc4 = ARC4.new(session_key)
        enc_buf = rc4.encrypt(pwd_buff)

        sam_user_pass_enc = samr.SAMPR_ENCRYPTED_USER_PASSWORD()
        sam_user_pass_enc["Buffer"] = enc_buf

        request = samr.SamrSetInformationUser2()
        request["UserHandle"] = user_handle
        request["UserInformationClass"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        request["Buffer"]["tag"] = samr.USER_INFORMATION_CLASS.UserInternal5Information
        request["Buffer"]["Internal5"]["UserPassword"] = sam_user_pass_enc
        request["Buffer"]["Internal5"]["PasswordExpired"] = 0
        dce.request(request)

        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()

    # ==================== Group Management ====================

    def create_group(self, group_name):
        """Create domain group."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrCreateGroupInDomain(dce, self._domain_handle, group_name, MAXIMUM_ALLOWED)
        rid = resp["RelativeId"]
        samr.hSamrCloseHandle(dce, resp["GroupHandle"])
        return rid

    def delete_group(self, group_name):
        """Delete domain group."""
        dce = self._get_samr_dce_np()
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]
        domain_name = next((d["Name"] for d in domains if d["Name"].lower() != "builtin"), None)

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
        domain_handle = resp["DomainHandle"]

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [group_name])
        rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenGroup(dce, domain_handle, MAXIMUM_ALLOWED, rid)
        group_handle = resp["GroupHandle"]

        samr.hSamrDeleteGroup(dce, group_handle)
        dce.disconnect()

    def add_to_group(self, username, group_name):
        """Add user to group."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [username])
        user_rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [group_name])
        group_rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenGroup(dce, self._domain_handle, MAXIMUM_ALLOWED, group_rid)
        group_handle = resp["GroupHandle"]

        samr.hSamrAddMemberToGroup(dce, group_handle, user_rid, samr.SE_GROUP_ENABLED_BY_DEFAULT)
        samr.hSamrCloseHandle(dce, group_handle)

    def remove_from_group(self, username, group_name):
        """Remove user from group."""
        self._open_samr_domain()
        dce = self.get_samr_dce()

        resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [username])
        user_rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, [group_name])
        group_rid = resp["RelativeIds"]["Element"][0]

        resp = samr.hSamrOpenGroup(dce, self._domain_handle, MAXIMUM_ALLOWED, group_rid)
        group_handle = resp["GroupHandle"]

        samr.hSamrRemoveMemberFromGroup(dce, group_handle, user_rid)
        samr.hSamrCloseHandle(dce, group_handle)

    # ==================== Additional LSA Operations ====================

    def lsa_enum_account_rights(self, sid):
        """Enumerate account rights for SID."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
        policy_handle = resp["PolicyHandle"]

        resp = lsad.hLsarEnumerateAccountRights(dce, policy_handle, sid)
        rights = resp["UserRights"]["UserRights"]

        return [r["Data"] for r in rights]

    def lsa_create_account(self, sid):
        """Create LSA account."""
        dce = self.get_lsa_dce()

        resp = lsad.hLsarOpenPolicy(dce, lsad.POLICY_CREATE_ACCOUNT)
        policy_handle = resp["PolicyHandle"]

        lsad.hLsarCreateAccount(dce, policy_handle, sid)

    # ==================== Lookup Operations ====================

    def lookup_names(self, names):
        """Lookup names in domain."""
        self._open_samr_domain()
        dce = self.get_samr_dce()
        domain_sid = self._domain_sid.formatCanonical()

        resp = samr.hSamrLookupNamesInDomain(dce, self._domain_handle, names)
        rids = resp["RelativeIds"]["Element"]
        uses = resp["Use"]["Element"]

        type_names = {1: "User", 2: "Group", 4: "Alias", 5: "WellKnown", 9: "Computer"}
        results = []

        for i, name in enumerate(names):
            if i < len(rids):
                rid = rids[i]["Data"]
                use = uses[i]["Data"]
                type_name = type_names.get(use, "Unknown")
                results.append((name, f"{domain_sid}-{rid}", type_name, use))

        return results

    def lookup_domain(self, domain_name):
        """Lookup domain SID."""
        dce = self.get_samr_dce()

        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        return resp["DomainId"].formatCanonical()

    def sam_lookup(self, domain_type, names):
        """SAM lookup names."""
        dce = self.get_samr_dce()

        if domain_type.lower() == "builtin":
            self._open_builtin_domain()
            domain_handle = self._builtin_handle
            resp = samr.hSamrLookupDomainInSamServer(dce, self._server_handle, "Builtin")
            domain_sid = resp["DomainId"].formatCanonical()
        else:
            self._open_samr_domain()
            domain_handle = self._domain_handle
            domain_sid = self._domain_sid.formatCanonical()

        resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, names)
        rids = resp["RelativeIds"]["Element"]
        uses = resp["Use"]["Element"]

        type_names = {1: "User", 2: "Group", 4: "Alias", 5: "WellKnown", 9: "Computer"}
        results = []

        for i, name in enumerate(names):
            if i < len(rids):
                rid = rids[i]["Data"]
                use = uses[i]["Data"]
                type_name = type_names.get(use, "Unknown")
                results.append((name, f"{domain_sid}-{rid}", type_name, use))

        return results

    # ==================== Helper Functions ====================

    @staticmethod
    def uac_to_flags(uac):
        """Convert UAC value to human-readable flags."""
        flags = []
        flag_map = {
            0x0001: "ACCOUNT_DISABLED",
            0x0002: "HOMEDIR_REQUIRED",
            0x0004: "PASSWORD_NOT_REQUIRED",
            0x0008: "TEMP_DUPLICATE_ACCOUNT",
            0x0010: "NORMAL_ACCOUNT",
            0x0020: "MNS_LOGON_ACCOUNT",
            0x0040: "INTERDOMAIN_TRUST_ACCOUNT",
            0x0080: "WORKSTATION_TRUST_ACCOUNT",
            0x0100: "SERVER_TRUST_ACCOUNT",
            0x0200: "DONT_EXPIRE_PASSWORD",
            0x0400: "ACCOUNT_AUTO_LOCKED",
            0x0800: "ENCRYPTED_TEXT_PWD_ALLOWED",
            0x1000: "SMARTCARD_REQUIRED",
            0x2000: "TRUSTED_FOR_DELEGATION",
            0x4000: "NOT_DELEGATED",
            0x8000: "USE_DES_KEY_ONLY",
            0x10000: "DONT_REQ_PREAUTH",
            0x20000: "PASSWORD_EXPIRED",
            0x40000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
            0x80000: "NO_AUTH_DATA_REQUIRED",
            0x100000: "PARTIAL_SECRETS_ACCOUNT",
        }
        for bit, name in flag_map.items():
            if uac & bit:
                flags.append(name)
        return flags

    @staticmethod
    def filetime_to_str(low, high):
        """Convert Windows FILETIME to string."""
        if low == 0 and high == 0:
            return "Never"
        if high == 0x7FFFFFFF and low == 0xFFFFFFFF:
            return "Never"
        try:
            import datetime

            filetime = (high << 32) | low
            if filetime == 0 or filetime > 0x7FFFFFFFFFFFFFFF:
                return "Never"
            epoch_diff = 116444736000000000
            if filetime < epoch_diff:
                return "Never"
            timestamp = (filetime - epoch_diff) / 10000000
            return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return f"{high}:{low}"
