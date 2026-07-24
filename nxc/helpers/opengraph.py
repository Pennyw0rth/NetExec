import json
import os
import zipfile
import tempfile
import shutil
import contextlib

from nxc.paths import NXC_PATH, TMP_PATH
from datetime import datetime
from nxc.logger import nxc_logger


class OpenGraph:
    # Collects nodes, edges, and properties for BloodHound-CE OpenGraph import.

    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.name2oid = {}
        self._ldap_loaded = False

# ------------------------- MAPPING ----------------------------

    def _load_json(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def _map_computers_json(self, data):
        for entry in data.get("data", []):
            oid = entry.get("ObjectIdentifier")
            props = entry.get("Properties", {})
            sam = props.get("samaccountname")
            if sam:
                self.name2oid[sam.upper()] = oid

    def _map_users_json(self, data):
        for entry in data.get("data", []):
            oid = entry.get("ObjectIdentifier")
            props = entry.get("Properties", {})
            sam = props.get("samaccountname")
            if sam:
                self.name2oid[sam.upper()] = oid

    def bh_mapping(self, bh_path):
        """Load mappings from BloodHound dump (ZIP or directory)."""
        # If ZIP → extract to temp
        tempdir = ""
        if bh_path.lower().endswith(".zip"):
            try:
                tempdir = tempfile.mkdtemp(prefix="bh_", dir=TMP_PATH)
                with zipfile.ZipFile(bh_path, "r") as z:
                    z.extractall(tempdir)
                bh_path = tempdir
            except Exception as e:
                nxc_logger.fail(f"Failed to unzip BloodHound data: {e}")
                return

        # Identify files
        comp_file = None
        user_file = None

        for entry in os.listdir(bh_path):
            if entry.endswith("computers.json"):
                comp_file = os.path.join(bh_path, entry)
            elif entry.endswith("users.json"):
                user_file = os.path.join(bh_path, entry)

        nxc_logger.debug(f"user file is {user_file}")
        nxc_logger.debug(f"computer file is {comp_file}")

        # Load mappings
        if comp_file:
            self._map_computers_json(self._load_json(comp_file))

        if user_file:
            self._map_users_json(self._load_json(user_file))

        nxc_logger.display(
            f"Loaded {len(self.name2oid)} name→OID mappings from BloodHound"
        )

        if os.path.exists(tempdir):
            shutil.rmtree(tempdir)

    def ldap_mapping(self, args):
        """Populate name->OID mappings by querying an LDAP server directly.

        This is protocol-agnostic: it opens its own LDAP connection to the host
        given in `--og-ldap` reusing the same credentials passed on the command
        line (plaintext, NTLM hash or Kerberos). Every user and computer
        sAMAccountName is resolved to its objectSid so add_tag/add_edge can
        reference nodes by their BloodHound OID.
        """
        if self._ldap_loaded:
            return
        self._ldap_loaded = True

        from impacket.ldap import ldap as ldap_impacket
        from impacket.ldap import ldapasn1 as ldapasn1_impacket
        from nxc.parsers.ldap_results import parse_result_attributes

        target = args.og_ldap

        # Extract the first credential set from the run
        username = args.username[0] if getattr(args, "username", None) else ""
        password = args.password[0] if getattr(args, "password", None) else ""
        domain = getattr(args, "domain", None) or ""
        aeskey = args.aesKey[0] if getattr(args, "aesKey", None) else ""
        kdc_host = getattr(args, "kdcHost", None)
        use_kcache = bool(getattr(args, "use_kcache", False))
        use_kerberos = bool(getattr(args, "kerberos", False) or aeskey or use_kcache)

        # Parse NTLM hash (accepts "LM:NT" or just "NT")
        lmhash = nthash = ""
        hashes = getattr(args, "hash", None)
        if hashes:
            h = hashes[0]
            lmhash, _, nthash = h.partition(":") if ":" in h else ("", "", h)

        try:
            connection = self._ldap_connect(
                ldap_impacket, ldapasn1_impacket, target, username, password,
                domain, lmhash, nthash, aeskey, kdc_host, use_kcache, use_kerberos
            )
        except Exception as e:
            nxc_logger.fail(f"Failed to connect/bind to LDAP server {target}: {e}")
            return

        if connection is None:
            return

        # Resolve the base DN from the RootDSE
        try:
            root = connection.search(
                scope=ldapasn1_impacket.Scope("baseObject"),
                attributes=["defaultNamingContext"],
                sizeLimit=0,
            )
            base_dn = parse_result_attributes(root)[0]["defaultNamingContext"]
        except Exception as e:
            nxc_logger.fail(f"Failed to retrieve base DN from {target}: {e}")
            return

        # SAM_NORMAL_USER_ACCOUNT (805306368) + SAM_MACHINE_ACCOUNT (805306369)
        search_filter = "(|(sAMAccountType=805306368)(sAMAccountType=805306369))"
        attributes = ["sAMAccountName", "objectSid"]

        try:
            paged = [ldapasn1_impacket.SimplePagedResultsControl(criticality=True, size=1000)]
            resp = connection.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0,
                searchControls=paged,
            )
            resp_parsed = parse_result_attributes(resp)
        except Exception as e:
            nxc_logger.fail(f"Failed to resolve OIDs via LDAP: {e}")
            return
        finally:
            with contextlib.suppress(Exception):
                connection.close()

        count = 0
        for item in resp_parsed:
            sam = item.get("sAMAccountName")
            sid = item.get("objectSid")
            if sam and sid:
                self.name2oid[sam.upper()] = sid
                count += 1

        nxc_logger.display(f"Loaded {count} name\u2192OID mappings from LDAP ({target})")

    def _ldap_connect(self, ldap_impacket, ldapasn1_impacket, target, username, password,
                      domain, lmhash, nthash, aeskey, kdc_host, use_kcache, use_kerberos):
        """Open and bind an impacket LDAPConnection, trying LDAP then LDAPS."""
        for proto in ("ldap", "ldaps"):
            url = f"{proto}://{target}"
            try:
                nxc_logger.debug(f"OpenGraph: connecting to {url}")
                conn = ldap_impacket.LDAPConnection(url, dstIp=target)
                if use_kerberos:
                    conn.kerberosLogin(
                        username, password, domain, lmhash, nthash, aeskey,
                        kdcHost=kdc_host, useCache=use_kcache
                    )
                else:
                    conn.login(username, password, domain, lmhash, nthash)
                return conn
            except Exception as e:
                nxc_logger.debug(f"OpenGraph: {proto} bind to {target} failed: {e}")
                last_error = e
        raise last_error

# ------------------------- NODES AND EDGES ----------------------------

    def add_node(self, node_id, kinds, properties=None):
        if "Base" not in kinds:
            kinds.append("Base")
        node_id = node_id.strip()
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "kinds": kinds,
                "properties": {},
            }
        else:
            node = self.nodes[node_id]
            if kinds:
                for k in kinds:
                    if k not in node["kinds"]:
                        node["kinds"].append(k)
            if properties:
                node["properties"].update(properties)

    def add_tag(self, node_id, kinds, tag_name, value):
        # formating node_id
        if not node_id.startswith("S-1-5"):
            if "Computer" in kinds:
                node_id = node_id.strip().split(".")[0]  # remove .domain.com if fqdn
                node_id = f"{node_id}$" if not node_id.endswith("$") else node_id
            if "User" in kinds:
                node_id = node_id.strip().split("@")[0]  # remove @domain.com if upn
            node_id = node_id.upper()
            if node_id in self.name2oid:
                node_id = self.name2oid[node_id]
        self.add_node(node_id, kinds)
        self.nodes[node_id]["properties"][tag_name] = value

    def add_edge(self, kind, start, end, start_match_by="id", end_match_by="id"):
        def resolve(value, match_by):
            v = value.strip()
            if match_by == "id" and not v.startswith("S-1-5-21"):
                lookup = v.upper()
                if lookup in self.name2oid:
                    return self.name2oid[lookup], match_by
                # Unresolved name: it can't be matched by "id", fall back to
                # matching on the node "name" property instead.
                return v, "name"
            return v, match_by

        start_value, start_match_by = resolve(start, start_match_by)
        end_value, end_match_by = resolve(end, end_match_by)
        edge = {
            "kind": kind,
            "start": {"value": start_value, "match_by": start_match_by},
            "end": {"value": end_value, "match_by": end_match_by},
        }
        self.edges.append(edge)

    def add_local_group_membership(self, principal, hostname, local_rid, ura_edge=None):
        """Emit the supporting edges for a local group membership.

        AdminTo (rid 544) and CanRDP (rid 555) are post-processed edges that
        BloodHound deletes/regenerates on ingest, so injecting them directly
        does not persist. Instead we add the supporting chain:

            principal -MemberOfLocalGroup-> LocalGroup -LocalToComputer-> Computer

        and BloodHound's post-processing synthesizes AdminTo (544) / CanPSRemote
        (580) / ExecuteDCOM (562) from it.

        CanRDP (555) additionally requires the SeRemoteInteractiveLogonRight URA,
        so pass ura_edge="RemoteInteractiveLogonRight" to also grant it to the
        local group; BloodHound then synthesizes CanRDP for the members.
        """
        comp = hostname.strip().split(".")[0]  # strip domain if FQDN
        comp = comp if comp.endswith("$") else f"{comp}$"
        comp = comp.upper()
        comp_sid = self.name2oid.get(comp, comp)
        group_id = f"{comp_sid}-{local_rid}"

        # Declare the local group node and its LocalToComputer link so the chain
        # is complete even when the target data was collected without local
        # group enumeration.
        self.add_node(group_id, ["Group"])
        self.add_edge("LocalToComputer", group_id, comp_sid, start_match_by="id", end_match_by="id")
        self.add_edge("MemberOfLocalGroup", principal, group_id, end_match_by="id")
        if ura_edge:
            self.add_edge(ura_edge, group_id, comp_sid, start_match_by="id", end_match_by="id")

# ------------------------- EXPORT ----------------------------

    def to_dict(self):
        return {
            "graph": {
                "nodes": [{"id": nid, **ndata} for nid, ndata in self.nodes.items()],
                "edges": self.edges,
            }
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def save(self):
        if not self.nodes and not self.edges:
            nxc_logger.display("Nothing to add to OpenGraph file")
            return

        filename = f"OpenGraph_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
        fullpath = os.path.join(NXC_PATH, "logs", filename)

        try:
            with open(fullpath, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
            nxc_logger.display(f"OpenGraph file successfully saved at {fullpath}")
        except Exception as e:
            nxc_logger.fail(f"Failed to save OpenGraph file: {e}")


# Global instance
opengraph = OpenGraph()
