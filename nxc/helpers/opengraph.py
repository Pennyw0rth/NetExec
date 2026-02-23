import json
import os
import zipfile
import tempfile
import shutil

from nxc.paths import NXC_PATH, TMP_PATH
from datetime import datetime
from nxc.logger import nxc_logger


class OpenGraph:
    # Collects nodes, edges, and properties for BloodHound-CE OpenGraph import.

    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.name2oid = {}

# ------------------------- MAPPINF ----------------------------

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
        nxc_logger.debug(f"user file is {comp_file}")

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

    def ldap_mapping(self):
        # TODO
        pass

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
                    return self.name2oid[lookup]
            return v

        edge = {
            "kind": kind,
            "start": {"value": resolve(start, start_match_by), "match_by": start_match_by},
            "end": {"value": resolve(end, end_match_by), "match_by": end_match_by},
        }
        self.edges.append(edge)

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
