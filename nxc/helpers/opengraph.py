import json
import os
from nxc.paths import NXC_PATH
from datetime import datetime
from nxc.logger import nxc_logger


class OpenGraph:
    # Collects nodes, edges, and properties for BloodHound-CE OpenGraph import.

    def __init__(self):
        self.nodes = {}  # id -> node
        self.edges = []  # list of edges
        self.fqdn2oid = {}  # fqdn -> Object ID

    def add_node(self, node_id, kinds=None, properties=None):
        """Add a new node, or merge with an existing one."""
        node_id = node_id.strip()
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "kinds": kinds or ["Computer", "Base"],
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

    def add_tag(self, node_id, tag_name, value):
        """Add a property/tag (e.g., module vulnerability flag)."""
        node_id = node_id.strip().lower()
        if node_id in self.fqdn2oid:
            node_id = self.fqdn2oid[node_id]
        self.add_node(node_id)  # ensure node exists
        self.nodes[node_id]["properties"][tag_name] = value

    def add_edge(self, kind, start, end, start_match_by="id", end_match_by="id"):
        """
        Add a relationship (edge) between two nodes.

        Automatically replaces FQDNs with GUIDs if:
          - match_by == "id"
          - and the value doesn't start with "S-1-5-21"
        """
        def resolve_if_needed(value, match_by):
            if match_by == "id" and not value.strip().startswith("S-1-5-21"):  # if match by id and value is not an oid
                # Try to map FQDN -> ObjectIdentifier if available
                lookup = value.strip().lower()
                if lookup in self.fqdn2oid:
                    return self.fqdn2oid[lookup]
            return value.strip()

        resolved_start = resolve_if_needed(start, start_match_by)
        resolved_end = resolve_if_needed(end, end_match_by)

        edge = {
            "kind": kind,
            "start": {"value": resolved_start, "match_by": start_match_by},
            "end": {"value": resolved_end, "match_by": end_match_by},
        }
        self.edges.append(edge)

    def simple_bh_mapping(self, path):
        """Build a mapping from host identifiers -> BloodHound node ID."""
        mapping = {}
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for computers in data.get("data", {}):
            oid = computers.get("ObjectIdentifier")
            props = computers.get("Properties", {})
            mapping[props["name"].strip().lower()] = oid
        self.fqdn2oid = mapping

    def to_dict(self):
        """Return the full OpenGraph dict."""
        return {
            "metadata": {
                "source_kind": "NetExec"
            },
            "graph": {
                "nodes": [
                    {"id": nid, **ndata} for nid, ndata in self.nodes.items()
                ],
                "edges": self.edges,
            }
        }

    def to_json(self, indent=2):
        """Return JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self):
        """Write JSON to file."""
        if not self.nodes and not self.edges:
            nxc_logger.display("Nothing to add to OpenGraph file")
            return

        base_log_dir = os.path.join(NXC_PATH, "logs")
        filename_pattern = f"OpenGraph_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
        self.output_filename = os.path.join(base_log_dir, filename_pattern)

        try:
            with open(self.output_filename, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
            nxc_logger.display(f"OpenGraph file successfully saved at {self.output_filename}")
        except Exception as e:
            nxc_logger.fail(f"Failed to save OpenGraph file: {e}")


# Global instance usable anywhere
opengraph = OpenGraph()
