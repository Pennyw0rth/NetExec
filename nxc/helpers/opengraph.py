import json
import os
from nxc.paths import NXC_PATH
from datetime import datetime
from nxc.logger import nxc_logger


class OpenGraph:
    # Collects nodes and properties for BloodHound-CE OpenGraph import.

    def __init__(self):
        self.nodes = {}  # id -> node
        self.fqdn2oid = {}  # fqdn -> Object ID

    def add_node(self, node_id: str, kinds=None, properties=None):
        """Add a new node, or merge with an existing one."""
        node_id = node_id.strip().lower()
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

    def add_tag(self, node_id: str, tag_name: str, value=True):
        node_id = node_id.strip().lower()
        # Add a property/tag
        self.add_node(node_id)  # ensure node exists
        self.nodes[node_id]["properties"][tag_name] = value

    def simple_bh_mapping(self, path):
        """
        Build a mapping from host identifiers -> BloodHound node ID
        using *_computers.json files.
        """
        mapping = {}
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for computers in data.get("data", {}):
            oid = computers.get("ObjectIdentifier")
            props = computers.get("Properties", {})
            mapping[props["name"].strip().lower()] = oid
        return mapping

    def update_node_ids_to_guids(self, path):
        """
        Replace node 'id' values that match resolved hostnames with GUIDs.
        Does not alter properties or kinds.
        """
        self.fqdn2oid = self.simple_bh_mapping(path)
        updated_nodes = {}
        for nid, ndata in self.nodes.items():
            new_id = self.fqdn2oid.get(nid.strip().lower(), nid)
            updated_nodes[new_id] = ndata
        self.nodes = updated_nodes

    def to_dict(self):
        """Return the full OpenGraph dict"""
        return {
            "graph": {
                "nodes": [
                    {"id": nid, **ndata} for nid, ndata in self.nodes.items()
                ]
            }
        }

    def to_json(self, indent=2):
        """Return JSON string"""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self):
        """Write JSON to file"""
        if self.nodes == {}:
            nxc_logger.display("Nothing to add to OpenGaph file")

        # Construct the output file template using os.path.join for OS compatibility
        base_log_dir = os.path.join(NXC_PATH, "logs")
        filename_pattern = f"OpenGraph_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json".replace(":", "-")
        self.output_file_template = os.path.join(base_log_dir, filename_pattern)
        # Default output filename for logs
        self.output_filename = os.path.join(base_log_dir, filename_pattern)
        try:
            with open(self.output_filename, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)
            nxc_logger.display(f"OpenGraph file successfully saved at {self.output_filename}")
        except Exception as e:
            nxc_logger.fail(f"Failed to save OpenGraph file: {e}")


# Global instance usable anywhere
opengraph = OpenGraph()
