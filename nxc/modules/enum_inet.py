#!/usr/bin/env python3

import struct
import ipaddress
from impacket.smb3structs import SMB2_0_IOCTL_IS_FSCTL


class NXCModule:
    """
    NetExec module for enumerating active network interfaces via SMB
    Module by Ilya Yatsenko (@fulc2um)
    """

    name = "enum_inet"
    description = "Enumerate active network interfaces via SMB using FSCTL_QUERY_NETWORK_INTERFACE_INFO"
    supported_protocols = ["smb"]
    opsec_safe = False

    def __init__(self):
        self.context = None
        self.module_options = {}

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        """Execute network interface enumeration on authenticated SMB connection"""
        self.context = context

        try:
            context.log.display("Starting network interface enumeration")

            tree_id = connection.conn.connectTree("IPC$")

            FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC

            response = connection.conn._SMBConnection.ioctl(
                tree_id,
                fileId=None,
                ctlCode=FSCTL_QUERY_NETWORK_INTERFACE_INFO,
                flags=SMB2_0_IOCTL_IS_FSCTL,
                inputBlob=b"",
                maxOutputResponse=8192
            )

            if response:
                context.log.success("Retrieved network interface data")
                self._parse_response(context, response)
            else:
                context.log.fail("No response data received")

            connection.conn.disconnectTree(tree_id)

        except Exception as e:
            context.log.fail(f"Error during network interface enumeration: {e}")
            context.log.fail(f"Full error: {e}", exc_info=True)

    def _parse_response(self, context, data):
        """Parse FSCTL_QUERY_NETWORK_INTERFACE_INFO response data"""
        if not data:
            context.log.fail("No data to parse")
            return

        # Parse and group interfaces
        grouped_interfaces = {}
        offset = 0

        while offset < len(data) and offset + 152 <= len(data):
            try:
                # Parse NETWORK_INTERFACE_INFO structure
                next_offset = struct.unpack("<L", data[offset:offset + 4])[0]
                if_index = struct.unpack("<L", data[offset + 4:offset + 8])[0]
                capabilities = struct.unpack("<L", data[offset + 8:offset + 12])[0]
                link_speed = struct.unpack("<Q", data[offset + 16:offset + 24])[0]

                # Socket address (SockAddr_Storage at offset+24)
                family = struct.unpack("<H", data[offset + 24:offset + 26])[0]

                if family == 0x0002:  # IPv4
                    ip_bytes = data[offset + 28:offset + 32]
                    ip_addr = ipaddress.IPv4Address(ip_bytes)
                    addr_info = f"IPv4: {ip_addr}"
                elif family == 0x0017:  # IPv6
                    ip6_bytes = data[offset + 32:offset + 48]
                    ip_addr = ipaddress.IPv6Address(ip6_bytes)
                    addr_info = f"IPv6: {ip_addr}"
                else:
                    addr_info = f"Unknown family: 0x{family:04x}"

                # Group by interface index
                if if_index not in grouped_interfaces:
                    caps = []
                    if capabilities & 0x01:
                        caps.append("RSS")
                    if capabilities & 0x02:
                        caps.append("RDMA")

                    grouped_interfaces[if_index] = {
                        "capabilities": caps,
                        "link_speed": link_speed,
                        "addresses": []
                    }

                grouped_interfaces[if_index]["addresses"].append(addr_info)

                if next_offset == 0:
                    break

                offset = next_offset if next_offset > offset else offset + next_offset
                if offset >= len(data):
                    break

            except (struct.error, IndexError) as e:
                context.log.fail(f"Error parsing interface at offset {offset}: {e}")
                break

        self._display_interfaces(context, grouped_interfaces)

    def _display_interfaces(self, context, grouped_interfaces):
        if not grouped_interfaces:
            context.log.fail("No network interfaces found")
            return

        context.log.highlight(f"Found {len(grouped_interfaces)} network interface(s)")

        for i, if_index in enumerate(sorted(grouped_interfaces.keys())):
            iface = grouped_interfaces[if_index]
            caps_str = ", ".join(iface["capabilities"]) if iface["capabilities"] else "None"
            speed_mbps = iface["link_speed"] / 1000000

            context.log.display(f"Interface {i + 1} (Index: {if_index}):")
            context.log.display(f"  - Capabilities: {caps_str}")
            context.log.display(f"  - Speed: {speed_mbps:.0f} Mbps")
            context.log.display("  - Addresses:")

            for addr in iface["addresses"]:
                prefix = "      -"
                context.log.display(f"{prefix} {addr}")
