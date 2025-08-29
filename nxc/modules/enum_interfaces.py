#!/usr/bin/env python3

import contextlib
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Retrieve the list of network interfaces info (Name, IP Address, Subnet Mask, Default Gateway) from remote Windows registry'
    Formerly --interfaces parameter
    Made by: @Sant0rryu, @NeffIsBack
    """

    name = "enum_interfaces"
    description = "Retrieve the list of network interfaces info (Name, IP Address, Subnet Mask, Default Gateway) from remote Windows registry (formerly --interfaces)"
    supported_protocols = ["smb"]
    opsec_safe = False
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = {}

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        """Execute network interface enumeration on authenticated SMB connection"""
        self.context = context

        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            if remoteOps._RemoteOperations__rrp:
                reg_handle = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)["phKey"]
                key_handle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, reg_handle, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces")["phkResult"]
                sub_key_list = rrp.hBaseRegQueryInfoKey(remoteOps._RemoteOperations__rrp, key_handle)["lpcSubKeys"]
                sub_keys = [rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, key_handle, i)["lpNameOut"][:-1] for i in range(sub_key_list)]

                context.log.highlight(f"{'-Name-':<11} | {'-IP Address-':<15} | {'-SubnetMask-':<15} | {'-Gateway-':<15} | -DHCP-")
                for sub_key in sub_keys:
                    interface = {}
                    try:
                        interface_key = f"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{sub_key}"
                        interface_handle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, reg_handle, interface_key)["phkResult"]

                        # Retrieve Interace Name
                        interface_name_key = f"SYSTEM\\ControlSet001\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{sub_key}\\Connection"
                        interface_name_handle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, reg_handle, interface_name_key)["phkResult"]
                        interface_name = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_name_handle, "Name")[1].rstrip("\x00")
                        interface["Name"] = str(interface_name)
                        if "Kernel" in interface_name:
                            continue

                        # Retrieve DHCP
                        try:
                            dhcp_enabled = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "EnableDHCP")[1]
                        except DCERPCException:
                            dhcp_enabled = False
                        interface["DHCP"] = bool(dhcp_enabled)

                        # Retrieve IPAddress
                        try:
                            ip_address = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "DhcpIPAddress" if dhcp_enabled else "IPAddress")[1].rstrip("\x00").replace("\x00", ", ")
                        except DCERPCException:
                            ip_address = None
                        interface["IPAddress"] = ip_address if ip_address else None

                        # Retrieve SubnetMask
                        try:
                            subnetmask = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "SubnetMask")[1].rstrip("\x00").replace("\x00", ", ")
                        except DCERPCException:
                            subnetmask = None
                        interface["SubnetMask"] = subnetmask if subnetmask else None

                        # Retrieve DefaultGateway
                        try:
                            default_gateway = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interface_handle, "DhcpDefaultGateway")[1].rstrip("\x00").replace("\x00", ", ")
                        except DCERPCException:
                            default_gateway = None
                        interface["DefaultGateway"] = default_gateway if default_gateway else None

                        context.log.highlight(f"{interface['Name']:<11} | {interface['IPAddress']!s:<15} | {interface['SubnetMask']!s:<15} | {interface['DefaultGateway']!s:<15} | {interface['DHCP']}")

                    except DCERPCException as e:
                        context.log.info(f"Failed to retrieve the network interface info for {sub_key}: {e!s}")

            with contextlib.suppress(Exception):
                remoteOps.finish()
        except DCERPCException as e:
            context.log.error(f"Failed to connect to the target: {e!s}")
