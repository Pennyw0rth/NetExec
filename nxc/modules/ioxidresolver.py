# Credit to https://airbus-cyber-security.com/fr/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/
# Airbus CERT
# module by @mpgn_x64
# updated by @NeffIsBack

from ipaddress import ip_address
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, DCERPCException
from impacket.dcerpc.v5.dcomrt import IObjectExporter, IID_IObjectExporter
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection


class NXCModule:
    name = "ioxidresolver"
    description = "This module helps you to identify hosts that have additional active interfaces"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """DIFFERENT show only ip address if different from target ip (Default: False)"""
        self.pivot = module_options.get("DIFFERENT", "false").lower() in ["true", "1"]

    def on_login(self, context, connection):
        try:
            portmap = NXCRPCConnection(connection, force_tcp=True).connect(
                None,
                IID_IObjectExporter,
                target_ip=connection.host,
                auth_level=RPC_C_AUTHN_LEVEL_NONE,
                anonymous_rpc=True,
            )

            objExporter = IObjectExporter(portmap)
            bindings = objExporter.ServerAlive2()

            context.log.debug(f"Retrieving network interface of {connection.host}")

            for binding in bindings:
                NetworkAddr = binding["aNetworkAddr"]
                try:
                    ip_address(NetworkAddr[:-1])
                    if self.pivot:
                        if NetworkAddr.rstrip("\x00") != connection.host:
                            context.log.highlight(f"Address: {NetworkAddr}")
                    else:
                        context.log.highlight(f"Address: {NetworkAddr}")
                except Exception as e:
                    context.log.debug(e)
        except DCERPCException as e:
            context.log.error(f"DCERPCException error: {e}")
