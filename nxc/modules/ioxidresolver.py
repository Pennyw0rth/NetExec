# Credit to https://airbus-cyber-security.com/fr/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/
# Airbus CERT
# module by @mpgn_x64
# updated by @NeffIsBack

from ipaddress import ip_address
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, DCERPCException
from impacket.dcerpc.v5.dcomrt import IObjectExporter


class NXCModule:
    name = "ioxidresolver"
    description = "This module helps you to identify hosts that have additional active interfaces"
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """DIFFERENT show only ip address if different from target ip (Default: False)"""
        self.pivot = module_options.get("DIFFERENT", "false").lower() in ["true", "1"]

    def on_login(self, context, connection):
        try:
            rpctransport = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{connection.host}")
            rpctransport.setRemoteHost(connection.host)

            portmap = rpctransport.get_dce_rpc()
            portmap.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
            portmap.connect()

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
