# https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py
from impacket import uuid
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpch import (
    RPC_PROXY_INVALID_RPC_PORT_ERR,
    RPC_PROXY_CONN_A1_0X6BA_ERR,
    RPC_PROXY_CONN_A1_404_ERR,
    RPC_PROXY_RPC_OUT_DATA_404_ERR,
)
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

KNOWN_PROTOCOLS = {
    135: {"bindstr": r"ncacn_ip_tcp:%s[135]"},
    445: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
}


class NXCModule:
    """
    For printnightmare: detect if print spooler is enabled or not. Then use @cube0x0's project https://github.com/cube0x0/CVE-2021-1675 or Mimikatz from Benjamin Delpy
    Module by @mpgn_x64
    """

    name = "spooler"
    description = "Detect if print spooler is enabled or not"
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.__string_binding = None
        self.port = None

    def options(self, context, module_options):
        """PORT    Port to check (defaults to 135)"""
        self.port = 135
        if "PORT" in module_options:
            self.port = int(module_options["PORT"])

    def on_login(self, context, connection):
        entries = []
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        self.__stringbinding = KNOWN_PROTOCOLS[self.port]["bindstr"] % connection.host
        context.log.debug(f"StringBinding {self.__stringbinding}")
        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)
        rpctransport.set_credentials(connection.username, connection.password, connection.domain, lmhash, nthash)
        rpctransport.setRemoteHost(connection.host)
        rpctransport.set_dport(self.port)

        if connection.kerberos:
            rpctransport.set_kerberos(connection.kerberos, connection.kdcHost)

        try:
            entries = self.__fetch_list(connection.kerberos, rpctransport)
        except Exception as e:
            error_text = f"Protocol failed: {e}"
            context.log.critical(error_text)

            if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text or RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or RPC_PROXY_CONN_A1_404_ERR in error_text or RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
                context.log.critical("This usually means the target does not allow to connect to its epmapper using RpcProxy.")
                return

        # Display results.
        endpoints = {}
        # Let's group the UUIDS
        for entry in entries:
            binding = epm.PrintStringBinding(entry["tower"]["Floors"])
            tmp_uuid = str(entry["tower"]["Floors"][0])
            if (tmp_uuid in endpoints) is not True:
                endpoints[tmp_uuid] = {}
                endpoints[tmp_uuid]["Bindings"] = []
            endpoints[tmp_uuid]["EXE"] = epm.KNOWN_UUIDS.get(uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmp_uuid))[:18], "N/A")
            endpoints[tmp_uuid]["annotation"] = entry["annotation"][:-1].decode("utf-8")
            endpoints[tmp_uuid]["Bindings"].append(binding)

            endpoints[tmp_uuid]["Protocol"] = epm.KNOWN_PROTOCOLS.get(tmp_uuid[:36], "N/A")

        for endpoint in list(endpoints.keys()):
            if "MS-RPRN" in endpoints[endpoint]["Protocol"]:
                context.log.debug(f"Protocol: {endpoints[endpoint]['Protocol']} ")
                context.log.debug(f"Provider: {endpoints[endpoint]['EXE']} ")
                context.log.debug(f"UUID    : {endpoint} {endpoints[endpoint]['annotation']}")
                context.log.debug("Bindings: ")
                for binding in endpoints[endpoint]["Bindings"]:
                    context.log.debug(f"          {binding}")
                context.log.debug("")
                context.log.highlight("Spooler service enabled")
                try:
                    host = context.db.get_hosts(connection.host)[0]
                    context.db.add_host(
                        host.ip,
                        host.hostname,
                        host.domain,
                        host.os,
                        host.smbv1,
                        host.signing,
                        spooler=True,
                    )
                except Exception:
                    context.log.debug("Error updating spooler status in database")
                break

        if entries:
            num = len(entries)
            if num == 1:
                context.log.debug("[Spooler] Received one endpoint")
            else:
                context.log.debug(f"[Spooler] Received {num} endpoints")
        else:
            context.log.debug("[Spooler] No endpoints found")

    def __fetch_list(self, doKerberos, rpctransport):
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        resp = epm.hept_lookup(None, dce=dce)
        dce.disconnect()
        return resp
