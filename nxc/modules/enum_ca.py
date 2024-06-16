from impacket.dcerpc.v5 import transport, epm
from impacket.http import AUTH_NTLM
from impacket.dcerpc.v5.rpch import RPC_PROXY_INVALID_RPC_PORT_ERR, \
    RPC_PROXY_CONN_A1_0X6BA_ERR, RPC_PROXY_CONN_A1_404_ERR, \
    RPC_PROXY_RPC_OUT_DATA_404_ERR
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket import uuid
import requests


class NXCModule:
    """
    -------
    Module by @0xjbb, original code from Impacket rpcdump.py
    """
    KNOWN_PROTOCOLS = {
        135: {"bindstr": r"ncacn_ip_tcp:%s[135]"},
        139: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
        443: {"bindstr": r"ncacn_http:[593,RpcProxy=%s:443]"},
        445: {"bindstr": r"ncacn_np:%s[\pipe\epmapper]"},
        593: {"bindstr": r"ncacn_http:%s"}
    }

    name = "enum_ca"
    description = "Anonymously uses RPC endpoints to hunt for ADCS CAs"
    supported_protocols = ["smb"]  # Example: ['smb', 'mssql']
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does it make sense to run this module on multiple hosts at a time?

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        self.__username = connection.username
        self.__password = connection.password
        self.__domain = connection.domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__port = 135.
        self.__stringbinding = ""

        if context.hash and ":" in context.hash[0]:
            hashList = context.hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif context.hash and ":" not in context.hash[0]:
            self.__nthash = context.hash[0]
            self.__lmhash = "00000000000000000000000000000000"

        self.__stringbinding = self.KNOWN_PROTOCOLS[self.__port]["bindstr"] % connection.host
        context.log.debug(f"StringBinding {self.__stringbinding}")

        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)

        if self.__port in [139, 445]:
            # Setting credentials for SMB
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            rpctransport.setRemoteHost(connection.host)
            rpctransport.set_dport(self.__port)
        elif self.__port in [443]:
            # Setting credentials only for RPC Proxy, but not for the MSRPC level
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            rpctransport.set_auth_type(AUTH_NTLM)
        else:
            rpctransport.setRemoteHost(connection.host)

        try:
            entries = self.__fetchList(connection.kerberos, rpctransport)
        except Exception as e:
            error_text = f"Protocol failed: {e}"
            context.log.fail(error_text)

            if RPC_PROXY_INVALID_RPC_PORT_ERR in error_text or \
               RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or \
               RPC_PROXY_CONN_A1_404_ERR in error_text or \
               RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
                context.log.fail("This usually means the target does not allow "
                                 "to connect to its epmapper using RpcProxy.")
                return
        for entry in entries:
            tmpUUID = str(entry["tower"]["Floors"][0])

            if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                exename = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
                context.log.debug("EXEs %s" % exename)
                if exename == "certsrv.exe":
                    context.log.highlight("Active Directory Certificate Services Found.")
                    url = f"http://{connection.host}/certsrv/certfnsh.asp"
                    context.log.highlight(url)
                    try:
                        response = requests.get(url, timeout=5)
                        if response.status_code == 401 and "WWW-Authenticate" in response.headers and "ntlm" in response.headers["WWW-Authenticate"].lower():
                            context.log.highlight("Web enrollment found on HTTP (ESC8).")
                    except requests.RequestException as e:
                        context.log.debug(e)
                    return

    def __fetchList(self, doKerberos, rpctransport):
        dce = rpctransport.get_dce_rpc()
        if doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        resp = epm.hept_lookup(None, dce=dce)
        dce.disconnect()
        return resp
