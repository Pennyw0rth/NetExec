import os

from io import StringIO
from datetime import datetime

from nxc.helpers.ntlm_parser import parse_challenge
from nxc.config import process_secret
from nxc.connection import connection, dcom_FirewallChecker, requires_admin
from nxc.logger import NXCAdapter
from nxc.protocols.wmi import wmiexec, wmiexec_event

from impacket import ntlm
from impacket.uuid import uuidtup_to_bin
from impacket.krb5.ccache import CCache
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, MSRPC_BIND, MSRPCBind, CtxItem, MSRPCHeader, SEC_TRAILER, MSRPCBindAck
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login

MSRPC_UUID_PORTMAP = uuidtup_to_bin(("E1AF8308-5D1F-11C9-91A4-08002B14A0FA", "3.0"))


class wmi(connection):
    def __init__(self, args, db, host):
        self.domain = ""
        self.targetDomain = ""
        self.hash = ""
        self.lmhash = ""
        self.nthash = ""
        self.server_os = None
        self.doKerberos = False
        self.stringBinding = None
        # from: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
        self.rpc_error_status = {
            "0000052F": "STATUS_ACCOUNT_RESTRICTION",
            "00000533": "STATUS_ACCOUNT_DISABLED",
            "00000775": "STATUS_ACCOUNT_LOCKED_OUT",
            "00000701": "STATUS_ACCOUNT_EXPIRED",
            "00000532": "STATUS_PASSWORD_EXPIRED",
            "00000530": "STATUS_INVALID_LOGON_HOURS",
            "00000531": "STATUS_INVALID_WORKSTATION",
            "00000569": "STATUS_LOGON_TYPE_NOT_GRANTED",
            "00000773": "STATUS_PASSWORD_MUST_CHANGE",
            "00000005": "STATUS_ACCESS_DENIED",
            "0000052E": "STATUS_LOGON_FAILURE",
            "0000052B": "STATUS_WRONG_PASSWORD",
            "00000721": "RPC_S_SEC_PKG_ERROR"
        }

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "WMI",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname
            }
        )

    def create_conn_obj(self):
        connection_target = fr"ncacn_ip_tcp:{self.remoteName}[{self.port!s}]"
        self.logger.debug(f"Creating WMI connection object to {connection_target}")
        try:
            rpctansport = transport.DCERPCTransportFactory(connection_target)
            rpctansport.set_credentials(username="", password="", domain="", lmhash="", nthash="", aesKey="")
            rpctansport.setRemoteHost(self.host)
            rpctansport.set_connect_timeout(self.args.rpc_timeout)
            dce = rpctansport.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
            dce.disconnect()
        except Exception as e:
            self.logger.debug(f"Received error creating WMI connection object: {e}")
            return False
        else:
            self.logger.debug(f"Successfully created WMI connection object to {connection_target}")
            self.conn = rpctansport
            return True

    def enum_host_info(self):
        # All code pick from DumpNTLNInfo.py
        # https://github.com/fortra/impacket/blob/master/examples/DumpNTLMInfo.py

        bind = MSRPCBind()
        item = CtxItem()
        item["AbstractSyntax"] = epm.MSRPC_UUID_PORTMAP
        item["TransferSyntax"] = uuidtup_to_bin(("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0"))
        item["ContextID"] = 0
        item["TransItems"] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet["type"] = MSRPC_BIND
        packet["pduData"] = bind.getData()
        packet["call_id"] = 1

        auth = ntlm.getNTLMSSPType1("", "", signingRequired=True, use_ntlmv2=True)
        sec_trailer = SEC_TRAILER()
        sec_trailer["auth_type"] = RPC_C_AUTHN_WINNT
        sec_trailer["auth_level"] = RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
        sec_trailer["auth_ctx_id"] = 0 + 79231
        pad = (4 - (len(packet.get_packet()) % 4)) % 4
        if pad != 0:
            packet["pduData"] += b"\xFF" * pad
            sec_trailer["auth_pad_len"] = pad
        packet["sec_trailer"] = sec_trailer
        packet["auth_data"] = auth

        try:
            self.conn.connect()
            self.conn.send(packet.get_packet())
            buffer = self.conn.recv()
        except Exception:
            buffer = 0

        if buffer != 0:
            response = MSRPCHeader(buffer)
            bindResp = MSRPCBindAck(response.getData())
            ntlm_info = parse_challenge(bindResp["auth_data"])
            self.targetDomain = self.domain = ntlm_info["domain"]
            self.hostname = ntlm_info["hostname"]
            self.server_os = ntlm_info["os_version"]
            self.logger.extra["hostname"] = self.hostname
        else:
            self.hostname = self.host
        if self.args.local_auth:
            self.domain = self.hostname
        if self.args.domain:
            self.domain = self.args.domain

        # DCOM connection with kerberos needed
        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))

    def print_host_info(self):
        self.logger.extra["protocol"] = "RPC"
        self.logger.extra["port"] = "135"
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.targetDomain})")

    def check_if_admin(self):
        try:
            dcom = DCOMConnection(self.remoteName, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True, doKerberos=self.doKerberos, kdcHost=self.kdcHost, aesKey=self.aesKey, remoteHost=self.host)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            flag, self.stringBinding = dcom_FirewallChecker(iInterface, self.host, self.args.rpc_timeout)
        except Exception as e:
            self.logger.debug(f"Received error while checking admin: {e}")
            if "dcom" in locals():
                dcom.disconnect()
            if "access_denied" not in str(e).lower():
                self.logger.fail(str(e))
        else:
            if not flag or not self.stringBinding:
                dcom.disconnect()
                error_msg = f'Check admin error: dcom initialization failed with stringbinding: "{self.stringBinding}", please try "--rpc-timeout" option. (probably is admin)'

                if not self.stringBinding:
                    error_msg = "Check admin error: dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"

                self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
            else:
                try:
                    iWbemLevel1Login = IWbemLevel1Login(iInterface)
                    iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
                except Exception as e:
                    dcom.disconnect()

                    if "access_denied" not in str(e).lower():
                        self.logger.fail(str(e))
                        return False
                else:
                    dcom.disconnect()
                    self.logger.extra["protocol"] = "WMI"
                    self.admin_privs = True

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.logger.debug("Starting WMI login with Kerberos")
        lmhash = ""
        nthash = ""
        self.password = password
        self.username = username
        self.domain = domain
        self.create_conn_obj()

        if password == "":
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
            else:
                nthash = ntlm_hash
            self.nthash = nthash
            self.lmhash = lmhash

        kerb_pass = next(s for s in [nthash, password, aesKey] if s) if not all(s == "" for s in [nthash, password, aesKey]) else ""

        if useCache and kerb_pass == "":
            ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            self.logger.debug(f"Using ccache from {ccache}")
            username = ccache.credentials[0].header["client"].prettyPrint().decode().split("@")[0]
            self.username = username
        used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
        
        try:
            self.logger.debug(f"Attempting to connect via WMI to {self.host}")
            self.conn.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, aesKey=self.aesKey)
            self.conn.setRemoteHost(self.host)
            self.conn.set_kerberos(True, kdcHost)
            dce = self.conn.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
        except Exception as e:
            dce.disconnect()
            error_msg = str(e).lower()
            self.logger.debug(f"WMI errored while connecting: {error_msg}")
            if "unpack requires a buffer of 4 bytes" in error_msg:
                error_msg = "Kerberos authentication failure"
                out = f"{self.domain}\\{self.username}{used_ccache} {error_msg}"
                self.logger.fail(out)
            elif "kerberos sessionerror" in error_msg:
                out = f"{self.domain}\\{self.username}{used_ccache} {next(iter(e.getErrorString()))}"
                self.logger.fail(out, color="magenta")
            else:
                out = f"{self.domain}\\{self.username}{used_ccache} {e!s}"
                self.logger.fail(out, color="red")
                return False
        else:
            try:
                self.logger.debug("Got valid creds, trying to get data from RPC connection")
                entry_handle = epm.ept_lookup_handle_t()
                request = epm.ept_lookup()
                request["inquiry_type"] = 0x0
                request["object"] = NULL
                request["Ifid"] = NULL
                request["vers_option"] = 0x1
                request["entry_handle"] = entry_handle
                request["max_ents"] = 1
                dce.request(request)
            except Exception as e:
                dce.disconnect()
                error_msg = str(e).lower()
                self.logger.debug(error_msg)
                for code in self.rpc_error_status:
                    if code in error_msg:
                        error_msg = self.rpc_error_status[code]
                out = f"{self.domain}\\{self.username}{used_ccache} {error_msg.upper()}"
                self.logger.fail(out, color=("red" if "access_denied" in error_msg else "magenta"))
                return False
            else:
                self.doKerberos = True
                self.check_if_admin()
                out = f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}"
                self.logger.success(out)
                dce.disconnect()
                return True

    def plaintext_login(self, domain, username, password):
        self.password = password
        self.username = username
        self.domain = domain
        try:
            self.conn.set_credentials(username=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
            dce = self.conn.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
        except Exception as e:
            dce.disconnect()
            self.logger.debug(str(e))
            out = f"{self.domain}\\{self.username}:{process_secret(self.password)} {e!s}"
            self.logger.fail(out, color="red")
        else:
            try:
                # Get data from rpc connection if got vaild creds
                entry_handle = epm.ept_lookup_handle_t()
                request = epm.ept_lookup()
                request["inquiry_type"] = 0x0
                request["object"] = NULL
                request["Ifid"] = NULL
                request["vers_option"] = 0x1
                request["entry_handle"] = entry_handle
                request["max_ents"] = 1
                dce.request(request)
            except Exception as e:
                dce.disconnect()
                error_msg = str(e).lower()
                self.logger.debug(error_msg)
                for code in self.rpc_error_status:
                    if code in error_msg:
                        error_msg = self.rpc_error_status[code]
                self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(self.password)} ({error_msg.upper()})"), color=("red" if "access_denied" in error_msg else "magenta"))
                return False
            else:
                self.check_if_admin()
                dce.disconnect()
                out = f"{domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}"
                if self.username == "" and self.password == "":
                    out += "(Default allow anonymous login)"
                self.logger.success(out)
                return True

    def hash_login(self, domain, username, ntlm_hash):
        self.username = username
        lmhash = ""
        nthash = ""
        if ntlm_hash.find(":") != -1:
            self.lmhash, self.nthash = ntlm_hash.split(":")
        else:
            lmhash = ""
            nthash = ntlm_hash

        self.nthash = nthash
        self.lmhash = lmhash

        try:
            self.conn.set_credentials(username=self.username, password=self.password, domain=self.domain, lmhash=lmhash, nthash=nthash)
            dce = self.conn.get_dce_rpc()
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(MSRPC_UUID_PORTMAP)
        except Exception as e:
            dce.disconnect()
            self.logger.debug(str(e))
            out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {e!s}"
            self.logger.fail(out, color="red")
        else:
            try:
                # Get data from rpc connection if got vaild creds
                entry_handle = epm.ept_lookup_handle_t()
                request = epm.ept_lookup()
                request["inquiry_type"] = 0x0
                request["object"] = NULL
                request["Ifid"] = NULL
                request["vers_option"] = 0x1
                request["entry_handle"] = entry_handle
                request["max_ents"] = 1
                dce.request(request)
            except Exception as e:
                dce.disconnect()
                error_msg = str(e).lower()
                self.logger.debug(error_msg)
                for code in self.rpc_error_status:
                    if code in error_msg:
                        error_msg = self.rpc_error_status[code]
                self.logger.fail((f"{self.domain}\\{self.username}:{process_secret(self.nthash)} ({error_msg.upper()})"), color=("red" if "access_denied" in error_msg else "magenta"))
                return False
            else:
                self.check_if_admin()
                dce.disconnect()
                out = f"{domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}"
                if self.username == "" and self.password == "":
                    out += "(Default allow anonymous login)"
                self.logger.success(out)
                return True

    # It's very complex to use wmi from rpctansport "convert" to dcom, so let we use dcom directly.
    @requires_admin
    def wmi(self, wql=None, namespace=None):
        """Execute WQL syntax via WMI
        
        This is done via the --wmi flag
        """
        records = []
        if not wql:
            wql = self.args.wmi.strip("\n")

        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            dcom = DCOMConnection(self.remoteName, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True, doKerberos=self.doKerberos, kdcHost=self.kdcHost, aesKey=self.aesKey, remoteHost=self.host)
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery(wql)
        except Exception as e:
            dcom.disconnect()
            self.logger.debug(str(e))
            self.logger.fail(f"Execute WQL error: {e}")
            return False
        else:
            self.logger.info(f"Executing WQL syntax: {wql}")
            try:
                while True:
                    wmi_results = iEnumWbemClassObject.Next(0xFFFFFFFF, 1)[0]
                    record = wmi_results.getProperties()
                    records.append(record)
                    for k, v in record.items():
                        self.logger.highlight(f"{k} => {v['value']}")
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    self.logger.debug(e)

            dcom.disconnect()

            return records

    @requires_admin
    def execute(self, command=None, get_output=False):
        output = ""
        if not command:
            command = self.args.execute

        if not self.args.no_output:
            get_output = True

        if "systeminfo" in command and self.args.exec_timeout < 10:
            self.logger.fail("Execute 'systeminfo' must set the interval time higher than 10 seconds")
            return False

        if self.server_os is not None and "NT 5" in self.server_os:
            self.logger.fail("Execute command failed, not support current server os (version < NT 6)")
            return False

        if self.args.exec_method == "wmiexec":
            exec_method = wmiexec.WMIEXEC(self.remoteName, self.username, self.password, self.domain, self.lmhash, self.nthash, self.doKerberos, self.kdcHost, self.host, self.aesKey, self.logger, self.args.exec_timeout, self.args.codec)
            output = exec_method.execute(command, get_output)

        elif self.args.exec_method == "wmiexec-event":
            exec_method = wmiexec_event.WMIEXEC_EVENT(self.remoteName, self.username, self.password, self.domain, self.lmhash, self.nthash, self.doKerberos, self.kdcHost, self.host, self.aesKey, self.logger, self.args.exec_timeout, self.args.codec)
            output = exec_method.execute(command, get_output)

        self.conn.disconnect()
        if output == "" and get_output:
            self.logger.fail("Execute command failed, probabaly got detection by AV.")
            return False
        else:
            self.logger.success(f'Executed command: "{command}" via {self.args.exec_method}')
            buf = StringIO(output).readlines()
            for line in buf:
                self.logger.highlight(line.strip())
            return output
