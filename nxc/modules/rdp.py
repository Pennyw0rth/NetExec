from sys import exit

from nxc.connection import dcom_FirewallChecker

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
import contextlib


class NXCModule:
    name = "rdp"
    description = "Enables/Disables RDP"
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """
        ACTION          Enable/Disable RDP (choices: enable, disable, enable-ram, disable-ram)
        METHOD          wmi(ncacn_ip_tcp)/smb(ncacn_np) (choices: wmi, smb, default is wmi)
        OLD             For old version system (under NT6, like: server 2003)
        DCOM-TIMEOUT    Set the Dcom connection timeout for WMI method (Default is 10 seconds)
        nxc smb 192.168.1.1 -u {user} -p {password} -M rdp -o ACTION={enable, disable, enable-ram, disable-ram} {OLD=true} {DCOM-TIMEOUT=5}
        nxc smb 192.168.1.1 -u {user} -p {password} -M rdp -o METHOD=smb ACTION={enable, disable, enable-ram, disable-ram}
        nxc smb 192.168.1.1 -u {user} -p {password} -M rdp -o METHOD=wmi ACTION={enable, disable, enable-ram, disable-ram} {OLD=true} {DCOM-TIMEOUT=5}
        """
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            exit(1)

        if module_options["ACTION"].lower() not in ["enable", "disable", "enable-ram", "disable-ram"]:
            context.log.fail("Invalid value for ACTION option!")
            exit(1)

        self.action = module_options["ACTION"].lower()

        if "METHOD" not in module_options:
            self.method = "wmi"
        else:
            self.method = module_options["METHOD"].lower()

        if context.protocol != "smb" and self.method == "smb":
            context.log.fail(f"Protocol: {context.protocol} not support this method")
            exit(1)

        if "DCOM-TIMEOUT" not in module_options:
            self.dcom_timeout = 10
        else:
            try:
                self.dcom_timeout = int(module_options["DCOM-TIMEOUT"])
            except Exception:
                context.log.fail("Wrong DCOM timeout value!")
                exit(1)

        if "OLD" not in module_options:
            self.oldSystem = False
        else:
            self.oldSystem = True

    def on_admin_login(self, context, connection):
        # Preparation for wmi protocol
        if self.method == "smb":
            context.log.info("Executing over SMB(ncacn_np)")
            try:
                smb_rdp = RdpSmb(context, connection)
                if "ram" in self.action:
                    smb_rdp.rdp_ram_wrapper(self.action)
                else:
                    smb_rdp.rdp_wrapper(self.action)
            except Exception as e:
                context.log.fail(f"Enable RDP via smb error: {e!s}")
        elif self.method == "wmi":
            context.log.info("Executing over WMI(ncacn_ip_tcp)")

            wmi_rdp = RdpWmi(context, connection, self.dcom_timeout)

            if hasattr(wmi_rdp, "_RdpWmi__iWbemLevel1Login"):
                if "ram" in self.action:
                    # Nt version under 6 not support RAM.
                    try:
                        wmi_rdp.rdp_ram_wrapper(self.action)
                    except Exception as e:
                        if "WBEM_E_NOT_FOUND" in str(e):
                            context.log.fail("System version under NT6 not support restricted admin mode")
                        else:
                            context.log.fail(str(e))
                else:
                    try:
                        wmi_rdp.rdp_wrapper(self.action, self.oldSystem)
                    except Exception as e:
                        if "WBEM_E_INVALID_NAMESPACE" in str(e):
                            context.log.fail("Looks like target system version is under NT6, please add 'OLD=true' in module options.")
                        else:
                            context.log.fail(str(e))
                wmi_rdp._RdpWmi__dcom.disconnect()


class RdpSmb:
    def __init__(self, context, connection):
        self.context = context
        self.__smbconnection = connection.conn
        self.__execute = connection.execute
        self.logger = context.log

    def rdp_wrapper(self, action):
        remote_ops = RemoteOperations(self.__smbconnection, False)
        remote_ops.enableRegistry()

        if remote_ops._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remote_ops._RemoteOperations__rrp,
                reg_handle,
                "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            )
            key_handle = ans["phkResult"]

            ans = rrp.hBaseRegSetValue(
                remote_ops._RemoteOperations__rrp,
                key_handle,
                "fDenyTSConnections",
                rrp.REG_DWORD,
                0 if action == "enable" else 1,
            )

            rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "fDenyTSConnections")

            if int(data) == 0:
                self.logger.success("Enable RDP via SMB(ncacn_np) successfully")
            elif int(data) == 1:
                self.logger.success("Disable RDP via SMB(ncacn_np) successfully")

            self.firewall_cmd(action)

            if action == "enable":
                self.query_rdp_port(remote_ops, reg_handle)
        with contextlib.suppress(Exception):
            remote_ops.finish()

    def rdp_ram_wrapper(self, action):
        remote_ops = RemoteOperations(self.__smbconnection, False)
        remote_ops.enableRegistry()

        if remote_ops._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                remote_ops._RemoteOperations__rrp,
                reg_handle,
                "System\\CurrentControlSet\\Control\\Lsa",
            )
            key_handle = ans["phkResult"]

            rrp.hBaseRegSetValue(
                remote_ops._RemoteOperations__rrp,
                key_handle,
                "DisableRestrictedAdmin",
                rrp.REG_DWORD,
                0 if action == "enable-ram" else 1,
            )

            rtype, data = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, "DisableRestrictedAdmin")

            if int(data) == 0:
                self.logger.success("Enable RDP Restricted Admin Mode via SMB(ncacn_np) succeed")
            elif int(data) == 1:
                self.logger.success("Disable RDP Restricted Admin Mode via SMB(ncacn_np) succeed")

        with contextlib.suppress(Exception):
            remote_ops.finish()

    def query_rdp_port(self, remoteOps, regHandle):
        if remoteOps:
            ans = rrp.hBaseRegOpenKey(
                remoteOps._RemoteOperations__rrp,
                regHandle,
                "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            )
            key_handle = ans["phkResult"]

            rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, key_handle, "PortNumber")

            self.logger.success(f"RDP Port: {data!s}")

    # https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/manage/enable_rdp.rb
    def firewall_cmd(self, action):
        cmd = f"netsh firewall set service type = remotedesktop mode = {action}"
        self.logger.info("Configure firewall via execute command.")
        output = self.__execute(cmd, True)
        if output:
            self.logger.success(f"{action.capitalize()} RDP firewall rules via cmd succeed")
        else:
            self.logger.fail(f"{action.capitalize()} RDP firewall rules via cmd failed, maybe got detected by AV software.")


class RdpWmi:
    def __init__(self, context, connection, timeout):
        self.logger = context.log
        self.__currentprotocol = context.protocol
        # From dfscoerce.py
        self.__username = connection.username
        self.__password = connection.password
        self.__domain = connection.domain
        self.__lmhash = connection.lmhash
        self.__nthash = connection.nthash
        self.__target = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
        self.__doKerberos = connection.kerberos
        self.__kdcHost = connection.kdcHost
        self.__remoteHost = connection.host
        self.__aesKey = connection.aesKey
        self.__timeout = timeout

        try:
            self.__dcom = DCOMConnection(
                self.__target,
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
                oxidResolver=True,
                doKerberos=self.__doKerberos,
                kdcHost=self.__kdcHost,
                remoteHost=self.__remoteHost,
            )

            i_interface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            if self.__currentprotocol == "smb":
                flag, self.__stringBinding = dcom_FirewallChecker(i_interface, self.__remoteHost, self.__timeout)
                if not flag or not self.__stringBinding:
                    error_msg = f'RDP-WMI: Dcom initialization failed on connection with stringbinding: "{self.__stringBinding}", please increase the timeout with the module option "DCOM-TIMEOUT=10". If it\'s still failing maybe something is blocking the RPC connection, please try to use "-o" with "METHOD=smb"'

                    if not self.__stringBinding:
                        error_msg = "RDP-WMI: Dcom initialization failed: can't get target stringbinding, maybe cause by IPv6 or any other issues, please check your target again"

                    self.logger.fail(error_msg) if not flag else self.logger.debug(error_msg)
                    # Make it force break function
                    self.__dcom.disconnect()
            self.__iWbemLevel1Login = wmi.IWbemLevel1Login(i_interface)
        except Exception as e:
            self.logger.fail(f'Unexpected wmi error: {e}, please try to use "-o" with "METHOD=smb"')
            if self.__iWbemLevel1Login in locals():
                self.__dcom.disconnect()

    def rdp_wrapper(self, action, old=False):
        if old is False:
            # According to this document: https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tslogonsetting
            # Authentication level must set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY when accessing namespace "//./root/cimv2/TerminalServices"
            i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2/TerminalServices", NULL, NULL)
            i_wbem_services.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.__iWbemLevel1Login.RemRelease()
            i_enum_wbem_class_object = i_wbem_services.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            i_wbem_class_object = i_enum_wbem_class_object.Next(0xFFFFFFFF, 1)[0]
            if action == "enable":
                self.logger.info("Enabled RDP services and setting up firewall.")
                i_wbem_class_object.SetAllowTSConnections(1, 1)
            elif action == "disable":
                self.logger.info("Disabled RDP services and setting up firewall.")
                i_wbem_class_object.SetAllowTSConnections(0, 0)
        else:
            i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            self.__iWbemLevel1Login.RemRelease()
            i_enum_wbem_class_object = i_wbem_services.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            i_wbem_class_object = i_enum_wbem_class_object.Next(0xFFFFFFFF, 1)[0]
            if action == "enable":
                self.logger.info("Enabling RDP services (old system not support setting up firewall)")
                i_wbem_class_object.SetAllowTSConnections(1)
            elif action == "disable":
                self.logger.info("Disabling RDP services (old system not support setting up firewall)")
                i_wbem_class_object.SetAllowTSConnections(0)

        self.query_rdp_result(old)

        if action == "enable":
            self.query_rdp_port()
        # Need to create new iWbemServices interface in order to flush results

    def query_rdp_result(self, old=False):
        if old is False:
            i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2/TerminalServices", NULL, NULL)
            i_wbem_services.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.__iWbemLevel1Login.RemRelease()
            i_enum_wbem_class_object = i_wbem_services.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            i_wbem_class_object = i_enum_wbem_class_object.Next(0xFFFFFFFF, 1)[0]
            result = dict(i_wbem_class_object.getProperties())
            result = result["AllowTSConnections"]["value"]
            if result == 0:
                self.logger.success("Disable RDP via WMI(ncacn_ip_tcp) successfully")
            else:
                self.logger.success("Enable RDP via WMI(ncacn_ip_tcp) successfully")
        else:
            i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            self.__iWbemLevel1Login.RemRelease()
            i_enum_wbem_class_object = i_wbem_services.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            i_wbem_class_object = i_enum_wbem_class_object.Next(0xFFFFFFFF, 1)[0]
            result = dict(i_wbem_class_object.getProperties())
            result = result["AllowTSConnections"]["value"]
            if result == 0:
                self.logger.success("Disable RDP via WMI(ncacn_ip_tcp) successfully (old system)")
            else:
                self.logger.success("Enable RDP via WMI(ncacn_ip_tcp) successfully (old system)")

    def query_rdp_port(self):
        i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/DEFAULT", NULL, NULL)
        self.__iWbemLevel1Login.RemRelease()
        std_reg_prov, resp = i_wbem_services.GetObject("StdRegProv")
        out = std_reg_prov.GetDWORDValue(2147483650, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber")
        self.logger.success(f"RDP Port: {out.uValue!s}")

    # Nt version under 6 not support RAM.
    def rdp_ram_wrapper(self, action):
        i_wbem_services = self.__iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.__iWbemLevel1Login.RemRelease()
        std_reg_prov, resp = i_wbem_services.GetObject("StdRegProv")
        if action == "enable-ram":
            self.logger.info("Enabling Restricted Admin Mode.")
            std_reg_prov.SetDWORDValue(2147483650, "System\\CurrentControlSet\\Control\\Lsa", "DisableRestrictedAdmin", 0)
        elif action == "disable-ram":
            self.logger.info("Disabling Restricted Admin Mode (Clear).")
            std_reg_prov.DeleteValue(2147483650, "System\\CurrentControlSet\\Control\\Lsa", "DisableRestrictedAdmin")
        out = std_reg_prov.GetDWORDValue(2147483650, "System\\CurrentControlSet\\Control\\Lsa", "DisableRestrictedAdmin")
        if out.uValue == 0:
            self.logger.success("Enable RDP Restricted Admin Mode via WMI(ncacn_ip_tcp) successfully")
        elif out.uValue is None:
            self.logger.success("Disable RDP Restricted Admin Mode via WMI(ncacn_ip_tcp) successfully")
