import re
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

class NXCModule:
    name = "bitlocker"
    description = "Enumerating BitLocker Status on target(s) If it is enabled or disabled."
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """ 
        USAGE:
        
        NetExec smb <IP> -u <username> -p <password> -M bitlocker
        NetExec wmi <IP> -u <username> -p <password> -M bitlocker (Better option to use on real life.)
        """

    def on_admin_login(self, context, connection):
        if context.protocol == "smb":
            bitlocker_smb = BitLockerSMB(context, connection)
            bitlocker_smb.check_bitlocker_status()
        elif context.protocol == "wmi":
            bitlocker_wmi = BitLockerWMI(context, connection)
            bitlocker_wmi.check_bitlocker_status()


class BitLockerSMB:
    def __init__(self, context, connection):
        self.context = context
        self.connection = connection

    def check_bitlocker_status(self):
        # PowerShell command to check BitLocker volumes status.
        check_bitlocker_command_str = 'powershell.exe "Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, ProtectionStatus"'

        try:
            # Executing the PowerShell command to get BitLocker volumes status.
            check_bitlocker_command_str_output = self.connection.execute(check_bitlocker_command_str, True)
            
            if "'Get-BitLockerVolume' is not recognized" in check_bitlocker_command_str_output:
                self.context.log.fail("BitLockerVolume not found on target.")
                return

            # Splitting the output into lines.
            lines = str(check_bitlocker_command_str_output).splitlines()
            data_lines = [line for line in lines if re.match(r"\w:", line)]
            
            for line in data_lines:
                # Checking every line for starting with drive
                if line[1] == ":": 
                    parts = line.split()
                    MountPoint, EncryptionMethod, protection_status = parts[0], parts[1], parts[2]

                    # Checking if BitLocker is enabled.
                    if protection_status == "On":
                        self.context.log.highlight(f"BitLocker is enabled on drive {MountPoint} (Encryption Method: {EncryptionMethod})")
                    else:
                        self.context.log.highlight(f"BitLocker is disabled on drive {MountPoint}")
        except Exception as e:
            self.context.log.exception(f"Exception occurred: {e}")


class BitLockerWMI:
    def __init__(self, context, connection):
        self.context = context
        self.connection = connection

    def check_bitlocker_status(self):
        try:
            # Create a DCOM connection
            dcom_conn = DCOMConnection(
                self.connection.host,
                self.connection.username,
                self.connection.password,
                self.connection.domain,
                self.connection.lmhash,
                self.connection.nthash,
                oxidResolver=True,
                doKerberos=self.connection.kerberos,
                kdcHost=self.connection.kdcHost)
                
            try:
                # CoCreateInstanceEx for WMI login
                i_interface = dcom_conn.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(i_interface)

                # Specify the namespace for BitLocker
                bitlockerNamespace = "root\\CIMv2\\Security\\MicrosoftVolumeEncryption"
                
                # NTLM login for WMI
                iWbemServices = iWbemLevel1Login.NTLMLogin(bitlockerNamespace, NULL, NULL)

                # Set authentication level
                iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

                # Query to get BitLocker status
                classQuery = "SELECT DriveLetter, ProtectionStatus, EncryptionMethod FROM Win32_EncryptableVolume"
                iEnumWbemClassObject = iWbemServices.ExecQuery(classQuery)
                encryptionTypeMapping = {0: "None", 1: "AES_256_WITH_DIFFUSER", 2: "AES_256_WITH_DIFFUSER", 3: "AES_128", 4: "AES_256", 5: "HARDWARE_ENCRYPTION", 6: "XTS_AES_128", 7: "XTS_AES_256"}
                
                try:
                    while True:
                        iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff, 1)
                        encryptionMethod = int(iWbemClassObject[0].EncryptionMethod)
                        if iWbemClassObject[0].ProtectionStatus == 1:
                            self.context.log.highlight(f"BitLocker is enabled on drive {iWbemClassObject[0].DriveLetter} (Encryption Method: {encryptionTypeMapping.get(encryptionMethod, 'Unknown')})")
                        else:
                            if encryptionMethod == 0:  # Should be 0 if disabled
                                self.context.log.highlight(f"BitLocker is disabled on drive {iWbemClassObject[0].DriveLetter}")
                except Exception:
                    pass  # Using pass because if try to log or printing, getting "WMI Session Error: code: 0x1 - WBEM_S_FALSE"

                # Release resources
                iWbemLevel1Login.RemRelease()
                iWbemServices.RemRelease()
                dcom_conn.disconnect()
            except Exception as e:
                if "WBEM_E_INVALID_NAMESPACE" in str(e):
                    self.context.log.fail("BitLockerNamespace not found on target.")
                    dcom_conn.disconnect()
        except Exception as e:
            self.context.log.error(f"Error occurred during BitLocker check: {e}")
            dcom_conn.disconnect()
