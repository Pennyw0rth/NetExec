#!/usr/bin/env python3

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rpcrt import DCERPCException

class NXCModule:
    '''
    Retrieve the list of network interfaces info (Name, IP Address, Subnet Mask, Default Gateway) from remote Windows registry'
    Module by Sant0rryu : @Sant0rryu
    '''
    name = 'interface'
    description = 'Retrieve the list of network interfaces info (Name, IP Address, Subnet Mask, Default Gateway) from remote Windows registry'
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_admin_login(self, context, connection):
        self.output = "Name: {} | IP Address: {} | SubnetMask: {} | Gateway: {}"
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            if remoteOps._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans['phKey']

                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces')
                keyHandle = ans['phkResult']

                interface = {}
                subKeys = []
                i = 0
                while True:
                    try:
                        key = rrp.hBaseRegEnumKey(remoteOps._RemoteOperations__rrp, keyHandle, i)
                        subKeys.append(key['lpNameOut'][:-1])
                        i += 1
                    except Exception:
                        break

                for subKey in subKeys:
                    try:
                        interfaceKey = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{}'.format(subKey)
                        ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, interfaceKey)
                        interfaceHandle = ans['phkResult']

                        #Retrieve IPAddress
                        ip_address = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interfaceHandle, 'IPAddress')
                        interface[subKey] = {'IPAddress' : str(ip_address[1])}

                        #Retrieve SubnetMask
                        subnetmask = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interfaceHandle, 'SubnetMask')
                        interface[subKey]['SubnetMask'] = str(subnetmask[1])


                        #Retrieve DefaultGateway
                        defaultgateway = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interfaceHandle, 'DefaultGateway')
                        interface[subKey]['DefaultGateway'] = str(defaultgateway[1])

                        #Retrieve Interace Name 
                        interfaceNameKey = 'SYSTEM\\ControlSet001\\Control\\Network\\' + '{4D36E972-E325-11CE-BFC1-08002BE10318}' + '\\{}\\Connection'.format(subKey)
                        ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, interfaceNameKey)
                        interfaceNameHandle = ans['phkResult']
                        name = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, interfaceNameHandle, 'Name')
                        interface[subKey]['Name'] = str(name[1])


                        context.log.highlight(self.output.format(interface[subKey]['Name'], interface[subKey]['IPAddress'], interface[subKey]['SubnetMask'], interface[subKey]['DefaultGateway']))

                    except DCERPCException:
                        continue

            try:
                remoteOps.finish()
            except Exception:
                pass

        except DCERPCException as e:
            context.log.error(f"Failed to connect to the target: {str(e)}")
