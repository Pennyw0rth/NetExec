"""
Tests for the NetExec ntds_shadow module.

All WinRM I/O is mocked. Tests use a fixed run_id for deterministic path
assertions. No live DC, no credential material.

Run:
    pytest tests/test_ntds_shadow.py -v
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from nxc.modules.ntds_shadow import (
    NXCModule,
    RunState,
    _ModuleAbort,
    _run_cmd,
    build_cleanup_script,
    build_create_script,
    build_delete_only_script,
    build_secretsdump_command,
    parse_alias_guid,
    parse_diskshadow_cleanup_transcript,
    parse_drive_letters,
    parse_expose_confirmation,
    parse_remote_file_size,
    select_drive_letter,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

FIXED_RUN_ID = "abcd1234"
FIXED_GUID = "11111111-2222-3333-4444-555555555555"
LETTER_GUID = "AABBCCDD-EEFF-1122-3344-556677889900"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_conn(ps_responses=None):
    """Return a MagicMock conn with configurable execute_ps / copy.

    Native-command calls go through _run_cmd (which uses execute_ps internally).
    Tests that exercise native-command phases must patch
    nxc.modules.ntds_shadow._run_cmd rather than conn.execute_cmd.
    """
    conn = MagicMock()
    ps_seq = list(ps_responses or [])

    def _ps(ps):
        if ps_seq:
            return ps_seq.pop(0)
        return ("", MagicMock(), False)

    conn.execute_ps.side_effect = _ps
    conn.copy.return_value = None
    return conn


def make_context():
    ctx = MagicMock()
    ctx.log = MagicMock()
    return ctx


def make_connection(conn):
    connection = MagicMock()
    connection.conn = conn
    return connection


def _valid_cleanup_stdout(guid=FIXED_GUID):
    return (
        f"-> DELETE SHADOWS ID {{{guid}}}\r\n"
        f"Deleting shadow copy {{{guid.lower()}}}...\r\n"
        "1 shadow copy deleted.\r\n"
    )


def _make_run_cmd_conn(stdout="", stderr="", exitcode=0, had_errors=False):
    conn = MagicMock()
    result = json.dumps({"Stdout": stdout, "Stderr": stderr, "ExitCode": exitcode})
    conn.execute_ps.return_value = (result, MagicMock(), had_errors)
    return conn


# ---------------------------------------------------------------------------
# RunState
# ---------------------------------------------------------------------------


class TestRunState:
    def test_path_layout(self):
        s = RunState(FIXED_RUN_ID)
        assert FIXED_RUN_ID in s.staging_dir
        assert s.staging_dir == rf"C:\Windows\Temp\nxc-{FIXED_RUN_ID}"
        assert s.create_script.startswith(s.staging_dir)
        assert s.create_script.endswith("ds-create.txt")
        assert s.cleanup_script.startswith(s.staging_dir)
        assert s.cleanup_script.endswith("ds-cleanup.txt")
        assert FIXED_RUN_ID in s.alias
        assert s.alias.isascii()
        assert s.alias.isalnum()
        for path in s.residual_paths():
            assert path.startswith(s.staging_dir)


# ---------------------------------------------------------------------------
# parse_alias_guid
# ---------------------------------------------------------------------------


class TestParseAliasGuid:
    def test_standard_output_returns_guid(self):
        alias = "nxcshadowabcd1234"
        stdout = (
            "-> expose %nxcshadowabcd1234% Z:\r\n"
            f"-> %nxcshadowabcd1234% = {{{FIXED_GUID}}}\r\n"
            "The shadow copy was successfully exposed as Z:\\.\r\n"
        )
        assert parse_alias_guid(stdout, alias) == FIXED_GUID

    def test_case_insensitive_alias_and_guid_uppercased(self):
        alias = "nxcshadowabcd"
        guid_lower = "aabbccdd-1122-3344-5566-778899aabbcc"
        stdout = f"-> %NXCSHADOWABCD% = {{{guid_lower}}}\r\n"
        assert parse_alias_guid(stdout, alias) == guid_lower.upper()

    def test_without_percent_delimiters(self):
        alias = "nxcshadowabcd"
        stdout = f"nxcshadowabcd = {{{FIXED_GUID}}}\r\n"
        assert parse_alias_guid(stdout, alias) == FIXED_GUID

    def test_other_alias_lines_not_counted(self):
        alias = "nxcshadowabcd"
        other_guid = "AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF"
        stdout = (
            f"-> %nxcshadowxxxx% = {{{other_guid}}}\r\n"
            f"-> %{alias}% = {{{FIXED_GUID}}}\r\n"
        )
        assert parse_alias_guid(stdout, alias) == FIXED_GUID

    @pytest.mark.parametrize(
        ("stdout", "alias"),
        [
            ("no alias here", "nxcshadowabcd"),
            ("", "nxcshadowabcd"),
            (f"-> %nxcshadowXXXX% = {{{FIXED_GUID}}}\r\n", "nxcshadowYYYY"),
        ],
    )
    def test_returns_none(self, stdout, alias):
        assert parse_alias_guid(stdout, alias) is None

    @pytest.mark.parametrize(
        ("stdout", "match"),
        [
            (
                (
                    f"-> %nxcshadowabcd% = {{{FIXED_GUID}}}\r\n"
                    f"-> %nxcshadowabcd% = {{{FIXED_GUID}}}\r\n"
                ),
                "2 alias-to-GUID",
            ),
            (
                "-> %nxcshadowabcd% = {not-a-valid-guid}\r\n",
                "malformed GUID",
            ),
            (
                f"-> %nxcshadowabcd% = {{{FIXED_GUID}-EXTRA}}\r\n",
                "malformed GUID",
            ),
        ],
    )
    def test_raises_valueerror(self, stdout, match):
        with pytest.raises(ValueError, match=match):
            parse_alias_guid(stdout, "nxcshadowabcd")


# ---------------------------------------------------------------------------
# parse_expose_confirmation
# ---------------------------------------------------------------------------


class TestParseExposeConfirmation:
    _REAL_Z = "The shadow copy was successfully exposed as Z:\\.\r\n"
    _REAL_Y = "The shadow copy was successfully exposed as Y:\\.\r\n"

    def test_real_output_with_context_lines(self):
        stdout = (
            "-> expose %nxcshadow773fcfc4% Z:\r\n"
            f"-> %nxcshadow773fcfc4% = {{{FIXED_GUID}}}\r\n" + self._REAL_Z
        )
        assert parse_expose_confirmation(stdout, "Z") is True

    def test_case_insensitive_and_lf_accepted(self):
        assert parse_expose_confirmation(self._REAL_Z.lower(), "Z") is True
        assert (
            parse_expose_confirmation(self._REAL_Z.replace("\r\n", "\n"), "Z") is True
        )

    def test_drive_letter_colon_suffix_handled(self):
        assert parse_expose_confirmation(self._REAL_Z, "Z:") is True

    @pytest.mark.parametrize(
        "stdout",
        [
            "The shadow copy was successfully exposed as Y:\\.\r\n",
            "The shadow copy was successfully exposed as Z:.\r\n",
            "The shadow copy was successfully exposed as Z:\\\r\n",
            "-> expose %nxcshadow773fcfc4% Z:\r\n",
            "AUDIT: The shadow copy was successfully exposed as Z:\\. Details.\r\n",
            "",
        ],
    )
    def test_false_cases(self, stdout):
        assert parse_expose_confirmation(stdout, "Z") is False

    def test_duplicate_semantic_lines_raises(self):
        with pytest.raises(ValueError, match="2 expose confirmation"):
            parse_expose_confirmation(self._REAL_Z + self._REAL_Z, "Z")

    def test_conflicting_drives_raises(self):
        with pytest.raises(ValueError, match="2 expose confirmation"):
            parse_expose_confirmation(self._REAL_Z + self._REAL_Y, "Z")


# ---------------------------------------------------------------------------
# parse_diskshadow_cleanup_transcript
# ---------------------------------------------------------------------------


class TestParseDiskshadowCleanupTranscript:
    _LAB_STDOUT = (
        f"-> UNEXPOSE Z:\r\n"
        f"Shadow copy ID {{{FIXED_GUID.lower()}}} is no longer exposed.\r\n"
        f"-> DELETE SHADOWS ID {{{FIXED_GUID}}}\r\n"
        f"Deleting shadow copy {{{FIXED_GUID.lower()}}}...\r\n"
        "1 shadow copy deleted.\r\n"
        "-> EXIT\r\n"
    )

    def test_exact_lab_output_succeeds(self):
        parse_diskshadow_cleanup_transcript(self._LAB_STDOUT, FIXED_GUID)

    def test_no_unexpose_line_still_accepted(self):
        stdout = (
            f"-> DELETE SHADOWS ID {{{FIXED_GUID}}}\r\n"
            f"Deleting shadow copy {{{FIXED_GUID.lower()}}}...\r\n"
            "1 shadow copy deleted.\r\n"
        )
        parse_diskshadow_cleanup_transcript(stdout, FIXED_GUID)

    def test_case_insensitive_guid_match(self):
        stdout = (
            f"Deleting shadow copy {{{LETTER_GUID.lower()}}}...\r\n"
            "1 shadow copy deleted.\r\n"
        )
        parse_diskshadow_cleanup_transcript(stdout, LETTER_GUID)

    @pytest.mark.parametrize(
        ("stdout", "match"),
        [
            (
                f"-> DELETE SHADOWS ID {{{FIXED_GUID}}}\r\n",
                "no 'Deleting shadow copy' line",
            ),
            (
                (
                    f"-> DELETE SHADOWS ID {{{FIXED_GUID}}}\r\n"
                    "Deleting shadow copy {AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}...\r\n"
                    "1 shadow copy deleted.\r\n"
                ),
                "GUID mismatch",
            ),
            (
                "Deleting shadow copy {not-a-guid}...\r\n1 shadow copy deleted.\r\n",
                "malformed GUID",
            ),
            (
                (
                    f"Deleting shadow copy {{{FIXED_GUID + '-EXTRA'}}}...\r\n"
                    "1 shadow copy deleted.\r\n"
                ),
                "malformed GUID",
            ),
            (
                f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n0 shadow copies deleted.\r\n",
                "expected deletion count 1, got '0'",
            ),
            (
                f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n2 shadow copies deleted.\r\n",
                "expected deletion count 1, got '2'",
            ),
            (
                f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n",
                "no deletion count line",
            ),
            (
                (
                    f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n"
                    f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n"
                    "1 shadow copy deleted.\r\n"
                ),
                "2 'Deleting shadow copy' lines",
            ),
            (
                (
                    f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n"
                    "1 shadow copy deleted.\r\n"
                    "1 shadow copy deleted.\r\n"
                ),
                "2 deletion count lines",
            ),
        ],
    )
    def test_raises_on_invalid_transcript(self, stdout, match):
        with pytest.raises(ValueError, match=match):
            parse_diskshadow_cleanup_transcript(stdout, FIXED_GUID)


# ---------------------------------------------------------------------------
# parse_drive_letters / select_drive_letter
# ---------------------------------------------------------------------------


class TestParseDriveLetters:
    def test_standard_output(self):
        assert parse_drive_letters("C:\\\r\nD:\\\r\nZ:\\\r\n") == {"C:", "D:", "Z:"}

    def test_empty_and_non_drive_lines_ignored(self):
        assert parse_drive_letters("") == set()
        result = parse_drive_letters("C:\\\r\nsome random text\r\n")
        assert result == {"C:"}
        assert "C:" in parse_drive_letters("c:\\\r\n")


class TestSelectDriveLetter:
    def test_z_when_empty(self):
        assert select_drive_letter(set()) == "Z"

    def test_skips_occupied_letters(self):
        assert select_drive_letter({"Z:"}) == "Y"
        assert select_drive_letter({"Z:", "Y:", "X:"}) == "W"
        assert select_drive_letter({"z:", "y:"}) == "X"

    def test_never_selects_c(self):
        occupied = {f"{chr(c)}:" for c in range(ord("D"), ord("Z") + 1)}
        assert select_drive_letter(occupied) is None


# ---------------------------------------------------------------------------
# Script builders
# ---------------------------------------------------------------------------


class TestScriptBuilders:
    def test_create_script_invariants(self):
        alias = "nxcshadowabcd1234"
        cab = r"C:\Windows\Temp\nxc-x\shadow.cab"
        content = build_create_script(alias, cab, "W")
        content.encode("ascii")  # raises if non-ASCII
        assert "\r\n" in content
        assert content.count("\n") == content.count("\r\n")
        assert alias in content
        assert f"%{alias}%" in content
        assert "expose" in content.lower()
        assert "W:" in content
        assert "set metadata" in content.lower()
        assert "persistent nowriters" in content.lower()
        last = [ln for ln in content.splitlines() if ln.strip()][-1]
        assert last.strip().lower() == "exit"

    def test_cleanup_script_safety(self):
        content = build_cleanup_script("Z", FIXED_GUID)
        content.encode("ascii")
        assert "\r\n" in content
        assert FIXED_GUID in content
        assert "Z:" in content
        assert "all" not in content.lower()
        lines = [ln.strip().lower() for ln in content.splitlines() if ln.strip()]
        unexpose_idx = next(i for i, ln in enumerate(lines) if "unexpose" in ln)
        delete_idx = next(i for i, ln in enumerate(lines) if "delete" in ln)
        assert unexpose_idx < delete_idx
        assert lines[-1] == "exit"

    def test_delete_only_script(self):
        content = build_delete_only_script(FIXED_GUID)
        content.encode("ascii")
        assert "\r\n" in content
        assert content.count("\n") == content.count("\r\n")
        assert FIXED_GUID in content
        assert "unexpose" not in content.lower()
        assert "all" not in content.lower()


# ---------------------------------------------------------------------------
# _run_cmd
# ---------------------------------------------------------------------------


class TestRunCmd:
    def test_valid_returns_stdout_stderr_rc(self):
        conn = _make_run_cmd_conn(stdout="hello", stderr="warn", exitcode=5)
        out, err, rc = _run_cmd(conn, "whoami /priv")
        assert (out, err, rc) == ("hello", "warn", 5)

    def test_had_errors_raises(self):
        conn = _make_run_cmd_conn(had_errors=True)
        with pytest.raises(RuntimeError, match="PowerShell transport error"):
            _run_cmd(conn, "whoami /priv")

    def test_empty_output_raises(self):
        for raw in ("", "   \n  "):
            conn = MagicMock()
            conn.execute_ps.return_value = (raw, MagicMock(), False)
            with pytest.raises(RuntimeError, match="empty output"):
                _run_cmd(conn, "cmd")

    def test_malformed_json_raises(self):
        conn = MagicMock()
        conn.execute_ps.return_value = ("not json {{", MagicMock(), False)
        with pytest.raises(RuntimeError, match="could not parse result JSON"):
            _run_cmd(conn, "cmd")

    def test_json_array_raises(self):
        conn = MagicMock()
        conn.execute_ps.return_value = (
            '[{"Stdout":"","Stderr":"","ExitCode":0}]',
            MagicMock(),
            False,
        )
        with pytest.raises(RuntimeError, match="expected JSON object"):
            _run_cmd(conn, "cmd")

    def test_apostrophe_in_command_escaped(self):
        conn = _make_run_cmd_conn()
        _run_cmd(conn, "cmd with 'apostrophe' arg")
        ps_script = conn.execute_ps.call_args.args[0]
        assert "''apostrophe''" in ps_script

    def test_ps_wrapper_contains_required_constructs(self):
        conn = _make_run_cmd_conn()
        _run_cmd(conn, "whoami /priv")
        ps = conn.execute_ps.call_args.args[0]
        for token in (
            "ProcessStartInfo",
            "RedirectStandardOutput",
            "RedirectStandardError",
            "ReadToEndAsync",
            "WaitForExit",
            "ErrorActionPreference",
            "Stop",
            "ConvertTo-Json",
        ):
            assert token in ps

    @pytest.mark.parametrize(
        ("payload", "match"),
        [
            ({"Stderr": "", "ExitCode": 0}, "missing required key 'Stdout'"),
            ({"Stdout": "", "ExitCode": 0}, "missing required key 'Stderr'"),
            ({"Stdout": "", "Stderr": ""}, "missing required key 'ExitCode'"),
        ],
    )
    def test_missing_key_raises(self, payload, match):
        conn = MagicMock()
        conn.execute_ps.return_value = (json.dumps(payload), MagicMock(), False)
        with pytest.raises(RuntimeError, match=match):
            _run_cmd(conn, "cmd")

    @pytest.mark.parametrize(
        ("payload", "match"),
        [
            ({"Stdout": 42, "Stderr": "", "ExitCode": 0}, "Stdout must be a string"),
            ({"Stdout": "", "Stderr": None, "ExitCode": 0}, "Stderr must be a string"),
            (
                {"Stdout": "", "Stderr": "", "ExitCode": "0"},
                "ExitCode must be an integer",
            ),
            (
                {"Stdout": "", "Stderr": "", "ExitCode": True},
                "ExitCode must be an integer",
            ),
        ],
    )
    def test_wrong_type_raises(self, payload, match):
        conn = MagicMock()
        conn.execute_ps.return_value = (json.dumps(payload), MagicMock(), False)
        with pytest.raises(RuntimeError, match=match):
            _run_cmd(conn, "cmd")


# ---------------------------------------------------------------------------
# _run_cmd interaction
# ---------------------------------------------------------------------------


class TestRunCmdInteraction:
    def setup_method(self):
        self.ctx = make_context()
        self.module = NXCModule()

    def test_cleanup_exception_doesnt_prevent_rmdir(self):
        state = RunState(FIXED_RUN_ID)
        state.verified_shadow_guid = FIXED_GUID
        state.staging_dir_created = True
        conn = MagicMock()
        conn.copy.return_value = None

        def _side(c, cmd):
            if "diskshadow" in cmd.lower():
                raise RuntimeError("PS transport failed")
            return ("", "", 0)

        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_side) as mock_run:
            self.module._cleanup(self.ctx, make_connection(conn), state)
        rmdir_calls = [c for c in mock_run.call_args_list if "rmdir" in c.args[1]]
        assert len(rmdir_calls) == 1


# ---------------------------------------------------------------------------
# parse_remote_file_size
# ---------------------------------------------------------------------------


class TestParseRemoteFileSize:
    def test_valid_and_whitespace_accepted(self):
        assert parse_remote_file_size("1234567\r\n", "", 0) == 1234567
        assert parse_remote_file_size("  9876  \r\n", "", 0) == 9876

    @pytest.mark.parametrize(
        ("stdout", "stderr", "rc", "match"),
        [
            ("0\r\n", "", 0, "empty"),
            ("-5\r\n", "", 0, "no numeric"),
            ("not a number\r\n", "", 0, "no numeric"),
            ("100\r\n200\r\n", "", 0, "multiple"),
            ("", "", 0, "no output"),
            ("1234567\r\n", "", 1, "rc=1"),
            ("1234567\r\n", "error\r\n", 0, "stderr"),
        ],
    )
    def test_invalid_raises(self, stdout, stderr, rc, match):
        with pytest.raises(ValueError, match=match):
            parse_remote_file_size(stdout, stderr, rc)


# ---------------------------------------------------------------------------
# Module phases: token info, staging, NTDS path, drive letter, verify exposure
# ---------------------------------------------------------------------------


class TestModulePhases:
    def setup_method(self):
        self.module = NXCModule()
        self.ctx = make_context()
        self.state = RunState(FIXED_RUN_ID)

    # SeBackupPrivilege
    def test_sebackupprivilege_present_logs_success(self):
        priv_out = '"SeBackupPrivilege","Back up files","Enabled"\r\n'
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            return_value=(priv_out, "", 0),
        ):
            self.module._phase_token_info(self.ctx, make_conn())
        success_text = " ".join(str(c) for c in self.ctx.log.success.call_args_list)
        assert "SeBackupPrivilege confirmed" in success_text

    def test_sebackupprivilege_absent_aborts(self):
        priv_out = '"SeRestorePrivilege","Restore files","Enabled"\r\n'
        with (
            patch("nxc.modules.ntds_shadow._run_cmd", return_value=(priv_out, "", 0)),
            pytest.raises(_ModuleAbort, match="SeBackupPrivilege"),
        ):
            self.module._phase_token_info(self.ctx, make_conn())
        fail_text = " ".join(str(c) for c in self.ctx.log.fail.call_args_list)
        assert "SeBackupPrivilege" in fail_text

    # NTDS path check
    def test_ntds_path_ok(self):
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            return_value=("Directory of C:\\Windows\\NTDS\r\n", "", 0),
        ):
            self.module._phase_check_ntds_path(self.ctx, make_conn())

    def test_ntds_path_aborts_on_failure(self):
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                return_value=("File Not Found", "", 1),
            ),
            pytest.raises(_ModuleAbort, match=r"ntds\.dit not accessible"),
        ):
            self.module._phase_check_ntds_path(self.ctx, make_conn())

    # Staging
    def test_staging_succeeds_sets_flag(self):
        with patch("nxc.modules.ntds_shadow._run_cmd", return_value=("", "", 0)):
            self.module._phase_staging(self.ctx, make_conn(), self.state)
        assert self.state.staging_dir_created is True

    def test_staging_aborts_when_dir_already_exists(self):
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                return_value=("", "A subdirectory or file already exists.", 1),
            ),
            pytest.raises(_ModuleAbort, match="mkdir failed"),
        ):
            self.module._phase_staging(self.ctx, make_conn(), self.state)
        assert self.state.staging_dir_created is False

    # Drive letter
    def test_drive_letter_selects_z(self):
        conn = make_conn(ps_responses=[("C:\\\r\n", MagicMock(), False)])
        self.module._phase_drive_letter(self.ctx, conn, self.state)
        assert self.state.drive_letter == "Z"

    def test_drive_letter_skips_occupied(self):
        conn = make_conn(
            ps_responses=[("C:\\\r\nZ:\\\r\nY:\\\r\n", MagicMock(), False)]
        )
        self.module._phase_drive_letter(self.ctx, conn, self.state)
        assert self.state.drive_letter == "X"

    def test_drive_letter_aborts_when_none_available(self):
        all_occupied = (
            "\r\n".join(f"{chr(code)}:\\" for code in range(ord("D"), ord("Z") + 1))
            + "\r\n"
        )
        conn = make_conn(ps_responses=[(all_occupied, MagicMock(), False)])
        with pytest.raises(_ModuleAbort, match=r"No available drive letter"):
            self.module._phase_drive_letter(self.ctx, conn, self.state)

    # Verify exposure
    def test_verify_exposure_succeeds_on_rc_zero(self):
        self.state.drive_letter = "Z"
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            return_value=("Volume in drive Z\r\n ntds.dit\r\n", "", 0),
        ):
            self.module._phase_verify_exposure(self.ctx, make_conn(), self.state)

    def test_verify_exposure_aborts_on_failure(self):
        self.state.drive_letter = "Z"
        for retval in [("File Not Found", "", 1), ("", "access denied", 0)]:
            with (
                patch("nxc.modules.ntds_shadow._run_cmd", return_value=retval),
                pytest.raises(_ModuleAbort, match=r"ntds.dit not visible"),
            ):
                self.module._phase_verify_exposure(self.ctx, make_conn(), self.state)


# ---------------------------------------------------------------------------
# DiskShadow snapshot creation phase
# ---------------------------------------------------------------------------


class TestDiskshadowCreatePhase:
    _VALID_STDOUT = (
        f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n"
        "The shadow copy was successfully exposed as Z:\\.\r\n"
    )

    def setup_method(self):
        self.module = NXCModule()
        self.ctx = make_context()
        self.state = RunState(FIXED_RUN_ID)
        self.state.drive_letter = "Z"

    def test_full_success_sets_guid_and_flags(self):
        with patch(
            "nxc.modules.ntds_shadow._run_cmd", return_value=(self._VALID_STDOUT, "", 0)
        ):
            self.module._phase_diskshadow_create(self.ctx, make_conn(), self.state)
        assert self.state.verified_shadow_guid == FIXED_GUID
        assert self.state.expose_reported is True

    @pytest.mark.parametrize(
        ("stdout", "stderr", "rc", "match"),
        [
            (_VALID_STDOUT, "", 1, "rc=1"),
            (_VALID_STDOUT, "some error", 0, "non-empty stderr"),
            (
                (
                    f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n"
                    "Error: some subsequent failure\r\n"
                ),
                "",
                0,
                "failure indicator",
            ),
            (
                f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n",
                "",
                0,
                "expose confirmation",
            ),
            (
                (
                    f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n"
                    "The shadow copy was successfully exposed as Y:\\.\r\n"
                ),
                "",
                0,
                "expose confirmation",
            ),
        ],
    )
    def test_ownership_set_then_phase_aborts(self, stdout, stderr, rc, match):
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd", return_value=(stdout, stderr, rc)
            ),
            pytest.raises(_ModuleAbort, match=match),
        ):
            self.module._phase_diskshadow_create(self.ctx, make_conn(), self.state)
        assert self.state.verified_shadow_guid == FIXED_GUID

    def test_transport_failure_sets_no_ownership(self):
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                side_effect=RuntimeError("transport error"),
            ),
            pytest.raises(_ModuleAbort, match="transport failed"),
        ):
            self.module._phase_diskshadow_create(self.ctx, make_conn(), self.state)
        assert self.state.verified_shadow_guid is None

    def test_duplicate_alias_sets_no_ownership(self):
        stdout = (
            f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n"
            f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n"
        )
        with (
            patch("nxc.modules.ntds_shadow._run_cmd", return_value=(stdout, "", 0)),
            pytest.raises(_ModuleAbort, match="ambiguous"),
        ):
            self.module._phase_diskshadow_create(self.ctx, make_conn(), self.state)
        assert self.state.verified_shadow_guid is None

    def test_expose_failure_triggers_cleanup_with_correct_script(self):
        """Snapshot ownership is established then NTDS access fails → cleanup runs
        with the exact verified GUID and never uses delete shadows all.
        """
        staging_dir = f"C:\\Windows\\Temp\\nxc-{FIXED_RUN_ID}"
        create_script_path = f"{staging_dir}\\ds-create.txt"
        cleanup_script_path = f"{staging_dir}\\ds-cleanup.txt"

        cleanup_stdout = (
            f"-> DELETE SHADOWS ID {{{FIXED_GUID}}}\r\n"
            f"Deleting shadow copy {{{FIXED_GUID}}}...\r\n"
            "1 shadow copy deleted.\r\n"
        )
        conn = MagicMock()
        conn.copy.return_value = None
        conn.execute_ps.side_effect = lambda ps: ("C:\\\r\n", MagicMock(), False)

        run_cmd_calls = []
        copy_payloads = []

        def _copy_side(local, remote):
            with open(local, "rb") as fh:
                copy_payloads.append((remote, fh.read().decode("ascii")))

        conn.copy.side_effect = _copy_side

        def _run_cmd_side(c, cmd):
            run_cmd_calls.append(cmd)
            cmd_l = cmd.lower()
            if "whoami /priv" in cmd_l:
                return ('"SeBackupPrivilege","Back up files","Enabled"\r\n', "", 0)
            if "systemroot" in cmd_l:
                return ("", "", 0)
            if cmd_l.startswith("mkdir"):
                return ("", "", 0)
            if "diskshadow" in cmd_l and "ds-create" in cmd_l:
                return (self._VALID_STDOUT, "", 0)
            if "ntds.dit" in cmd_l:
                return ("File Not Found", "", 1)
            if "diskshadow" in cmd_l and "ds-cleanup" in cmd_l:
                return (cleanup_stdout, "", 0)
            if "rmdir" in cmd_l:
                return ("", "", 0)
            return ("", "", 1)

        with (
            patch("secrets.token_hex", return_value=FIXED_RUN_ID),
            patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_run_cmd_side),
        ):
            ctx = make_context()
            NXCModule().on_login(ctx, make_connection(conn))

        # snapshot GUID logged after creation
        debug_msgs = [str(c) for c in ctx.log.debug.call_args_list]
        assert any(
            "Snapshot ownership established" in s and FIXED_GUID in s
            for s in debug_msgs
        )

        # abort reason logged
        fail_msgs = [str(c) for c in ctx.log.fail.call_args_list]
        assert any("ntds.dit not visible" in s for s in fail_msgs)

        # exactly two DiskShadow calls: create + cleanup
        ds_cmds = [cmd for cmd in run_cmd_calls if "diskshadow" in cmd.lower()]
        assert len(ds_cmds) == 2
        assert ds_cmds[0] == f'diskshadow.exe /s "{create_script_path}"'
        assert ds_cmds[1] == f'diskshadow.exe /s "{cleanup_script_path}"'

        # cleanup script targets the verified GUID, no "all"
        assert len(copy_payloads) == 2
        cleanup_remote, cleanup_content = copy_payloads[1]
        assert cleanup_remote == cleanup_script_path
        cleanup_lower = cleanup_content.lower()
        assert "unexpose z:" in cleanup_lower
        assert FIXED_GUID.lower() in cleanup_lower
        assert "delete shadows all" not in cleanup_lower

        # staging directory removed
        assert any("rmdir" in cmd for cmd in run_cmd_calls)


# ---------------------------------------------------------------------------
# Cleanup safety behaviours
# ---------------------------------------------------------------------------


class TestCleanupSafety:
    def _make_state(self, **kwargs):
        state = RunState(FIXED_RUN_ID)
        for k, v in kwargs.items():
            setattr(state, k, v)
        return state

    def test_no_guid_logs_warning_no_copy(self):
        state = self._make_state(diskshadow_invoked=True, staging_dir_created=False)
        conn = MagicMock()
        ctx = make_context()
        NXCModule()._cleanup(ctx, make_connection(conn), state)
        conn.copy.assert_not_called()
        fail_calls = [str(c) for c in ctx.log.fail.call_args_list]
        assert any("no snapshot GUID was identified" in s for s in fail_calls)

    def test_uses_delete_only_when_not_exposed(self):
        state = self._make_state(
            verified_shadow_guid=FIXED_GUID,
            diskshadow_invoked=True,
            staging_dir_created=False,
        )
        conn = MagicMock()
        conn.copy.return_value = None
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                return_value=(_valid_cleanup_stdout(), "", 0),
            ),
            patch("nxc.modules.ntds_shadow.build_delete_only_script") as mock_del,
            patch("nxc.modules.ntds_shadow.build_cleanup_script") as mock_full,
        ):
            mock_del.return_value = (
                f"set verbose on\r\ndelete shadows id {{{FIXED_GUID}}}\r\nexit\r\n"
            )
            NXCModule()._cleanup(make_context(), make_connection(conn), state)
        mock_del.assert_called_once_with(FIXED_GUID)
        mock_full.assert_not_called()

    def test_uses_full_script_when_exposed(self):
        state = self._make_state(
            verified_shadow_guid=FIXED_GUID,
            drive_letter="Z",
            staging_dir_created=False,
            expose_reported=True,
        )
        conn = MagicMock()
        conn.copy.return_value = None
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                side_effect=[
                    (_valid_cleanup_stdout(), "", 0),
                    ("", "", 1),
                ],
            ),
            patch("nxc.modules.ntds_shadow.build_cleanup_script") as mock_full,
            patch("nxc.modules.ntds_shadow.build_delete_only_script") as mock_del,
        ):
            mock_full.return_value = (
                f"set verbose on\r\nunexpose Z:\r\n"
                f"delete shadows id {{{FIXED_GUID}}}\r\nexit\r\n"
            )
            NXCModule()._cleanup(make_context(), make_connection(conn), state)
        mock_full.assert_called_once_with("Z", FIXED_GUID)
        mock_del.assert_not_called()

    def test_transcript_confirmed_logs_success(self):
        state = self._make_state(
            verified_shadow_guid=FIXED_GUID,
            diskshadow_invoked=True,
            staging_dir_created=False,
        )
        conn = MagicMock()
        conn.copy.return_value = None
        ctx = make_context()
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            return_value=(_valid_cleanup_stdout(), "", 0),
        ):
            NXCModule()._cleanup(ctx, make_connection(conn), state)
        debug_calls = [str(c) for c in ctx.log.debug.call_args_list]
        assert any("transcript confirmed" in s for s in debug_calls)
        success_calls = [str(c) for c in ctx.log.success.call_args_list]
        assert any(
            "Remote artifacts and shadow copy removed" in s for s in success_calls
        )

    @pytest.mark.parametrize(
        ("rc", "stderr", "stdout"),
        [
            (1, "", ""),
            (0, "access denied", ""),
            (0, "", "Shadow copy deleted but wrong format."),
            (0, "", RuntimeError("transport error")),  # RuntimeError triggers residual
        ],
    )
    def test_cleanup_failure_logs_residual(self, rc, stderr, stdout):
        state = self._make_state(
            verified_shadow_guid=FIXED_GUID,
            diskshadow_invoked=True,
            staging_dir_created=False,
        )
        conn = MagicMock()
        conn.copy.return_value = None
        ctx = make_context()
        if isinstance(stdout, Exception):
            se = stdout
            with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=se):
                NXCModule()._cleanup(ctx, make_connection(conn), state)
        else:
            with patch(
                "nxc.modules.ntds_shadow._run_cmd", return_value=(stdout, stderr, rc)
            ):
                NXCModule()._cleanup(ctx, make_connection(conn), state)
        fail_calls = [str(c) for c in ctx.log.fail.call_args_list]
        assert any("may remain" in s for s in fail_calls)

    def test_diskshadow_exception_doesnt_stop_rmdir(self):
        state = self._make_state(
            verified_shadow_guid=FIXED_GUID, staging_dir_created=True
        )
        conn = MagicMock()
        conn.copy.side_effect = Exception("upload failed")
        with patch(
            "nxc.modules.ntds_shadow._run_cmd", return_value=("", "", 0)
        ) as mock_run:
            NXCModule()._cleanup(make_context(), make_connection(conn), state)
        rmdir_calls = [c for c in mock_run.call_args_list if "rmdir" in c.args[1]]
        assert len(rmdir_calls) == 1

    def test_pre_mutation_failure_emits_no_cleanup_success(self):
        state = RunState(FIXED_RUN_ID)
        ctx = make_context()
        NXCModule()._cleanup(ctx, make_connection(make_conn()), state)
        success_text = " ".join(str(c) for c in ctx.log.success.call_args_list)
        assert "Remote artifacts" not in success_text


# ---------------------------------------------------------------------------
# Remote artifact cleanup ordering and isolation
# ---------------------------------------------------------------------------


class TestArtifactCleanup:
    def setup_method(self):
        self.module = NXCModule()
        self.ctx = make_context()
        self.state = RunState(FIXED_RUN_ID)
        self.state.drive_letter = "Z"
        self.state.verified_shadow_guid = FIXED_GUID
        self.state.staging_dir_created = True
        self.state.expose_reported = True

    def test_partial_artifacts_deleted_even_when_copy_flag_false(self):
        self.state.ntds_copy_attempted = True
        self.state.ntds_copied = False
        self.state.system_save_attempted = True
        self.state.system_saved = False
        issued = []
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            side_effect=lambda c, cmd: issued.append(cmd) or ("", "", 0),
        ):
            self.module._cleanup_remote_artifacts(self.ctx, make_conn(), self.state)
        del_ntds = [c for c in issued if "del " in c.lower() and "ntds.dit" in c]
        del_sys = [c for c in issued if "del " in c.lower() and "SYSTEM.hive" in c]
        assert del_ntds
        assert not any("*" in c for c in del_ntds)
        assert del_sys

    def test_ntds_deletion_failure_doesnt_block_system_deletion(self):
        self.state.ntds_copy_attempted = True
        self.state.system_save_attempted = True
        system_del_issued = []

        def _side(c, cmd):
            if "ntds.dit" in cmd and cmd.lower().startswith("del "):
                raise RuntimeError("pipe closed")
            if "SYSTEM.hive" in cmd and cmd.lower().startswith("del "):
                system_del_issued.append(cmd)
            return ("", "", 0)

        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_side):
            self.module._cleanup_remote_artifacts(self.ctx, make_conn(), self.state)
        assert system_del_issued

    def test_both_artifacts_precede_diskshadow_cleanup(self):
        self.state.ntds_copy_attempted = True
        self.state.system_save_attempted = True
        sequence = []
        conn = MagicMock()
        conn.copy.return_value = None

        def _side(c, cmd):
            if "ntds.dit" in cmd and cmd.lower().startswith("del /f /q"):
                sequence.append("del_ntds")
            elif "SYSTEM.hive" in cmd and cmd.lower().startswith("del /f /q"):
                sequence.append("del_system")
            elif "diskshadow" in cmd.lower():
                sequence.append("diskshadow")
                return (_valid_cleanup_stdout(), "", 0)
            return ("", "", 0)

        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_side):
            self.module._cleanup(self.ctx, make_connection(conn), self.state)

        ds_pos = sequence.index("diskshadow")
        assert sequence.index("del_ntds") < ds_pos
        assert sequence.index("del_system") < ds_pos

    def test_no_acquisition_no_artifact_del(self):
        self.state.ntds_copy_attempted = False
        self.state.system_save_attempted = False
        issued = []
        conn = MagicMock()
        conn.copy.return_value = None

        def _side(c, cmd):
            issued.append(cmd)
            if "diskshadow" in cmd.lower():
                return (_valid_cleanup_stdout(), "", 0)
            return ("", "", 0)

        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_side):
            self.module._cleanup(self.ctx, make_connection(conn), self.state)
        assert not [c for c in issued if c.lower().startswith("del ")]

    def test_staging_rmdir_always_runs(self):
        self.state.ntds_copy_attempted = True
        self.state.staging_dir_created = True
        rmdir_issued = []

        def _side(c, cmd):
            if "ntds.dit" in cmd and cmd.lower().startswith("del "):
                raise RuntimeError("pipe closed")
            if "rmdir" in cmd.lower():
                rmdir_issued.append(cmd)
            return ("", "", 0)

        conn = MagicMock()
        conn.copy.return_value = None
        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_side):
            self.module._cleanup(self.ctx, make_connection(conn), self.state)
        assert rmdir_issued


# ---------------------------------------------------------------------------
# NTDS copy and SYSTEM save phases
# ---------------------------------------------------------------------------


class TestNtdsCopyAndSystemSave:
    def setup_method(self):
        self.module = NXCModule()
        self.ctx = make_context()

    def _ntds_state(self):
        state = RunState(FIXED_RUN_ID)
        state.drive_letter = "Z"
        state.verified_shadow_guid = FIXED_GUID
        state.expose_reported = True
        return state

    def _system_state(self):
        state = RunState(FIXED_RUN_ID)
        state.ntds_copied = True
        state.remote_ntds_size = 12345678
        return state

    # NTDS copy success variants
    def test_ntds_rc1_sets_copied_and_size(self):
        state = self._ntds_state()
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            side_effect=[("", "", 1), ("9876543\r\n", "", 0)],
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)
        assert state.ntds_copied is True
        assert state.remote_ntds_size == 9876543

    def test_ntds_rc7_succeeds(self):
        state = self._ntds_state()
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            side_effect=[("", "", 7), ("100\r\n", "", 0)],
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)
        assert state.ntds_copied is True

    def test_ntds_rc0_no_artifact_aborts(self):
        state = self._ntds_state()
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                side_effect=[("", "", 0), ("", "", 0)],
            ),
            pytest.raises(_ModuleAbort, match="size"),
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)
        assert state.ntds_copied is False

    def test_ntds_rc8_aborts_before_size_check(self):
        state = self._ntds_state()
        with (
            patch("nxc.modules.ntds_shadow._run_cmd", return_value=("", "", 8)),
            pytest.raises(_ModuleAbort, match="rc=8"),
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)
        assert state.ntds_copy_attempted is True
        assert state.ntds_copied is False
        assert state.remote_ntds_size is None

    def test_ntds_stderr_aborts(self):
        state = self._ntds_state()
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                return_value=("", "Access is denied.\r\n", 1),
            ),
            pytest.raises(_ModuleAbort, match="stderr"),
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)

    def test_ntds_transport_failure_aborts(self):
        state = self._ntds_state()
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                side_effect=RuntimeError("pipe closed"),
            ),
            pytest.raises(_ModuleAbort, match="transport failed"),
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)
        assert state.ntds_copy_attempted is True
        assert state.ntds_copied is False

    def test_ntds_ownership_preserved_on_failure(self):
        state = self._ntds_state()
        with (
            patch("nxc.modules.ntds_shadow._run_cmd", return_value=("", "", 8)),
            pytest.raises(_ModuleAbort),
        ):
            self.module._phase_ntds_copy(self.ctx, make_conn(), state)
        assert state.verified_shadow_guid == FIXED_GUID

    # SYSTEM save
    def test_system_rc0_sets_saved_and_size(self):
        state = self._system_state()
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            side_effect=[("", "", 0), ("15728640\r\n", "", 0)],
        ):
            self.module._phase_system_save(self.ctx, make_conn(), state)
        assert state.system_saved is True
        assert state.remote_system_size == 15728640

    @pytest.mark.parametrize(
        ("retval", "match"),
        [
            (("", "", 5), "rc=5"),
            (("", "Access denied.\r\n", 0), "stderr"),
        ],
    )
    def test_system_aborts(self, retval, match):
        state = self._system_state()
        with (
            patch("nxc.modules.ntds_shadow._run_cmd", return_value=retval),
            pytest.raises(_ModuleAbort, match=match),
        ):
            self.module._phase_system_save(self.ctx, make_conn(), state)
        assert state.system_saved is False

    def test_system_zero_size_aborts(self):
        state = self._system_state()
        with (
            patch(
                "nxc.modules.ntds_shadow._run_cmd",
                side_effect=[("", "", 0), ("0\r\n", "", 0)],
            ),
            pytest.raises(_ModuleAbort, match="size"),
        ):
            self.module._phase_system_save(self.ctx, make_conn(), state)

    def test_system_failure_preserves_ntds_state(self):
        state = self._system_state()
        with (
            patch("nxc.modules.ntds_shadow._run_cmd", return_value=("", "", 5)),
            pytest.raises(_ModuleAbort, match="rc=5"),
        ):
            self.module._phase_system_save(self.ctx, make_conn(), state)
        assert state.ntds_copied is True
        assert state.remote_ntds_size == 12345678
        assert state.system_saved is False


# ---------------------------------------------------------------------------
# Local directory preparation
# ---------------------------------------------------------------------------


class TestLocalPathConstruction:
    def setup_method(self):
        self.module = NXCModule()
        self.ctx = make_context()

    def _ready_state(self):
        state = RunState(FIXED_RUN_ID)
        state.ntds_copied = True
        state.system_saved = True
        state.remote_ntds_size = 1024
        state.remote_system_size = 2048
        return state

    def _conn(self, tmp_path):
        conn = MagicMock()
        conn.output_file_template = str(tmp_path / "nxc_192.168.1.1_{output_folder}")
        return conn

    def test_paths_contain_run_id_and_correct_filenames(self, tmp_path):
        state = self._ready_state()
        self.module._phase_prepare_local_dir(self.ctx, self._conn(tmp_path), state)
        assert FIXED_RUN_ID in state.local_evidence_dir
        assert "ntds" in state.local_evidence_dir
        assert state.local_ntds_path.endswith("ntds.dit")
        assert state.local_system_path.endswith("SYSTEM.hive")

    def test_collision_aborts(self, tmp_path):
        state = self._ready_state()
        connection = self._conn(tmp_path)
        output_base = connection.output_file_template.format(output_folder="ntds")
        parent = os.path.dirname(output_base)
        os.makedirs(parent, exist_ok=True)
        collision = os.path.join(
            parent, f"{os.path.basename(output_base)}_diskshadow_{FIXED_RUN_ID}"
        )
        os.mkdir(collision)
        with pytest.raises(_ModuleAbort, match="already exists"):
            self.module._phase_prepare_local_dir(self.ctx, connection, state)

    def test_parent_created_if_missing(self, tmp_path):
        state = self._ready_state()
        nested = tmp_path / "a" / "b" / "c"
        connection = MagicMock()
        connection.output_file_template = str(nested / "nxc_{output_folder}")
        self.module._phase_prepare_local_dir(self.ctx, connection, state)
        assert os.path.isdir(state.local_evidence_dir)

    def test_mode_is_0700(self, tmp_path):
        state = self._ready_state()
        self.module._phase_prepare_local_dir(self.ctx, self._conn(tmp_path), state)
        mode = oct(os.stat(state.local_evidence_dir).st_mode & 0o777)
        assert mode == oct(0o700)

    @pytest.mark.parametrize(
        ("ntds_copied", "system_saved", "ntds_size"),
        [
            (False, True, 1024),
            (True, False, 1024),
            (True, True, None),
        ],
    )
    def test_preconditions_abort(self, ntds_copied, system_saved, ntds_size, tmp_path):
        state = RunState(FIXED_RUN_ID)
        state.ntds_copied = ntds_copied
        state.system_saved = system_saved
        state.remote_ntds_size = ntds_size
        state.remote_system_size = 2048
        connection = MagicMock()
        connection.output_file_template = str(tmp_path / "nxc_{output_folder}")
        with pytest.raises(_ModuleAbort, match="precondition"):
            self.module._phase_prepare_local_dir(self.ctx, connection, state)


# ---------------------------------------------------------------------------
# Download phases (NTDS.dit and SYSTEM.hive)
# ---------------------------------------------------------------------------


def _make_download_state(tmp_path):
    state = RunState(FIXED_RUN_ID)
    state.ntds_copied = True
    state.system_saved = True
    state.remote_ntds_size = 1024
    state.remote_system_size = 2048
    evidence_dir = tmp_path / f"ev_{FIXED_RUN_ID}"
    evidence_dir.mkdir()
    state.local_evidence_dir = str(evidence_dir)
    state.local_ntds_path = str(evidence_dir / "ntds.dit")
    state.local_system_path = str(evidence_dir / "SYSTEM.hive")
    return state


class TestDownloadPhases:
    def setup_method(self):
        self.module = NXCModule()
        self.ctx = make_context()

    @pytest.mark.parametrize(
        ("phase", "remote_attr", "local_attr"),
        [
            ("_phase_download_ntds", "remote_ntds_path", "local_ntds_path"),
            ("_phase_download_system", "remote_system_path", "local_system_path"),
        ],
    )
    def test_fetch_called_with_correct_paths(
        self, phase, remote_attr, local_attr, tmp_path
    ):
        state = _make_download_state(tmp_path)
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * state.remote_ntds_size)
        state.ntds_downloaded = True
        state.local_ntds_size = state.remote_ntds_size
        connection = MagicMock()
        connection.conn.fetch.return_value = None
        getattr(self.module, phase)(self.ctx, connection, state)
        connection.conn.fetch.assert_called_once_with(
            getattr(state, remote_attr), getattr(state, local_attr)
        )

    @pytest.mark.parametrize(
        ("phase", "downloaded_attr"),
        [
            ("_phase_download_ntds", "ntds_downloaded"),
            ("_phase_download_system", "system_downloaded"),
        ],
    )
    def test_fetch_exception_sets_downloaded_false(
        self, phase, downloaded_attr, tmp_path
    ):
        state = _make_download_state(tmp_path)
        if "system" in phase:
            with open(state.local_ntds_path, "wb") as f:
                f.write(b"x" * state.remote_ntds_size)
            state.ntds_downloaded = True
            state.local_ntds_size = state.remote_ntds_size
        connection = MagicMock()
        connection.conn.fetch.side_effect = RuntimeError("transport failed")
        with pytest.raises(_ModuleAbort, match="fetch failed"):
            getattr(self.module, phase)(self.ctx, connection, state)
        assert getattr(state, downloaded_attr) is False

    @pytest.mark.parametrize(
        ("phase", "local_attr", "size"),
        [
            ("_phase_download_ntds", "local_ntds_path", 64),
            ("_phase_download_system", "local_system_path", 50),
        ],
    )
    def test_partial_file_retained_and_warned(self, phase, local_attr, size, tmp_path):
        state = _make_download_state(tmp_path)
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * state.remote_ntds_size)
        state.ntds_downloaded = True
        state.local_ntds_size = state.remote_ntds_size

        def _fetch(remote, local):
            with open(local, "wb") as f:
                f.write(b"x" * size)
            raise RuntimeError("connection lost mid-transfer")

        connection = MagicMock()
        connection.conn.fetch.side_effect = _fetch
        with pytest.raises(_ModuleAbort):
            getattr(self.module, phase)(self.ctx, connection, state)
        assert os.path.exists(getattr(state, local_attr))
        fail_text = " ".join(str(c) for c in self.ctx.log.fail.call_args_list)
        assert "partial" in fail_text.lower() or "unverified" in fail_text.lower()

    def test_verify_missing_ntds_raises(self, tmp_path):
        state = _make_download_state(tmp_path)
        connection = MagicMock()
        connection.conn.fetch.return_value = None
        self.module._phase_download_ntds(self.ctx, connection, state)
        with pytest.raises(_ModuleAbort, match="missing"):
            self.module._phase_verify_local_artifacts(self.ctx, state)

    def test_verify_zero_byte_ntds_raises(self, tmp_path):
        state = _make_download_state(tmp_path)
        open(state.local_ntds_path, "wb").close()
        with pytest.raises(_ModuleAbort, match="empty"):
            self.module._phase_verify_local_artifacts(self.ctx, state)

    def test_verify_size_mismatch_raises_and_file_retained(self, tmp_path):
        state = _make_download_state(tmp_path)
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * 100)  # 100 != 1024
        with pytest.raises(_ModuleAbort, match="mismatch"):
            self.module._phase_verify_local_artifacts(self.ctx, state)
        assert os.path.exists(state.local_ntds_path)

    def test_verify_success_sets_flags_and_sizes(self, tmp_path):
        state = _make_download_state(tmp_path)
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * state.remote_ntds_size)
        with open(state.local_system_path, "wb") as f:
            f.write(b"y" * state.remote_system_size)
        self.module._phase_verify_local_artifacts(self.ctx, state)
        assert state.ntds_downloaded is True
        assert state.system_downloaded is True
        assert state.local_ntds_size == state.remote_ntds_size
        assert state.local_system_size == state.remote_system_size

    def test_system_failure_preserves_verified_ntds(self, tmp_path):
        state = _make_download_state(tmp_path)
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * state.remote_ntds_size)
        with open(state.local_system_path, "wb") as f:
            f.write(b"y" * 50)  # wrong size
        with pytest.raises(_ModuleAbort, match="mismatch"):
            self.module._phase_verify_local_artifacts(self.ctx, state)
        assert state.ntds_downloaded is True
        assert state.local_ntds_size == state.remote_ntds_size
        assert state.system_downloaded is False


# ---------------------------------------------------------------------------
# Download integration
# ---------------------------------------------------------------------------


class TestDownloadIntegration:
    def setup_method(self):
        self.ctx = make_context()

    def _staged_state(self):
        state = RunState(FIXED_RUN_ID)
        state.drive_letter = "Z"
        state.verified_shadow_guid = FIXED_GUID
        state.expose_reported = True
        state.ntds_copy_attempted = True
        state.ntds_copied = True
        state.remote_ntds_size = 1024
        state.system_save_attempted = True
        state.system_saved = True
        state.remote_system_size = 2048
        state.staging_dir_created = True
        return state

    def _noop_early(self, m):
        for name in (
            "_phase_token_info",
            "_phase_check_ntds_path",
            "_phase_staging",
            "_phase_drive_letter",
            "_phase_upload_create_script",
            "_phase_diskshadow_create",
            "_phase_verify_exposure",
            "_phase_ntds_copy",
            "_phase_system_save",
        ):
            setattr(m, name, MagicMock())

    def test_fetch_order_ntds_then_system(self, tmp_path):
        state = self._staged_state()
        conn = MagicMock()
        connection = MagicMock()
        connection.conn = conn
        connection.output_file_template = str(tmp_path / "nxc_{output_folder}")
        fetch_order = []

        def _fetch(remote, local):
            fetch_order.append(local)
            size = (
                state.remote_ntds_size
                if "ntds.dit" in local
                else state.remote_system_size
            )
            with open(local, "wb") as f:
                f.write(b"x" * size)

        conn.fetch.side_effect = _fetch
        m = NXCModule()
        self._noop_early(m)
        m._run(self.ctx, connection, state)
        assert conn.fetch.call_count == 2
        assert "ntds.dit" in fetch_order[0]
        assert "SYSTEM.hive" in fetch_order[1]

    def test_local_files_survive_cleanup(self, tmp_path):
        state = self._staged_state()
        evidence_dir = tmp_path / f"ev_{FIXED_RUN_ID}"
        evidence_dir.mkdir()
        state.local_evidence_dir = str(evidence_dir)
        state.local_ntds_path = str(evidence_dir / "ntds.dit")
        state.local_system_path = str(evidence_dir / "SYSTEM.hive")
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * state.remote_ntds_size)
        with open(state.local_system_path, "wb") as f:
            f.write(b"y" * state.remote_system_size)
        state.ntds_downloaded = True
        state.local_ntds_size = state.remote_ntds_size
        state.system_downloaded = True
        state.local_system_size = state.remote_system_size
        conn = MagicMock()
        conn.copy.return_value = None

        def _side(c, cmd):
            if "diskshadow" in cmd.lower() and "ds-cleanup" in cmd:
                return (_valid_cleanup_stdout(), "", 0)
            return ("", "", 0)

        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_side):
            NXCModule()._cleanup(self.ctx, make_connection(conn), state)
        assert os.path.exists(state.local_ntds_path)
        assert os.path.exists(state.local_system_path)

    def test_system_fetch_failure_cleanup_still_runs(self, tmp_path):
        state = self._staged_state()
        evidence_dir = tmp_path / f"ev_{FIXED_RUN_ID}"
        evidence_dir.mkdir()
        state.local_evidence_dir = str(evidence_dir)
        state.local_ntds_path = str(evidence_dir / "ntds.dit")
        state.local_system_path = str(evidence_dir / "SYSTEM.hive")
        with open(state.local_ntds_path, "wb") as f:
            f.write(b"x" * state.remote_ntds_size)
        state.ntds_downloaded = True
        state.local_ntds_size = state.remote_ntds_size
        del_issued = []

        def _run_side(c, cmd):
            if cmd.lower().startswith("del /f /q"):
                del_issued.append(cmd)
            if "diskshadow" in cmd.lower() and "ds-cleanup" in cmd:
                return (_valid_cleanup_stdout(), "", 0)
            return ("", "", 0)

        conn = MagicMock()
        conn.copy.return_value = None
        connection = MagicMock()
        connection.conn = conn
        connection.conn.fetch.side_effect = RuntimeError("refused")

        m = NXCModule()
        with pytest.raises(_ModuleAbort, match="fetch failed"):
            m._phase_download_system(self.ctx, connection, state)

        with patch("nxc.modules.ntds_shadow._run_cmd", side_effect=_run_side):
            m2 = NXCModule()
            m2._cleanup(self.ctx, make_connection(conn), state)

        assert os.path.exists(state.local_ntds_path)
        assert del_issued
        assert state.ntds_downloaded is True


# ---------------------------------------------------------------------------
# build_secretsdump_command + next-step gating
# ---------------------------------------------------------------------------


class TestDefaultActionUX:
    def setup_method(self):
        self.ctx = make_context()

    def _noop_phases(self, m):
        for name in (
            "_phase_token_info",
            "_phase_check_ntds_path",
            "_phase_staging",
            "_phase_drive_letter",
            "_phase_upload_create_script",
            "_phase_diskshadow_create",
            "_phase_verify_exposure",
            "_phase_ntds_copy",
            "_phase_system_save",
            "_phase_prepare_local_dir",
            "_phase_download_ntds",
            "_phase_download_system",
            "_phase_verify_local_artifacts",
        ):
            setattr(m, name, MagicMock())

    def _download_state(self):
        state = RunState(FIXED_RUN_ID)
        state.verified_shadow_guid = FIXED_GUID
        state.diskshadow_invoked = True
        state.staging_dir_created = False
        state.ntds_downloaded = True
        state.system_downloaded = True
        state.local_evidence_dir = "/tmp/ev"
        state.local_ntds_path = "/tmp/ev/ntds.dit"
        state.local_system_path = "/tmp/ev/SYSTEM.hive"
        state.local_ntds_size = 16777216
        state.local_system_size = 20692992
        return state

    def test_paths_logged_at_display_level_with_sizes(self):
        m = NXCModule()
        self._noop_phases(m)
        state = RunState(FIXED_RUN_ID)
        state.local_ntds_size = 12345678
        state.local_system_size = 87654321
        state.local_ntds_path = "/evidence/ntds.dit"
        state.local_system_path = "/evidence/SYSTEM.hive"
        m._run(self.ctx, make_connection(make_conn()), state)
        display_text = " ".join(str(c) for c in self.ctx.log.display.call_args_list)
        assert "/evidence/ntds.dit" in display_text
        assert "/evidence/SYSTEM.hive" in display_text
        assert "12345678" in display_text
        assert "87654321" in display_text

    def test_next_step_after_cleanup_success(self):
        state = self._download_state()
        conn = MagicMock()
        conn.copy.return_value = None
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            return_value=(_valid_cleanup_stdout(), "", 0),
        ):
            NXCModule()._cleanup(self.ctx, make_connection(conn), state)
        display_text = " ".join(str(c) for c in self.ctx.log.display.call_args_list)
        assert "impacket-secretsdump" in display_text
        assert "Next step" in display_text

    def test_next_step_absent_when_cleanup_fails(self):
        state = self._download_state()
        conn = MagicMock()
        conn.copy.return_value = None
        with patch("nxc.modules.ntds_shadow._run_cmd", return_value=("", "", 1)):
            NXCModule()._cleanup(self.ctx, make_connection(conn), state)
        display_text = " ".join(str(c) for c in self.ctx.log.display.call_args_list)
        assert "impacket-secretsdump" not in display_text

    def test_next_step_absent_when_verification_incomplete(self):
        state = self._download_state()
        state.ntds_downloaded = False
        conn = MagicMock()
        conn.copy.return_value = None
        with patch(
            "nxc.modules.ntds_shadow._run_cmd",
            return_value=(_valid_cleanup_stdout(), "", 0),
        ):
            NXCModule()._cleanup(self.ctx, make_connection(conn), state)
        display_text = " ".join(str(c) for c in self.ctx.log.display.call_args_list)
        assert "impacket-secretsdump" not in display_text

    def test_secretsdump_uses_impacket_name_not_script(self):
        result = build_secretsdump_command("/tmp/SYSTEM.hive", "/tmp/ntds.dit")
        assert "impacket-secretsdump" in result
        assert "secretsdump.py" not in result
        assert "-system" in result
        assert "-ntds" in result
        assert "LOCAL" in result

    def test_secretsdump_quotes_paths_with_spaces(self):
        import shlex as _shlex

        sys_path = "/tmp/my evidence/SYSTEM.hive"
        ntds_path = "/tmp/my evidence/ntds.dit"
        result = build_secretsdump_command(sys_path, ntds_path)
        assert _shlex.quote(sys_path) in result
        assert _shlex.quote(ntds_path) in result


# ---------------------------------------------------------------------------
# End-to-end on_login workflow
# ---------------------------------------------------------------------------


class TestOnLoginIntegration:
    """Complete successful on_login run with all 17 native-command calls mocked."""

    NTDS_SIZE = 100
    SYSTEM_SIZE = 200

    def _native_cmd_responses(self):
        create_stdout = (
            f"-> %nxcshadow{FIXED_RUN_ID}% = {{{FIXED_GUID}}}\r\n"
            "The shadow copy was successfully exposed as Z:\\.\r\n"
        )
        cleanup_stdout = (
            "-> UNEXPOSE Z:\r\n"
            f"Shadow copy ID {{{FIXED_GUID.lower()}}} is no longer exposed.\r\n"
            f"-> DELETE SHADOWS ID {{{FIXED_GUID}}}\r\n"
            f"Deleting shadow copy {{{FIXED_GUID.lower()}}}...\r\n"
            "1 shadow copy deleted.\r\n"
            "-> EXIT\r\n"
        )
        return [
            (
                '"SeBackupPrivilege","Back up files","Enabled"\r\n',
                "",
                0,
            ),  # 1 whoami /priv
            ("Directory of C:\\Windows\\NTDS\r\n ntds.dit\r\n", "", 0),  # 2 ntds path
            ("", "", 0),  # 3 mkdir
            (create_stdout, "", 0),  # 4 diskshadow create
            (
                "Directory of Z:\\Windows\\NTDS\r\n ntds.dit\r\n",
                "",
                0,
            ),  # 5 verify exposure
            ("", "", 1),  # 6 robocopy (rc=1)
            (f"{self.NTDS_SIZE}\r\n", "", 0),  # 7 ntds size
            ("", "", 0),  # 8 reg save SYSTEM
            (f"{self.SYSTEM_SIZE}\r\n", "", 0),  # 9 system size
            ("", "", 0),  # 10 del ntds.dit
            ("", "", 0),  # 11 if exist ntds.dit
            ("", "", 0),  # 12 del SYSTEM.hive
            ("", "", 0),  # 13 if exist SYSTEM.hive
            (cleanup_stdout, "", 0),  # 14 diskshadow cleanup
            ("", "", 0),  # 15 rmdir
            ("", "", 1),  # 16 dir Z:\ (gone)
            ("", "", 1),  # 17 dir staging (gone)
        ]

    def test_full_success_flow(self, tmp_path):
        call_log = []
        copy_payloads = []
        native_iter = iter(self._native_cmd_responses())

        def run_cmd_side(conn, cmd):
            call_log.append(("cmd", cmd))
            return next(native_iter)

        def fetch_side(remote, local):
            call_log.append(("fetch", local))
            size = self.NTDS_SIZE if "ntds.dit" in local else self.SYSTEM_SIZE
            with open(local, "wb") as fh:
                fh.write(b"\x00" * size)

        def copy_side(local, remote):
            with open(local, "rb") as fh:
                copy_payloads.append((remote, fh.read().decode("ascii")))

        conn = MagicMock()
        conn.execute_ps.side_effect = lambda ps: ("C:\\\r\n", MagicMock(), False)
        conn.fetch.side_effect = fetch_side
        conn.copy.side_effect = copy_side

        with (
            patch("secrets.token_hex", return_value=FIXED_RUN_ID),
            patch(
                "nxc.modules.ntds_shadow._run_cmd", side_effect=run_cmd_side
            ) as mock_run_cmd,
        ):
            ctx = make_context()
            connection = make_connection(conn)
            connection.output_file_template = str(tmp_path / "{output_folder}")
            NXCModule().on_login(ctx, connection)

        cmds = [c.args[1] for c in mock_run_cmd.call_args_list]
        assert len(cmds) == 17

        # Command sequence spot-checks
        assert "whoami" in cmds[0]
        assert "priv" in cmds[0]
        assert "ntds.dit" in cmds[1].lower()
        assert "mkdir" in cmds[2].lower()
        assert "diskshadow" in cmds[3].lower()
        assert "ntds.dit" in cmds[4].lower()
        assert "robocopy" in cmds[5].lower()
        assert "ntds.dit" in cmds[6].lower()
        assert "reg.exe save" in cmds[7]
        assert "HKLM" in cmds[7]
        assert "system.hive" in cmds[8].lower()
        assert "del /f /q" in cmds[9].lower()
        assert "ntds.dit" in cmds[9].lower()
        assert "del /f /q" in cmds[11].lower()
        assert "system.hive" in cmds[11].lower()
        assert "diskshadow" in cmds[13].lower()
        assert "rmdir" in cmds[14].lower()
        assert not any("vssadmin" in c.lower() for c in cmds)

        # Cleanup script targets the verified GUID, no "delete shadows all"
        expected_cleanup_path = RunState(FIXED_RUN_ID).cleanup_script
        cleanup_remote, cleanup_content = copy_payloads[1]
        assert cleanup_remote == expected_cleanup_path
        assert cmds[13] == f'diskshadow.exe /s "{expected_cleanup_path}"'
        cleanup_lower = cleanup_content.lower()
        assert "unexpose z:" in cleanup_lower
        assert FIXED_GUID.lower() in cleanup_lower
        assert "delete shadows all" not in cleanup_lower

        # Two fetches, NTDS first
        assert conn.fetch.call_count == 2
        ntds_local = conn.fetch.call_args_list[0].args[1]
        system_local = conn.fetch.call_args_list[1].args[1]
        assert "ntds.dit" in ntds_local
        assert "SYSTEM.hive" in system_local

        # Both fetches precede remote artifact deletion
        fetch_pos = [i for i, (k, _) in enumerate(call_log) if k == "fetch"]
        del_pos = [
            i
            for i, (k, a) in enumerate(call_log)
            if k == "cmd" and "del /f /q" in a.lower()
        ]
        assert max(fetch_pos) < min(del_pos)

        # Local file sizes
        assert os.path.getsize(ntds_local) == self.NTDS_SIZE
        assert os.path.getsize(system_local) == self.SYSTEM_SIZE

        # Success milestones
        success_str = " ".join(str(c) for c in ctx.log.success.call_args_list)
        assert "SeBackupPrivilege confirmed" in success_str
        assert "Snapshot created and NTDS accessible" in success_str
        assert "NTDS database and SYSTEM hive downloaded" in success_str
        assert "Remote artifacts and shadow copy removed" in success_str

        # Display output
        display_str = " ".join(str(c) for c in ctx.log.display.call_args_list)
        assert "ntds.dit" in display_str
        assert str(self.NTDS_SIZE) in display_str
        assert "Next step: impacket-secretsdump" in display_str

        # No failures
        assert not ctx.log.fail.called
