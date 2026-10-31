"""Tests for WinRM --ntds vss."""
import argparse
import os
from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join
from types import SimpleNamespace

import pytest

from impacket.examples.secretsdump import NTDSHashes

import nxc.protocols.winrm.ntds as ntds_helpers
from nxc.protocols.winrm.ntds import (
    build_cleanup_script,
    build_create_script,
    parse_alias_guid,
    read_ntds_path,
)
from nxc.protocols.winrm.proto_args import proto_args

GUID = "11DE9570-3055-4A25-9729-282C48AF344E"
REMOTE_SIZE = 64

WHOAMI_ENABLED = '"SeBackupPrivilege","Back up files and directories","Enabled"\r\n'
WHOAMI_DISABLED = '"SeBackupPrivilege","Back up files and directories","Disabled"\r\n'
WHOAMI_MISSING = '"SeRemoteShutdownPrivilege","Shut down the system","Disabled"\r\n'

NTDS_PATH_D = "D:\\NTDS\\ntds.dit"

DS_CREATE_OK = (
    "Microsoft DiskShadow version 1.0\r\n"
    f"Alias vssabcd1234 for shadow ID {{{GUID}}} set as environment variable.\r\n"
    f"-> %vssabcd1234% = {{{GUID}}}\r\n"
    "The shadow copy was successfully exposed as Z:\\.\r\n"
)

DS_CLEANUP_OK = (
    f"Deleting shadow copy {{{GUID}}}...\r\n"
    "\r\n"
    "1 shadow copy deleted.\r\n"
)


@pytest.fixture(scope="module")
def winrm_module():
    winrm_path = join(dirname(dirname(__file__)), "nxc", "protocols", "winrm.py")
    spec = spec_from_file_location("winrm_protocol", winrm_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeLogger:
    def __init__(self):
        self.messages = []

    def _log(self, level, msg):
        self.messages.append((level, str(msg)))

    def display(self, msg):
        self._log("display", msg)

    def fail(self, msg):
        self._log("fail", msg)

    def success(self, msg):
        self._log("success", msg)

    def highlight(self, msg):
        self._log("highlight", msg)

    def debug(self, msg):
        self._log("debug", msg)

    def info(self, msg):
        self._log("info", msg)

    def has(self, level, needle):
        return any(lvl == level and needle in msg for lvl, msg in self.messages)


class FakeConn:
    def __init__(self, cmd_handler, ps_handler, fetch_fail_contains=None, fetch_partial_contains=None):
        self.cmd_handler = cmd_handler
        self.ps_handler = ps_handler
        self.fetch_fail_contains = fetch_fail_contains
        self.fetch_partial_contains = fetch_partial_contains
        self.commands = []
        self.ps_commands = []
        self.uploads = {}  # remote path -> content
        self.upload_bytes = {}  # remote path -> raw bytes read from the local temp file
        self.fetches = []

    def execute_cmd(self, cmd, encoding=None):
        self.commands.append(cmd)
        return self.cmd_handler(cmd)

    def execute_ps(self, ps):
        self.ps_commands.append(ps)
        return self.ps_handler(ps)

    def copy(self, local_path, remote_path):
        with open(local_path) as f:
            self.uploads[remote_path] = f.read()
        with open(local_path, "rb") as f:
            self.upload_bytes[remote_path] = f.read()

    def fetch(self, remote_path, local_path):
        if self.fetch_partial_contains and self.fetch_partial_contains in remote_path:
            with open(local_path, "wb") as f:
                f.write(b"\0" * 8)
            raise Exception("simulated partial fetch failure")
        if self.fetch_fail_contains and self.fetch_fail_contains in remote_path:
            raise Exception("simulated fetch failure")
        self.fetches.append((remote_path, local_path))
        with open(local_path, "wb") as f:
            f.write(b"\0" * REMOTE_SIZE)


class FakeDB:
    def __init__(self):
        self.credentials = []

    def get_hosts(self, filter_term=None):
        return [(1,)]

    def add_credential(self, *args, **kwargs):
        self.credentials.append((args, kwargs))


class FakeNTDS:
    SECRET_TYPE = NTDSHashes.SECRET_TYPE
    instance = None

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.dumped = False
        FakeNTDS.instance = self

    def dump(self):
        self.dumped = True
        self.kwargs["perSecretCallback"](
            self.SECRET_TYPE.NTDS,
            "contoso.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
        )

    def finish(self):
        pass


class FakeLocalOperations:
    def __init__(self, system_file):
        pass

    def getBootKey(self):
        return b"\0" * 16


def make_cmd_handler(whoami=WHOAMI_ENABLED, robocopy_rc=1, create_result=(DS_CREATE_OK, "", 0), temp="C:\\Windows\\Temp", reg_save_rc=0):
    def handler(cmd):
        c = cmd.lower()
        if "whoami /priv" in c:
            return whoami, "", 0
        if "echo %temp%" in c:
            return f"{temp}\r\n", "", 0
        if c.startswith("mkdir"):
            return "", "", 0
        if c.startswith("reg save"):
            return "", "", reg_save_rc
        if "diskshadow /s" in c and "create.dsh" in c:
            return create_result
        if c.startswith("robocopy"):
            return "", "", robocopy_rc
        if "diskshadow /s" in c and "cleanup.dsh" in c:
            return DS_CLEANUP_OK, "", 0
        if c.startswith("rmdir"):
            return "", "", 0
        raise AssertionError(f"unexpected command: {cmd}")
    return handler


def ps_handler(ps):
    if "GetDrives" in ps:
        return "C:\\\r\nD:\\\r\n", None, False
    raise AssertionError(f"unexpected powershell: {ps}")


def make_winrm(winrm_module, tmp_path, cmd_handler, monkeypatch, fetch_fail_contains=None, ntds_path=NTDS_PATH_D, fetch_partial_contains=None):
    monkeypatch.setattr(winrm_module, "NTDSHashes", FakeNTDS)
    monkeypatch.setattr(winrm_module, "LocalOperations", FakeLocalOperations)
    monkeypatch.setattr(winrm_module, "read_ntds_path", lambda hive: ntds_path)
    # Match the run ID to the sample DiskShadow output.
    monkeypatch.setattr(winrm_module, "gen_random_string", lambda length=10: "abcd1234")
    instance = winrm_module.winrm.__new__(winrm_module.winrm)
    instance.logger = FakeLogger()
    instance.conn = FakeConn(cmd_handler, ps_handler, fetch_fail_contains, fetch_partial_contains)
    instance.db = FakeDB()
    instance.domain = "contoso.local"
    instance.hostname = "DC01"
    instance.host = "192.168.0.10"
    instance.output_file_template = join(str(tmp_path), "{output_folder}", "DC01_ntds")
    instance.args = SimpleNamespace(
        codec="437",
        ntds="vss",
        history=False,
        kerberos_keys=False,
        enabled=False,
        userntds=None,
        no_output=True,
    )
    return instance


# ---------- pure helpers ----------


def test_parse_alias_guid_matches_both_output_formats_once():
    assert parse_alias_guid(DS_CREATE_OK, "vssabcd1234") == GUID


def test_parse_alias_guid_absent_returns_none():
    assert parse_alias_guid("nothing here", "vssabcd1234") is None


def test_parse_alias_guid_ambiguous_raises():
    stdout = (
        f"-> %vssabcd12% = {{{GUID}}}\r\n"
        "Alias vssabcd12 for shadow ID {A8DE9570-3055-4A25-9729-282C48AF344F} set as environment variable.\r\n"
    )
    with pytest.raises(ValueError, match="Ambiguous"):
        parse_alias_guid(stdout, "vssabcd12")


class FakeHive:
    def __init__(self, values):
        self.values = values
        self.queries = []

    def getValue(self, path):
        self.queries.append(path)
        return self.values.get(path)


def make_hive(monkeypatch, values):
    hive = FakeHive(values)
    monkeypatch.setattr(ntds_helpers.winregistry, "get_registry_parser", lambda path, is_remote: hive)
    return hive


def reg_sz(text):
    return (1, text.encode("utf-16le") + b"\x00\x00")


def test_read_ntds_path_relocated_database(monkeypatch):
    hive = make_hive(monkeypatch, {
        "\\Select\\Current": (4, 2),
        "\\ControlSet002\\Services\\NTDS\\Parameters\\DSA Database file": reg_sz("E:\\NTDS\\ntds.dit"),
    })

    assert read_ntds_path("system.hive") == "E:\\NTDS\\ntds.dit"
    assert "\\ControlSet002\\Services\\NTDS\\Parameters\\DSA Database file" in hive.queries
    assert not any("ControlSet001" in query for query in hive.queries)


def test_read_ntds_path_missing_value_returns_none(monkeypatch):
    make_hive(monkeypatch, {"\\Select\\Current": (4, 1)})

    assert read_ntds_path("system.hive") is None


def test_read_ntds_path_rejects_path_without_drive_letter(monkeypatch):
    make_hive(monkeypatch, {
        "\\Select\\Current": (4, 1),
        "\\ControlSet001\\Services\\NTDS\\Parameters\\DSA Database file": reg_sz("ntds.dit"),
    })

    assert read_ntds_path("system.hive") is None


def test_create_script_uses_configured_ntds_volume():
    script = build_create_script("vssabcd12", "D:", "Z", "C:\\Windows\\Temp\\nxc_x\\metadata.cab")
    assert "add volume D: alias vssabcd12" in script
    assert "expose %vssabcd12% Z:" in script


def test_cleanup_script_deletes_only_the_created_snapshot():
    script = build_cleanup_script("Z", GUID)
    assert "unexpose Z:" in script
    assert f"delete shadows id {{{GUID}}}" in script
    assert "delete shadows all" not in script.lower()
    assert "oldest" not in script.lower()


# ---------- argument parsing ----------


def build_parser():
    parser = argparse.ArgumentParser(prog="netexec")
    subparsers = parser.add_subparsers(dest="protocol")
    proto_args(subparsers, [])
    return parser


def test_args_ntds_vss_parses():
    args = build_parser().parse_args(["winrm", "--ntds", "vss"])
    assert args.ntds == "vss"


def test_args_ntds_requires_vss_value():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["winrm", "--ntds"])


def test_args_ntds_rejects_drsuapi():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["winrm", "--ntds", "drsuapi"])


def test_args_kerberos_keys_require_ntds():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["winrm", "--kerberos-keys"])


def test_args_ntds_options_parse():
    args = build_parser().parse_args(["winrm", "--ntds", "vss", "--kerberos-keys", "--enabled", "--history", "--user", "bob"])
    assert args.kerberos_keys
    assert args.enabled
    assert args.history
    assert args.userntds == "bob"


# ---------- protocol behavior ----------


def test_ntds_success_flow(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)
    instance.ntds()

    assert len(instance.conn.fetches) == 2
    assert FakeNTDS.instance.dumped
    assert len(instance.db.credentials) == 1
    cleanup_uploads = [path for path in instance.conn.uploads if path.endswith("cleanup.dsh")]
    assert len(cleanup_uploads) == 1
    assert f"delete shadows id {{{GUID}}}" in instance.conn.uploads[cleanup_uploads[0]]
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)
    assert instance.logger.has("success", "Remote artifacts and shadow copy removed")


def test_ntds_uses_configured_volume(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)
    instance.ntds()

    create_uploads = [path for path in instance.conn.uploads if path.endswith("create.dsh")]
    assert len(create_uploads) == 1
    assert "add volume D: " in instance.conn.uploads[create_uploads[0]]
    robocopy = next(cmd for cmd in instance.conn.commands if cmd.startswith("robocopy"))
    assert robocopy.startswith('robocopy "Z:\\NTDS"')


def test_ntds_privilege_present_but_disabled_proceeds(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(whoami=WHOAMI_DISABLED), monkeypatch)
    instance.ntds()

    assert any("diskshadow /s" in cmd and "create.dsh" in cmd for cmd in instance.conn.commands)
    assert instance.logger.has("display", "present but disabled")


def test_ntds_privilege_absent_aborts(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(whoami=WHOAMI_MISSING), monkeypatch)
    instance.ntds()

    assert instance.conn.commands == ["whoami /priv /fo csv /nh"]
    assert instance.logger.has("fail", "SeBackupPrivilege was not found")


def test_ntds_robocopy_failure_cleans_up_snapshot(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(robocopy_rc=8), monkeypatch)
    instance.ntds()

    assert [remote for remote, _ in instance.conn.fetches] == ["C:\\Windows\\Temp\\nxc_abcd1234\\SYSTEM"]
    assert not os.path.exists(join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system"))
    assert instance.logger.has("fail", "Could not copy ntds.dit")
    cleanup_uploads = [path for path in instance.conn.uploads if path.endswith("cleanup.dsh")]
    assert len(cleanup_uploads) == 1
    assert f"delete shadows id {{{GUID}}}" in instance.conn.uploads[cleanup_uploads[0]]
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


def test_ntds_create_failure_without_guid_only_removes_staging(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(
        winrm_module,
        tmp_path,
        make_cmd_handler(create_result=("DiskShadow encountered an error\r\n", "", 1)),
        monkeypatch,
    )
    instance.ntds()

    assert [remote for remote, _ in instance.conn.fetches] == ["C:\\Windows\\Temp\\nxc_abcd1234\\SYSTEM"]
    assert not os.path.exists(join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system"))
    assert not any(path.endswith("cleanup.dsh") for path in instance.conn.uploads)
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)
    assert instance.logger.has("fail", "snapshot may remain")


def test_ntds_unexposed_snapshot_is_deleted_without_unexpose(winrm_module, tmp_path, monkeypatch):
    create_result = (
        (
            "Microsoft DiskShadow version 1.0\r\n"
            f"Alias vssabcd1234 for shadow ID {{{GUID}}} set as environment variable.\r\n"
            f"-> %vssabcd1234% = {{{GUID}}}\r\n"
        ),
        "",
        0,
    )
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(create_result=create_result), monkeypatch)
    instance.ntds()

    assert instance.logger.has("fail", "did not confirm that the snapshot was exposed")
    cleanup_uploads = [path for path in instance.conn.uploads if path.endswith("cleanup.dsh")]
    assert len(cleanup_uploads) == 1
    cleanup_script = instance.conn.uploads[cleanup_uploads[0]]
    assert f"delete shadows id {{{GUID}}}" in cleanup_script
    assert "unexpose" not in cleanup_script


def test_ntds_local_makedirs_failure_still_cleans_remote_staging(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)

    def failing_makedirs(*args, **kwargs):
        raise OSError("local disk full")

    monkeypatch.setattr(os, "makedirs", failing_makedirs)
    instance.ntds()

    assert instance.logger.has("fail", "Could not acquire NTDS.dit and the SYSTEM hive")
    assert not any(cmd.startswith("reg save") for cmd in instance.conn.commands)
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


def test_ntds_commands_quote_staging_path_with_spaces(winrm_module, tmp_path, monkeypatch):
    temp = "C:\\Users\\Bob Smith\\AppData\\Local\\Temp"
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(temp=temp), monkeypatch)
    instance.ntds()

    staging = f"{temp}\\nxc_abcd1234"
    assert f'mkdir "{staging}"' in instance.conn.commands
    assert f'diskshadow /s "{staging}\\create.dsh"' in instance.conn.commands
    assert f'reg save HKLM\\SYSTEM "{staging}\\SYSTEM" /y' in instance.conn.commands
    assert f'diskshadow /s "{staging}\\cleanup.dsh"' in instance.conn.commands
    assert f'rmdir /s /q "{staging}"' in instance.conn.commands
    create_script = instance.conn.uploads[f"{staging}\\create.dsh"]
    assert f'set metadata "{staging}\\metadata.cab"' in create_script


def test_ntds_uses_configured_filename(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch, ntds_path="D:\\NTDS\\ntds_custom.dit")
    instance.ntds()

    robocopy = next(cmd for cmd in instance.conn.commands if cmd.startswith("robocopy"))
    assert '"ntds_custom.dit"' in robocopy
    assert any(remote.endswith("\\ntds_custom.dit") for remote, _ in instance.conn.fetches)


def test_upload_preserves_crlf_bytes(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)
    content = build_create_script("vssabcd1234", "C:", "Z", "C:\\Temp\\metadata.cab")
    assert instance._upload(content, "X:\\remote\\create.dsh")
    assert instance.conn.upload_bytes["X:\\remote\\create.dsh"] == content.encode()


def test_ntds_early_command_failure_is_caught(winrm_module, tmp_path, monkeypatch):
    handler_ok = make_cmd_handler()

    def handler(cmd):
        if "echo %temp%" in cmd.lower():
            raise RuntimeError("transport broken")
        return handler_ok(cmd)

    instance = make_winrm(winrm_module, tmp_path, handler, monkeypatch)
    instance.ntds()

    assert instance.logger.has("fail", "Could not prepare the NTDS dump")
    assert not any("diskshadow" in cmd for cmd in instance.conn.commands)


def test_ntds_reg_save_failure_aborts_before_snapshot(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(reg_save_rc=1), monkeypatch)
    instance.ntds()

    assert instance.logger.has("fail", "Could not save the SYSTEM hive")
    assert instance.conn.fetches == []
    assert not any("create.dsh" in cmd for cmd in instance.conn.commands)
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


def test_ntds_system_download_failure_aborts_before_snapshot(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch, fetch_fail_contains="\\SYSTEM")
    instance.ntds()

    assert instance.logger.has("fail", "Could not download SYSTEM")
    assert not any("create.dsh" in cmd for cmd in instance.conn.commands)
    assert not any(path.endswith("cleanup.dsh") for path in instance.conn.uploads)
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)
    assert not os.path.exists(join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system"))


def test_ntds_dit_download_failure_removes_local_system(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch, fetch_fail_contains="ntds.dit")
    instance.ntds()

    assert not os.path.exists(join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system"))
    assert instance.logger.has("fail", "Could not download both the NTDS database and SYSTEM hive")
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


def test_ntds_partial_download_is_removed(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch, fetch_partial_contains="\\SYSTEM")
    instance.ntds()

    assert instance.logger.has("fail", "Could not download SYSTEM")
    assert not os.path.exists(join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system"))
    assert not any("create.dsh" in cmd for cmd in instance.conn.commands)
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


def test_ntds_existing_output_file_is_not_overwritten(winrm_module, tmp_path, monkeypatch):
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)
    existing = join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system")
    os.makedirs(os.path.dirname(existing), exist_ok=True)
    with open(existing, "w") as f:
        f.write("precious")

    instance.ntds()

    with open(existing) as f:
        assert f.read() == "precious"
    assert instance.logger.has("fail", "already exists")
    assert not any(remote.endswith("\\SYSTEM") for remote, _ in instance.conn.fetches)
    assert not any("create.dsh" in cmd for cmd in instance.conn.commands)
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


def test_ntds_drive_probe_failure_aborts(winrm_module, tmp_path, monkeypatch):
    def failing_ps(ps):
        raise RuntimeError("runspace broken")

    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)
    instance.conn.ps_handler = failing_ps
    instance.ntds()

    assert instance.logger.has("fail", "Could not enumerate the remote drives")
    assert not any("create.dsh" in cmd for cmd in instance.conn.commands)
    assert not os.path.exists(join(str(tmp_path), "ntds", "DC01_ntds_abcd1234.system"))


def test_ntds_output_collision_preserves_existing_files(winrm_module, tmp_path, monkeypatch):
    # Simulate files from an earlier run.
    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch, fetch_fail_contains="ntds.dit")
    old_base = instance.output_file_template.format(output_folder="ntds")
    os.makedirs(os.path.dirname(old_base), exist_ok=True)
    for suffix in (".dit", ".system"):
        with open(old_base + suffix, "w") as f:
            f.write("precious")

    instance.ntds()

    for suffix in (".dit", ".system"):
        with open(old_base + suffix) as f:
            assert f.read() == "precious"
    assert not os.path.exists(f"{old_base}_abcd1234.system")


def test_ntds_invalid_system_hive_is_caught(winrm_module, tmp_path, monkeypatch):
    class BadLocalOperations:
        def __init__(self, system_file):
            pass

        def getBootKey(self):
            raise Exception("not a registry hive")

    instance = make_winrm(winrm_module, tmp_path, make_cmd_handler(), monkeypatch)
    monkeypatch.setattr(winrm_module, "LocalOperations", BadLocalOperations)
    instance.ntds()

    assert instance.logger.has("fail", "not a registry hive")
    assert len(instance.conn.fetches) == 2
    assert any(cmd.lower().startswith("rmdir /s /q") for cmd in instance.conn.commands)


# ---------- _run_cmd code-5 fallback ----------


class FakeWSManFault(Exception):
    code = 5


def test_run_cmd_falls_back_to_powershell_on_code5(winrm_module, tmp_path, monkeypatch):
    def failing_cmd_handler(cmd):
        raise FakeWSManFault("access denied")

    instance = make_winrm(winrm_module, tmp_path, failing_cmd_handler, monkeypatch)
    instance.conn.ps_handler = lambda ps: ("hello\r\nNXC_RC=3\r\n", None, False)

    stdout, stderr, rc = instance._run_cmd("whoami")
    assert stdout == "hello\r\n"
    assert stderr == ""
    assert rc == 3
    assert instance.conn.ps_commands == ["cmd /c 'whoami'; \"NXC_RC=$LASTEXITCODE\""]


def test_run_cmd_reraises_non_code5_errors(winrm_module, tmp_path, monkeypatch):
    def failing_cmd_handler(cmd):
        raise ValueError("boom")

    instance = make_winrm(winrm_module, tmp_path, failing_cmd_handler, monkeypatch)
    with pytest.raises(ValueError, match="boom"):
        instance._run_cmd("whoami")


def test_run_cmd_fallback_raises_without_exit_marker(winrm_module, tmp_path, monkeypatch):
    def failing_cmd_handler(cmd):
        raise FakeWSManFault("access denied")

    instance = make_winrm(winrm_module, tmp_path, failing_cmd_handler, monkeypatch)
    instance.conn.ps_handler = lambda ps: ("hello\r\n", None, False)

    with pytest.raises(RuntimeError, match="No exit code marker"):
        instance._run_cmd("whoami")


def test_run_cmd_fallback_preserves_stderr(winrm_module, tmp_path, monkeypatch):
    def failing_cmd_handler(cmd):
        raise FakeWSManFault("access denied")

    instance = make_winrm(winrm_module, tmp_path, failing_cmd_handler, monkeypatch)
    instance.conn.ps_handler = lambda ps: ("out\r\nNXC_RC=1\r\n", SimpleNamespace(error=["Access is denied."]), True)

    stdout, stderr, rc = instance._run_cmd('mkdir "C:\\temp dir\\nxc_x"')
    assert rc == 1
    assert stdout == "out\r\n"
    assert stderr == "Access is denied."
    assert instance.conn.ps_commands == ["cmd /c 'mkdir \"C:\\temp dir\\nxc_x\"'; \"NXC_RC=$LASTEXITCODE\""]
