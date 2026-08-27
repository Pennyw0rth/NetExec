import csv
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from nxc.modules.scope import NXCModule


class ModuleLog:
    def __init__(self):
        self.failures = []

    def debug(self, message):
        pass

    def display(self, message):
        pass

    def fail(self, message):
        self.failures.append(message)

    def success(self, message):
        pass


@pytest.fixture(autouse=True)
def reset_module_state():
    NXCModule.default_output_dir = None
    NXCModule.initialized_output_dirs.clear()
    NXCModule.recorded_hosts.clear()


@pytest.fixture
def context():
    return SimpleNamespace(
        args=SimpleNamespace(username=[], password=[], hash=[], cred_id=[], aesKey=None, use_kcache=False),
        log=ModuleLog(),
    )


def host(address, signing, no_ntlm=False, null_auth=False):
    return SimpleNamespace(
        host=address,
        hostname=f"HOST-{address.rsplit('.', 1)[-1]}",
        targetDomain="EXAMPLE.TEST",
        server_os="Windows Server 2022",
        smbv1=False,
        signing=signing,
        no_ntlm=no_ntlm,
        null_auth=null_auth,
        is_guest=False,
        isdc=False,
    )


def test_scope_outputs_classified_hosts(tmp_path, context):
    module = NXCModule()
    assert module.options(context, {"OUTPUT": str(tmp_path)}) is None

    module.on_login(context, host("192.0.2.10", signing=False, null_auth=True))
    module.on_login(context, host("192.0.2.11", signing=True))
    module.on_login(context, host("192.0.2.12", signing=False, no_ntlm=True))

    assert (tmp_path / "hosts.txt").read_text(encoding="utf-8").splitlines() == ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
    assert (tmp_path / "relay.txt").read_text(encoding="utf-8").splitlines() == ["192.0.2.10"]
    assert (tmp_path / "null-auth.txt").read_text(encoding="utf-8").splitlines() == ["192.0.2.10"]

    with (tmp_path / "scope.csv").open(newline="", encoding="utf-8") as output_file:
        rows = list(csv.DictReader(output_file))
    assert len(rows) == 3
    assert rows[0]["signing_required"] == "False"
    assert rows[0]["ntlm_enabled"] == "True"
    assert rows[0]["null_auth"] == "True"
    assert rows[0]["dc_detected"] == "False"


def test_scope_deduplicates_overlapping_targets(tmp_path, context):
    module = NXCModule()
    module.options(context, {"OUTPUT": str(tmp_path)})
    connection = host("192.0.2.10", signing=False, null_auth=True)

    module.on_login(context, connection)
    module.on_login(context, connection)

    assert (tmp_path / "hosts.txt").read_text(encoding="utf-8").splitlines() == ["192.0.2.10"]
    assert len((tmp_path / "scope.csv").read_text(encoding="utf-8").splitlines()) == 2


def test_scope_rejects_credentials(tmp_path, context):
    context.args.username = ["user"]
    module = NXCModule()

    assert module.options(context, {"OUTPUT": str(tmp_path)}) is False
    assert context.log.failures
    assert not (tmp_path / "hosts.txt").exists()


def test_scope_allows_explicit_blank_credentials(tmp_path, context):
    context.args.username = [""]
    context.args.password = [""]
    module = NXCModule()

    assert module.options(context, {"OUTPUT": str(tmp_path)}) is None
    assert (tmp_path / "hosts.txt").exists()


def test_scope_refuses_to_overwrite_results(tmp_path, context):
    (tmp_path / "hosts.txt").write_text("existing\n", encoding="utf-8")
    module = NXCModule()

    assert module.options(context, {"OUTPUT": str(tmp_path)}) is False
    assert (tmp_path / "hosts.txt").read_text(encoding="utf-8") == "existing\n"


def test_scope_overwrite_option_replaces_results(tmp_path, context):
    (tmp_path / "hosts.txt").write_text("existing\n", encoding="utf-8")
    module = NXCModule()

    assert module.options(context, {"OUTPUT": str(tmp_path), "OVERWRITE": "true"}) is None
    assert (tmp_path / "hosts.txt").read_text(encoding="utf-8") == ""


def test_scope_serializes_concurrent_hosts(tmp_path, context):
    module = NXCModule()
    module.options(context, {"OUTPUT": str(tmp_path)})

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(lambda number: module.on_login(context, host(f"192.0.2.{number}", signing=number % 2 == 0)), range(1, 51)))

    assert len((tmp_path / "hosts.txt").read_text(encoding="utf-8").splitlines()) == 50
    assert len((tmp_path / "scope.csv").read_text(encoding="utf-8").splitlines()) == 51
