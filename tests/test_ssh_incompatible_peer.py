"""Regression tests for SSH peer negotiation reporting (nxc/protocols/ssh.py).

Background: paramiko raises ``IncompatiblePeer`` - a subclass of ``SSHException``
- when the peer offers no kex or host key algorithm in common. It matched the
``except SSHException`` handler in ``plaintext_login`` and fell through to the
catch-all ``else`` branch, which renders a full traceback per host and buries the
one line that explains the mismatch.
"""

from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join
from types import SimpleNamespace

import pytest
from paramiko.ssh_exception import IncompatiblePeer


def _load_ssh():
    spec = spec_from_file_location(
        "ssh_peer_test", join(dirname(dirname(__file__)), "nxc", "protocols", "ssh.py")
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ssh


class _RecordingLogger:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args[0] if args else None))

        return record


def _login_with(exception):
    ssh = _load_ssh()

    obj = ssh.__new__(ssh)
    obj.host, obj.port, obj.username, obj.password = "127.0.0.1", 22, "user", "pass"
    obj.args = SimpleNamespace(key_file=None, ssh_timeout=5)
    obj.conn = SimpleNamespace(
        connect=lambda *a, **k: (_ for _ in ()).throw(exception), close=lambda: None
    )
    obj.logger = _RecordingLogger()
    obj.db = SimpleNamespace(add_credential=lambda *a, **k: 1)
    obj.check_shell = lambda cred_id: None
    obj.uac = ""
    obj.server_os_platform = ""
    obj.shell_access = False
    obj.mark_pwned = lambda: ""

    result = obj.plaintext_login("user", "pass")
    return result, obj.logger.calls


@pytest.mark.parametrize(
    "reason",
    ["no acceptable kex algorithm", "no acceptable host key"],
)
def test_incompatible_peer_is_reported_without_a_traceback(reason):
    calls = _login_with(IncompatiblePeer(f"Incompatible ssh peer ({reason})"))[1]

    levels = [level for level, _ in calls]
    assert "exception" not in levels, f"a traceback was rendered: {calls}"
    assert "error" in levels

    message = dict(calls)["error"]
    assert "Incompatible SSH peer" in message
    assert reason in message


def test_other_ssh_errors_still_raise_a_traceback():
    from paramiko.ssh_exception import SSHException

    calls = _login_with(SSHException("something unexpected"))[1]

    assert [level for level, _ in calls if level in ("error", "exception", "fail")] == [
        "exception"
    ]
