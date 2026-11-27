"""Regression tests for SSH IncompatiblePeer handling (nxc/protocols/ssh.py)."""
from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from paramiko.ssh_exception import IncompatiblePeer, SSHException


@pytest.fixture(scope="module")
def ssh_module():
    ssh_path = join(dirname(dirname(__file__)), "nxc", "protocols", "ssh.py")
    spec = spec_from_file_location("protocol", ssh_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_ssh_instance(ssh_module, side_effect):
    conn = MagicMock()
    conn.connect.side_effect = side_effect
    return SimpleNamespace(
        host="127.0.0.1",
        port=2222,
        args=SimpleNamespace(key_file=None, ssh_timeout=5),
        logger=MagicMock(),
        conn=conn,
    )


@pytest.mark.parametrize(
    "message",
    [
        "Incompatible ssh peer (no acceptable kex algorithm)",
        "Incompatible ssh peer (no acceptable host key)",
    ],
)
def test_incompatible_peer_logs_error_without_traceback(ssh_module, message):
    instance = make_ssh_instance(ssh_module, IncompatiblePeer(message))

    result = ssh_module.ssh.plaintext_login(instance, "bob", "pw")

    assert result is False
    instance.logger.error.assert_called_once_with(f"Incompatible SSH peer for bob:pw, {message}")
    instance.logger.exception.assert_not_called()


def test_unknown_ssh_exception_still_logs_traceback(ssh_module):
    err = SSHException("unexpected failure")
    instance = make_ssh_instance(ssh_module, err)

    result = ssh_module.ssh.plaintext_login(instance, "bob", "pw")

    assert result is False
    instance.logger.exception.assert_called_once_with(err)
