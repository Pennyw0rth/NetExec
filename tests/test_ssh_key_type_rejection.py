"""
Unit tests for the SSH key-type rejection detection added for issue #1356.

When an sshd server rejects a public key because its algorithm is not in
`PubkeyAcceptedAlgorithms` (e.g. server allows only ssh-ed25519 while the
key is RSA), Paramiko raises with one of a few known messages. NetExec must
recognise those and report "Key type rejected by server" instead of the
misleading "Could not decrypt private key, invalid password".

These tests load the real helper from nxc/protocols/ssh.py without pulling
in the heavy nxc dependency tree (which fails to build on Python 3.14).
"""
import importlib.util
import os
import sys
import types

import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSH_MODULE = os.path.join(REPO_ROOT, "nxc", "protocols", "ssh.py")


def _load_helper():
    # Stub the nxc.* imports so we can import ssh.py in isolation.
    for name in ("nxc", "nxc.config", "nxc.connection", "nxc.logger"):
        sys.modules.setdefault(name, types.ModuleType(name))

    spec = importlib.util.spec_from_file_location("nxc_ssh_isolated", SSH_MODULE)
    module = importlib.util.module_from_spec(spec)
    # Provide the symbols ssh.py expects from nxc without real implementations.
    sys.modules["nxc.config"].process_secret = lambda s: s
    nxc_connection = sys.modules.setdefault("nxc.connection", types.ModuleType("nxc.connection"))
    nxc_connection.connection = object
    nxc_connection.highlight = lambda s: s
    nxc_logger = sys.modules.setdefault("nxc.logger", types.ModuleType("nxc.logger"))
    nxc_logger.NXCAdapter = object
    sys.modules["nxc_ssh_isolated"] = module
    spec.loader.exec_module(module)
    return module._is_key_type_rejected


_is_key_type_rejected = _load_helper()


def _real_paramiko_messages():
    """Build the actual exception messages Paramiko 5.x emits for this case."""
    return [
        SSHException("Auth rejected: pubkey algorithm 'ssh-rsa' unsupported or disabled"),
        AuthenticationException(
            "Unable to agree on a pubkey algorithm for signing a 'ssh-rsa' key!"
        ),
        SSHException(
            "An RSA key was specified, but no RSA pubkey algorithms are configured!"
        ),
    ]


def test_real_paramiko_rejection_messages_are_detected():
    for exc in _real_paramiko_messages():
        assert _is_key_type_rejected(exc), f"failed to detect: {exc}"


def test_wrong_passphrase_is_not_flagged_as_rejection():
    # The existing "Invalid key" path must NOT be misclassified as a server
    # rejection, otherwise we'd hide the real "invalid password" message.
    assert not _is_key_type_rejected(SSHException("Invalid key"))


def test_unrelated_ssh_exception_is_not_flagged():
    assert not _is_key_type_rejected(
        SSHException("Error reading SSH protocol banner")
    )


def test_private_key_encrypted_is_not_flagged():
    assert not _is_key_type_rejected(
        AuthenticationException("Private key file is encrypted")
    )
