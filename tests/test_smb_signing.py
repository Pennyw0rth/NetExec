"""Regression tests for SMB signing detection (nxc/protocols/smb.py).

Background: impacket force-sets ``_Connection["RequireSigning"] = True`` for
*any* SMB 3.1.1 negotiation, regardless of the server's real policy, because
the 3.1.1 session setup is always signed. Reading that flag therefore produced
false negatives for relay-target discovery: 3.1.1 hosts that merely *enable*
(but do not *require*) signing were reported as ``signing:True`` and silently
dropped from ``--gen-relay-list`` output.

The fix reads the real negotiated ``ServerSecurityMode`` for SMB 3.0+ instead.
"""
from os.path import dirname, join
from types import SimpleNamespace

import pytest
from importlib.util import module_from_spec, spec_from_file_location
from impacket.smb3structs import (
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB2_NEGOTIATE_SIGNING_ENABLED,
    SMB2_NEGOTIATE_SIGNING_REQUIRED,
)


@pytest.fixture(scope="module")
def smb_module():
    smb_path = join(dirname(dirname(__file__)), "nxc", "protocols", "smb.py")
    spec = spec_from_file_location("protocol", smb_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_smbv2_conn(dialect, server_security_mode, require_signing):
    """Mimic the relevant slice of an impacket SMBConnection for SMB2/3.

    ``isSigningRequired()`` returns ``RequireSigning``, matching impacket, for
    the dialects below SMB 3.0 that fall back to it.
    """
    inner = SimpleNamespace(
        _Connection={
            "Dialect": dialect,
            "ServerSecurityMode": server_security_mode,
            "RequireSigning": require_signing,
        }
    )
    return SimpleNamespace(_SMBConnection=inner, isSigningRequired=lambda: require_signing)


def make_smbv1_conn(signing_required):
    return SimpleNamespace(isSigningRequired=lambda: signing_required)


def test_smb311_signing_enabled_not_required_reports_false(smb_module):
    # The regression: impacket forces RequireSigning=True on 3.1.1, but the
    # server only *enables* signing -> this host IS a valid relay target.
    conn = make_smbv2_conn(
        dialect=SMB2_DIALECT_311,
        server_security_mode=SMB2_NEGOTIATE_SIGNING_ENABLED,
        require_signing=True,
    )
    assert smb_module.smb._is_signing_required(None, conn, smbv1=False) is False


def test_smb311_signing_required_reports_true(smb_module):
    conn = make_smbv2_conn(
        dialect=SMB2_DIALECT_311,
        server_security_mode=SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED,
        require_signing=True,
    )
    assert smb_module.smb._is_signing_required(None, conn, smbv1=False) is True


def test_smb30_signing_not_required_reports_false(smb_module):
    conn = make_smbv2_conn(
        dialect=SMB2_DIALECT_30,
        server_security_mode=SMB2_NEGOTIATE_SIGNING_ENABLED,
        require_signing=False,
    )
    assert smb_module.smb._is_signing_required(None, conn, smbv1=False) is False


def test_smb21_falls_back_to_require_signing(smb_module):
    # ServerSecurityMode is only populated for SMB 3.0+, so for 2.1 we must
    # fall back to RequireSigning (accurate below 3.1.1).
    conn = make_smbv2_conn(
        dialect=SMB2_DIALECT_21,
        server_security_mode=0,
        require_signing=True,
    )
    assert smb_module.smb._is_signing_required(None, conn, smbv1=False) is True


def test_smbv1_uses_session_signing_flag(smb_module):
    assert smb_module.smb._is_signing_required(None, make_smbv1_conn(True), smbv1=True) is True
    assert smb_module.smb._is_signing_required(None, make_smbv1_conn(False), smbv1=True) is False
