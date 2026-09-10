"""
Regression tests for issue #1385: the CSV header for `export hosts` was hard
coded to the SMB schema (smbv1/signing/spooler/zerologon/petitpotam) and did not
match the actual row content for other protocols (RDP, SSH, MSSQL, ...).

The header is now derived from the active protocol's HostsTable columns, so the
header always matches the rows. These tests build lightweight SQLAlchemy tables
that mirror the real per-protocol schemas and assert the derived headers.

nxcdb.py pulls in the whole nxc stack at import time, so we register minimal
stubs for its heavy imports before loading the module in isolation.
"""

import importlib.util
import os
import sys
import types
from sqlalchemy import Column, Integer, String, Boolean, MetaData, Table

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.path.join(REPO_ROOT, "nxc", "nxcdb.py")


def _load_host_csv_headers():
    # Stub the heavy third-party / nxc imports so we can import nxcdb.py
    # without building the full NetExec dependency tree (which fails on 3.14).
    requests_stub = types.ModuleType("requests")
    requests_stub.get = lambda *a, **k: None
    requests_stub.post = lambda *a, **k: None
    requests_stub.ConnectionError = type("ConnectionError", (Exception,), {})
    sys.modules.setdefault("requests", requests_stub)
    sys.modules.setdefault("terminaltables3", types.ModuleType("terminaltables3"))
    sys.modules["terminaltables3"].AsciiTable = object
    sys.modules.setdefault("termcolor", types.ModuleType("termcolor"))
    sys.modules["termcolor"].colored = lambda *a, **k: a[0] if a else ""

    nxc_pkg = types.ModuleType("nxc")
    nxc_pkg.__path__ = []
    sys.modules.setdefault("nxc", nxc_pkg)
    nxc_paths = types.ModuleType("nxc.paths")
    nxc_paths.CONFIG_PATH = "/tmp"
    nxc_paths.WORKSPACE_DIR = "/tmp"
    sys.modules.setdefault("nxc.paths", nxc_paths)
    nxc_db = types.ModuleType("nxc.database")
    for fn in (
        "create_db_engine",
        "open_config",
        "get_workspace",
        "get_db",
        "write_configfile",
        "create_workspace",
        "set_workspace",
    ):
        setattr(nxc_db, fn, lambda *a, **k: None)
    sys.modules.setdefault("nxc.database", nxc_db)
    for sub in (
        "nxc.loaders",
        "nxc.loaders.protocolloader",
        "nxc.logger",
        "nxc.console",
    ):
        sys.modules.setdefault(sub, types.ModuleType(sub))
    sys.modules["nxc.loaders.protocolloader"].ProtocolLoader = object

    spec = importlib.util.spec_from_file_location("nxcdb_isolated", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nxcdb_isolated"] = module
    spec.loader.exec_module(module)
    return module.host_csv_headers


def _make_hosts_table(column_spec):
    """Build a throwaway HostsTable with the given (name, type) columns."""
    meta = MetaData()
    cols = [Column(name, col_type) for name, col_type in column_spec]
    return Table("hosts", meta, *cols)


def test_simple_header_matches_smb_schema_exactly():
    host_csv_headers = _load_host_csv_headers()
    # SMB HostsTable (id + 10 columns) -> simple keeps the first 8, which must
    # equal the historical SMB simple header so we don't regress SMB exports.
    smb = _make_hosts_table([
        ("id", Integer),
        ("ip", String),
        ("hostname", String),
        ("domain", String),
        ("os", String),
        ("dc", Boolean),
        ("smbv1", Boolean),
        ("signing", Boolean),
        ("spooler", Boolean),
        ("zerologon", Boolean),
        ("petitpotam", Boolean),
    ])
    assert host_csv_headers(smb, "simple") == (
        "id",
        "ip",
        "hostname",
        "domain",
        "os",
        "dc",
        "smbv1",
        "signing",
    )


def test_detailed_header_uses_every_column_of_the_table():
    host_csv_headers = _load_host_csv_headers()
    smb = _make_hosts_table([
        ("id", Integer),
        ("ip", String),
        ("hostname", String),
        ("domain", String),
        ("os", String),
        ("dc", Boolean),
        ("smbv1", Boolean),
        ("signing", Boolean),
        ("spooler", Boolean),
        ("zerologon", Boolean),
        ("petitpotam", Boolean),
    ])
    assert host_csv_headers(smb, "detailed") == (
        "id",
        "ip",
        "hostname",
        "domain",
        "os",
        "dc",
        "smbv1",
        "signing",
        "spooler",
        "zerologon",
        "petitpotam",
    )


def test_rdp_header_has_no_smb_only_columns():
    host_csv_headers = _load_host_csv_headers()
    # RDP's real schema (no smbv1/spooler/zerologon/petitpotam). The bug in
    # #1385 was that exporting RDP hosts printed those SMB-only headers.
    rdp = _make_hosts_table([
        ("id", Integer),
        ("ip", String),
        ("hostname", String),
        ("domain", String),
        ("os", String),
        ("nla", Boolean),
    ])
    simple = host_csv_headers(rdp, "simple")
    detailed = host_csv_headers(rdp, "detailed")
    for header in (simple, detailed):
        assert "smbv1" not in header
        assert "spooler" not in header
        assert "zerologon" not in header
        assert "petitpotam" not in header
    assert detailed == ("id", "ip", "hostname", "domain", "os", "nla")
    # RDP has 6 columns, so simple returns all of them (fewer than 8).
    assert simple == ("id", "ip", "hostname", "domain", "os", "nla")
