import pytest
from argparse import ArgumentParser
from pathlib import Path
from types import SimpleNamespace

from nxc.loaders.protocolloader import ProtocolLoader
from nxc.modules.oracle_exec import NXCModule as OracleExec
from nxc.modules.oracle_shell import NXCModule as OracleShell


PROTOCOL_ARGS_PATH = Path(__file__).parents[1] / "nxc" / "protocols" / "oracle" / "proto_args.py"
proto_args = ProtocolLoader().load_protocol(str(PROTOCOL_ARGS_PATH)).proto_args


class Logger:
    def __init__(self):
        self.messages = []

    def debug(self, message):
        self.messages.append(message)

    def info(self, message):
        self.messages.append(message)

    def fail(self, message):
        self.messages.append(message)

    def success(self, message):
        self.messages.append(message)

    def display(self, message):
        self.messages.append(message)

    def highlight(self, message):
        self.messages.append(message)


def make_context():
    return SimpleNamespace(log=Logger())


def make_connection(conn=None):
    return SimpleNamespace(conn=conn)


# ── Proto args ───────────────────────────────────────────────────────────────

def test_argument_parser_accepts_service_name():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--service-name", "ORCL"])
    assert args.service_name == "ORCL"
    assert args.sid is None


def test_argument_parser_accepts_sid():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--sid", "XE"])
    assert args.sid == "XE"
    assert args.service_name is None


def test_argument_parser_rejects_service_name_and_sid_together():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    with pytest.raises(SystemExit):
        parser.parse_args(["oracle", "--service-name", "ORCL", "--sid", "XE"])


def test_argument_parser_accepts_sysdba():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--service-name", "XE", "--sysdba"])
    assert args.sysdba is True
    assert args.sysoper is False


def test_argument_parser_accepts_sysoper():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--service-name", "XE", "--sysoper"])
    assert args.sysoper is True
    assert args.sysdba is False


def test_argument_parser_rejects_sysdba_and_sysoper_together():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    with pytest.raises(SystemExit):
        parser.parse_args(["oracle", "--service-name", "XE", "--sysdba", "--sysoper"])


def test_argument_parser_accepts_dump_hashes():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--service-name", "XE", "--dump-hashes"])
    assert args.dump_hashes is True


def test_argument_parser_accepts_query():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--service-name", "XE", "-q", "SELECT 1 FROM dual"])
    assert args.query == "SELECT 1 FROM dual"


def test_argument_parser_defaults():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--service-name", "XE"])
    assert args.port == 1521
    assert args.oracle_timeout == 5
    assert args.sysdba is False
    assert args.sysoper is False
    assert args.dump_hashes is False
    assert args.users is False
    assert args.roles is False
    assert args.tablespaces is False
    assert args.dblinks is False
    assert args.query is None


# ── oracle_exec: option validation ──────────────────────────────────────────

def test_oracle_exec_options_requires_cmd():
    module = OracleExec()
    ctx = make_context()
    module.options(ctx, {})
    assert any("CMD" in m for m in ctx.log.messages)
    assert module.cmd is None


def test_oracle_exec_options_sets_cmd():
    module = OracleExec()
    ctx = make_context()
    module.options(ctx, {"CMD": "id"})
    assert module.cmd == "id"
    assert not ctx.log.messages


def test_oracle_exec_on_admin_login_requires_cmd():
    module = OracleExec()
    ctx = make_context()
    module.on_admin_login(ctx, make_connection())
    assert any("No command" in m for m in ctx.log.messages)


# ── oracle_exec: java availability ──────────────────────────────────────────

def test_oracle_exec_java_available_returns_false_when_count_is_zero():
    module = OracleExec()

    class Cursor:
        def execute(self, sql): pass
        def fetchone(self): return (0,)
        def close(self): pass

    class Conn:
        def cursor(self): return Cursor()

    assert module.java_available(Conn(), Logger()) is False


def test_oracle_exec_java_available_returns_true_when_dbms_java_present():
    module = OracleExec()

    class Cursor:
        def execute(self, sql): pass
        def fetchone(self): return (1,)
        def close(self): pass

    class Conn:
        def cursor(self): return Cursor()

    assert module.java_available(Conn(), Logger()) is True


def test_oracle_exec_java_available_returns_false_on_db_error():
    module = OracleExec()

    class Cursor:
        def execute(self, sql): raise Exception("ORA-00942: table or view does not exist")
        def close(self): pass

    class Conn:
        def cursor(self): return Cursor()

    assert module.java_available(Conn(), Logger()) is False


def test_oracle_exec_fails_cleanly_when_java_unavailable(monkeypatch):
    module = OracleExec()
    module.cmd = "id"
    ctx = make_context()
    monkeypatch.setattr(module, "java_available", lambda conn, log: False)
    monkeypatch.setattr(module, "cleanup", lambda conn, log: None)
    module.on_admin_login(ctx, make_connection())
    assert any("Java is not enabled" in m for m in ctx.log.messages)


# ── oracle_exec: cleanup in finally ─────────────────────────────────────────

def test_oracle_exec_cleanup_runs_when_create_source_raises(monkeypatch):
    module = OracleExec()
    module.cmd = "id"
    ctx = make_context()
    cleaned_up = []

    def raise_compile_error(conn, log):
        raise RuntimeError("Java compilation failed: PLS-00103")

    monkeypatch.setattr(module, "java_available", lambda conn, log: True)
    monkeypatch.setattr(module, "grant_java_perms", lambda conn, log: None)
    monkeypatch.setattr(module, "create_java_source", raise_compile_error)
    monkeypatch.setattr(module, "cleanup", lambda conn, log: cleaned_up.append(True))

    module.on_admin_login(ctx, make_connection())
    assert cleaned_up, "cleanup must run even when Java compilation fails"
    assert any("PLS-00103" in m for m in ctx.log.messages)


# ── oracle_shell: option validation ─────────────────────────────────────────

def test_oracle_shell_options_requires_lhost():
    module = OracleShell()
    ctx = make_context()
    module.options(ctx, {"LPORT": "4444"})
    assert any("LHOST" in m for m in ctx.log.messages)
    assert module.lhost is None


def test_oracle_shell_options_requires_lport():
    module = OracleShell()
    ctx = make_context()
    module.options(ctx, {"LHOST": "192.168.1.10"})
    assert any("LPORT" in m for m in ctx.log.messages)
    assert module.lport is None


def test_oracle_shell_options_rejects_non_integer_lport():
    module = OracleShell()
    ctx = make_context()
    module.options(ctx, {"LHOST": "192.168.1.10", "LPORT": "notaport"})
    assert any("integer" in m for m in ctx.log.messages)
    assert module.lport is None


def test_oracle_shell_options_sets_lhost_and_lport():
    module = OracleShell()
    ctx = make_context()
    module.options(ctx, {"LHOST": "192.168.1.10", "LPORT": "4444"})
    assert module.lhost == "192.168.1.10"
    assert module.lport == 4444


def test_oracle_shell_on_admin_login_requires_lhost_and_lport():
    module = OracleShell()
    ctx = make_context()
    module.on_admin_login(ctx, make_connection())
    assert any("LHOST and LPORT" in m for m in ctx.log.messages)


# ── oracle_shell: java availability ─────────────────────────────────────────

def test_oracle_shell_fails_cleanly_when_java_unavailable(monkeypatch):
    module = OracleShell()
    module.lhost = "192.168.1.10"
    module.lport = 4444
    ctx = make_context()
    monkeypatch.setattr(module, "java_available", lambda conn, log: False)
    monkeypatch.setattr(module, "cleanup", lambda conn, log: None)
    module.on_admin_login(ctx, make_connection())
    assert any("Java is not enabled" in m for m in ctx.log.messages)


# ── oracle_shell: cleanup in finally ────────────────────────────────────────

def test_oracle_shell_cleanup_runs_when_connection_refused(monkeypatch):
    module = OracleShell()
    module.lhost = "192.168.1.10"
    module.lport = 4444
    ctx = make_context()
    cleaned_up = []

    def raise_connection_refused(conn, log):
        raise Exception("Connection refused")

    monkeypatch.setattr(module, "java_available", lambda conn, log: True)
    monkeypatch.setattr(module, "grant_java_perms", lambda conn, log: None)
    monkeypatch.setattr(module, "create_java_source", lambda conn, log: None)
    monkeypatch.setattr(module, "create_wrapper", lambda conn, log: None)
    monkeypatch.setattr(module, "run_shell", raise_connection_refused)
    monkeypatch.setattr(module, "cleanup", lambda conn, log: cleaned_up.append(True))

    module.on_admin_login(ctx, make_connection())
    assert cleaned_up, "cleanup must run even when the shell connection fails"
    assert any("Connection refused" in m for m in ctx.log.messages)
