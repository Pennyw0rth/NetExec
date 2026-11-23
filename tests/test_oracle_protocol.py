import pytest
from argparse import ArgumentParser
from pathlib import Path

from nxc.loaders.protocolloader import ProtocolLoader


PROTOCOL_ARGS_PATH = Path(__file__).parents[1] / "nxc" / "protocols" / "oracle" / "proto_args.py"
proto_args = ProtocolLoader().load_protocol(str(PROTOCOL_ARGS_PATH)).proto_args


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


def test_argument_parser_accepts_enum_sids():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["oracle", "--enum-sids"])
    assert args.enum_sids is True


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
    assert args.enum_sids is False
    assert args.query is None
