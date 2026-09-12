import sys
from argparse import ArgumentParser
from pathlib import Path
from types import SimpleNamespace

import pytest

from nxc.loaders.protocolloader import ProtocolLoader


PROTOCOL_PATH = Path(__file__).parents[1] / "nxc" / "protocols" / "nfs.py"
PROTOCOL_ARGS_PATH = Path(__file__).parents[1] / "nxc" / "protocols" / "nfs" / "proto_args.py"
PROTOCOL_MODULE = ProtocolLoader().load_protocol(str(PROTOCOL_PATH))
proto_args = ProtocolLoader().load_protocol(str(PROTOCOL_ARGS_PATH)).proto_args
nfs = PROTOCOL_MODULE.nfs


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


class Database:
    def __init__(self):
        self.hosts = []

    def add_host(self, *host):
        self.hosts.append(host)


def make_protocol(version="4.0", auth="sys", port=None, share=None):
    protocol = object.__new__(nfs)
    protocol.args = SimpleNamespace(nfs_version=version, nfs_auth=auth, nfs_timeout=2, port=port, share=share, use_kcache=False, domain=None, username=[], kdcHost=None)
    protocol.host = "192.0.2.1"
    protocol.hostname = "server.example"
    protocol.port = port or 2049
    protocol.nfs = None
    protocol.nfs_version = version
    protocol.nfs_versions = () if version is None else (version,)
    protocol.discovery = None
    protocol.auth = {
        "flavor": 1,
        "machine_name": "NXC123",
        "uid": 0,
        "gid": 0,
        "aux_gid": [],
    }
    protocol.rpc_auth = protocol.auth if auth == "sys" else None
    protocol.logger = Logger()
    protocol.db = Database()
    protocol.root_escape = None
    protocol.escape_share = None
    protocol.escape_fh = b""
    protocol.authenticated = False
    protocol.credentials = None
    protocol.proto_logger = lambda: None
    return protocol


def discovery(*versions, nfs3_port=None, inconclusive=()):
    return SimpleNamespace(supported=versions, nfs3_port=nfs3_port, inconclusive=inconclusive)


def client_class(calls):
    class Client:
        def __init__(self, host, version, port, timeout, auth):
            calls.append(("init", host, version, port, timeout, auth))
            self.version = version
            self.port = port or 2049
            self.auth = auth
            self.connected = False

        def connect(self):
            self.connected = True
            calls.append(("connect", self.version))
            return self

        def disconnect(self):
            self.connected = False
            calls.append(("disconnect", self.version))

    return Client


def test_argument_defaults_use_auto_discovery():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["nfs", "--shares"])
    assert args.nfs_version is None
    assert args.nfs_auth == "sys"
    assert args.port is None
    assert args.nfs_timeout == 2


@pytest.mark.parametrize("version", ["3", "4.0", "4.1", "4.2"])
def test_argument_parser_accepts_exact_versions(version):
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    assert parser.parse_args(["nfs", "--nfs-version", version]).nfs_version == version


def test_argument_parser_rejects_legacy_nfsv4_value():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    with pytest.raises(SystemExit):
        parser.parse_args(["nfs", "--nfs-version", "4"])


def test_auto_discovery_prefers_nfsv3(monkeypatch):
    calls = []
    discovered = discovery("3", "4.0", "4.1", "4.2", nfs3_port=2050)

    def discover(*args):
        calls.append(("discover", args))
        return discovered

    monkeypatch.setattr(PROTOCOL_MODULE, "discover_nfs_versions", discover)
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", client_class(calls))
    protocol = make_protocol(None)

    assert protocol.create_conn_obj()
    assert protocol.nfs_version == "3"
    assert protocol.nfs_versions == discovered.supported
    assert calls[0] == ("discover", ("192.0.2.1", protocol.rpc_auth, 2049, 2, 111))
    assert calls[1] == ("init", "192.0.2.1", "3", 2050, 2, protocol.rpc_auth)


def test_auto_discovery_uses_latest_supported_nfsv4(monkeypatch):
    calls = []
    monkeypatch.setattr(PROTOCOL_MODULE, "discover_nfs_versions", lambda *args: discovery("4.0", "4.2"))
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", client_class(calls))
    protocol = make_protocol(None)

    assert protocol.create_conn_obj()
    assert protocol.nfs_version == "4.2"
    assert calls[0] == ("init", "192.0.2.1", "4.2", None, 2, protocol.rpc_auth)


def test_conclusively_unsupported_explicit_version_fails_without_fallback(monkeypatch):
    monkeypatch.setattr(PROTOCOL_MODULE, "discover_nfs_versions", lambda *args: discovery("4.1", "4.2"))
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", lambda *args: (_ for _ in ()).throw(AssertionError("client constructed")))
    protocol = make_protocol("3")

    assert not protocol.create_conn_obj()
    assert protocol.nfs_version == "3"
    assert "NFSv3 is not supported by the target" in protocol.logger.messages[-1]


@pytest.mark.parametrize(("version", "label"), [("3", "rpcbind"), ("3", "3@2049"), ("4.0", "4.0")])
def test_inconclusive_explicit_version_is_still_attempted(monkeypatch, version, label):
    calls = []
    monkeypatch.setattr(PROTOCOL_MODULE, "discover_nfs_versions", lambda *args: discovery("4.2", inconclusive=((label, TimeoutError()),)))
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", client_class(calls))
    protocol = make_protocol(version)

    assert protocol.create_conn_obj()
    assert protocol.nfs_version == version
    assert calls[0][2] == version


def test_custom_port_is_used_for_discovery_and_client(monkeypatch):
    calls = []

    def discover(*args):
        calls.append(("discover", args))
        return discovery("4.1")

    monkeypatch.setattr(PROTOCOL_MODULE, "discover_nfs_versions", discover)
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", client_class(calls))
    protocol = make_protocol("4.1", port=3049)

    assert protocol.create_conn_obj()
    assert calls[0] == ("discover", ("192.0.2.1", protocol.rpc_auth, 3049, 2, 111))
    assert calls[1] == ("init", "192.0.2.1", "4.1", 3049, 2, protocol.rpc_auth)


def test_auto_discovery_rejects_hosts_without_a_supported_version(monkeypatch):
    monkeypatch.setattr(PROTOCOL_MODULE, "discover_nfs_versions", lambda *args: discovery())
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", lambda *args: (_ for _ in ()).throw(AssertionError("client constructed")))
    protocol = make_protocol(None)
    assert not protocol.create_conn_obj()
    assert "No supported NFS version discovered" in protocol.logger.messages[-1]


def test_host_output_includes_discovered_and_selected_versions():
    protocol = make_protocol("3")
    protocol.nfs_versions = ("3", "4.0", "4.1", "4.2")
    protocol.print_host_info()
    assert "Supported NFS versions: (3, 4.0, 4.1, 4.2) NFSv3 sys" in protocol.logger.messages[-1]


def test_enum_host_info_uses_the_selected_generic_client():
    protocol = make_protocol("4.2")
    protocol.nfs_versions = ("4.1", "4.2")
    protocol.nfs = object()
    protocol.try_root_escape = lambda: True
    protocol.enum_host_info()
    assert protocol.root_escape is True
    assert protocol.db.hosts[-1][2:] == (2049, ("4.1", "4.2"), True)


def test_kerberos_rebuilds_the_selected_generic_client(monkeypatch):
    events = []

    class Client:
        def __init__(self, host, version, port, timeout, auth):
            self.port = port or 2049
            self.auth = auth
            events.append(("init", version, auth))

        def connect(self):
            events.append(("connect",))

        def disconnect(self):
            events.append(("disconnect",))

        def establish_gss(self, initiator, service):
            events.append(("gss", initiator.host, service))
            self.auth = "rpcsec-gss"

    class Initiator:
        def __init__(self, host, credentials):
            self.host = host
            self.credentials = credentials

    monkeypatch.setattr(PROTOCOL_MODULE, "NFSClient", Client)
    monkeypatch.setitem(sys.modules, "pyNfsClient.kerberos", SimpleNamespace(KerberosInitiator=Initiator))
    protocol = make_protocol("4.1", auth="krb5p")
    protocol.discovery = discovery("4.1")
    protocol.try_root_escape = lambda: False

    assert protocol.kerberos_login("NFS.TEST", "nfsclient", password="secret", kdcHost="192.0.2.2")
    assert ("init", "4.1", protocol.auth) in events
    assert ("gss", "192.0.2.1", "krb5p") in events
    assert protocol.rpc_auth == "rpcsec-gss"


def test_selected_root_handle_delegates_to_generic_client():
    protocol = make_protocol("4.2", share="/export")
    protocol.nfs = SimpleNamespace(
        root_handle=lambda share: {"status": 0, "mountinfo": {"fhandle": b"root"}},
        status_name=lambda status: str(status),
    )
    assert protocol.selected_root_handle() == b"root"


def test_nfsv3_without_share_still_requires_root_escape():
    protocol = make_protocol("3")
    protocol.nfs = SimpleNamespace()
    assert protocol.selected_root_handle() is None
    assert "please specify a share" in protocol.logger.messages[-1]


def test_root_escape_validation_uses_the_generic_client():
    protocol = make_protocol()
    protocol.nfs = SimpleNamespace(
        getattr=lambda file_handle, auth=None: {"status": 0, "attributes": {"type": 2}},
        readdir=lambda file_handle, auth=None: {"status": 0, "resok": {}},
        exports=lambda: [("/", ["Everyone"])],
        root_handle=lambda share: {"status": 0, "mountinfo": {"fhandle": b"export"}},
        unmount=lambda: None,
    )
    protocol.get_root_handles = lambda file_handle: [b"forged"]
    assert protocol.try_root_escape() is True
    assert protocol.escape_share == "/"
    assert protocol.escape_fh == b"forged"


def test_named_owner_does_not_replace_auth_sys_numeric_uid():
    protocol = make_protocol()
    protocol.nfs = SimpleNamespace(
        getattr=lambda file_handle, auth=None: {"status": 0, "attributes": {"uid": "root@nfs.test", "gid": "root@nfs.test"}},
        access=lambda file_handle, access, auth=None: {"status": 0, "resok": {"access": access}},
    )
    assert protocol.list_dir(b"root", "/", recurse=0)[0]["uid"] == "root@nfs.test"
    assert protocol.auth["uid"] == 0
    assert protocol.auth["gid"] == 0


def test_print_directory_restores_directory_identity_between_entries():
    calls = []
    owners = {b"one": (1000, 100), b"two": (2000, 200)}
    protocol = make_protocol()
    protocol.auth.update({"uid": 500, "gid": 50})

    def get_attributes(file_handle, auth=None):
        calls.append(("getattr", file_handle, auth["uid"], auth["gid"]))
        uid, gid = owners[file_handle]
        return {"status": 0, "attributes": {"uid": uid, "gid": gid}}

    def access(file_handle, requested, auth=None):
        calls.append(("access", file_handle, auth["uid"], auth["gid"]))
        return {"status": 0, "resok": {"access": requested}}

    protocol.nfs = SimpleNamespace(getattr=get_attributes, access=access)
    protocol.print_directory(
        [
            {
                "name": b"one",
                "name_attributes": {"present": True, "attributes": {"uid": 1000, "type": 1, "size": 0}},
                "name_handle": {"present": True, "handle": {"data": b"one"}},
            },
            {
                "name": b"two",
                "name_attributes": {"present": True, "attributes": {"uid": 2000, "type": 1, "size": 0}},
                "name_handle": {"present": True, "handle": {"data": b"two"}},
            },
        ],
        "/",
    )

    assert calls == [
        ("getattr", b"one", 500, 50),
        ("access", b"one", 1000, 100),
        ("access", b"one", 1000, 100),
        ("access", b"one", 1000, 100),
        ("getattr", b"two", 500, 50),
        ("access", b"two", 2000, 200),
        ("access", b"two", 2000, 200),
        ("access", b"two", 2000, 200),
    ]
    assert protocol.auth["uid"] == 500
    assert protocol.auth["gid"] == 50


def test_btrfs_root_escape_handles_are_python_310_compatible(monkeypatch):
    protocol = make_protocol()
    protocol.nfs = SimpleNamespace(readdirplus=lambda file_handle, auth=None: {})
    monkeypatch.setattr(protocol, "format_directory", lambda response: [])
    handles = protocol.get_root_handles(b"\x01\x00\x00\x4d" + b"12345678")
    assert len(handles) == 18
    assert handles[2][20:24] == b"\x00\x01\x00\x00"
    assert handles[-1][20:24] == b"\x0f\x01\x00\x00"


def test_netexec_uses_only_the_generic_client_api():
    source = PROTOCOL_PATH.read_text()
    assert "NFSClient" in source
    assert ".compound(" not in source
    assert "NFSv40" not in source
    assert "NFSv41" not in source
    assert "NFSv42" not in source


@pytest.mark.parametrize("version", ["3", "4.0", "4.1", "4.2"])
def test_uid_and_gid_changes_are_passed_to_each_generic_call(version):
    calls = []
    protocol = make_protocol(version=version)
    protocol.args.cat = "file"
    protocol.connect_nfs = lambda: protocol.nfs
    protocol.selected_root_handle = lambda: b"root"

    def get_attributes(file_handle, auth=None):
        calls.append(("getattr", file_handle, auth["uid"], auth["gid"]))
        uid, gid = (1000, 100) if file_handle == b"root" else (2000, 200)
        return {"status": 0, "attributes": {"uid": uid, "gid": gid}}

    def lookup(file_handle, name, auth=None):
        calls.append(("lookup", file_handle, auth["uid"], auth["gid"]))
        return {"status": 0, "resok": {"object": {"data": b"file"}, "obj_attributes": {"attributes": {"type": PROTOCOL_MODULE.NF3REG}}}}

    def read(file_handle, offset, auth=None):
        calls.append(("read", file_handle, auth["uid"], auth["gid"]))
        return {"status": 0, "resok": {"data": b"data", "eof": True}}

    protocol.nfs = SimpleNamespace(getattr=get_attributes, lookup=lookup, read=read)
    protocol.cat()

    assert calls == [
        ("getattr", b"root", 0, 0),
        ("lookup", b"root", 1000, 100),
        ("getattr", b"file", 1000, 100),
        ("read", b"file", 2000, 200),
    ]


def test_put_file_reuses_open_auth_snapshot_after_uid_detection(tmp_path):
    local_file = tmp_path / "upload.txt"
    local_file.write_bytes(b"payload")
    protocol = make_protocol("4.0")
    protocol.args.put_file = [str(local_file), "upload.txt"]
    protocol.selected_root_handle = lambda: b"root"
    events = []

    def update_auth(file_handle):
        if file_handle == b"root":
            protocol.auth.update({"uid": 1000, "gid": 100})
        else:
            protocol.auth.update({"uid": 2000, "gid": 200})
        return {"status": 0, "attributes": {"uid": protocol.auth["uid"], "gid": protocol.auth["gid"]}}

    class Client:
        def lookup(self, *args, **kwargs):
            return {"status": PROTOCOL_MODULE.NFS3ERR_NOENT, "resok": None, "resfail": {}}

        def create(self, dir_handle, name, create_mode, mode=None, auth=None):
            events.append(("create", auth))
            return {"status": 0, "resok": {"obj": {"handle": {"data": b"file"}}}}

        def fsinfo(self, *args, **kwargs):
            return {"status": 0, "resok": {"wtpref": 1024}}

        def write(self, file_handle, offset, count, content, stable_how, auth=None):
            events.append(("write", auth, content))
            return {"status": 0, "resok": {"count": count}}

        def close(self, file_handle, auth=None):
            events.append(("close", auth))
            return {"status": 0}

        def unmount(self):
            pass

        @staticmethod
        def status_name(status):
            return str(status)

    protocol.nfs = Client()
    protocol.update_auth = update_auth
    protocol.put_file()

    assert protocol.auth["uid"] == 2000
    assert events[0][1]["uid"] == 1000
    assert events[1][1] is events[0][1]
    assert events[2][1] is events[0][1]
    assert events[1][2] == b"payload"


def test_disconnect_delegates_all_cleanup_to_generic_client():
    class Client:
        def disconnect(self):
            self.disconnected = True

    protocol = make_protocol()
    protocol.nfs = Client()
    protocol.nfs.disconnected = False
    protocol.disconnect()
    assert protocol.nfs.disconnected
