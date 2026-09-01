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


def make_protocol(version=4, auth="sys", port=None, share=None):
    protocol = object.__new__(nfs)
    protocol.args = SimpleNamespace(nfs_version=version, nfs_auth=auth, nfs_timeout=5, port=port, share=share, use_kcache=False, domain=None, username=[], kdcHost=None)
    protocol.host = "192.0.2.1"
    protocol.hostname = "server.example"
    protocol.port = port or (2049 if version == 4 else 111)
    protocol.portmap = None
    protocol.mount = None
    protocol.nfs = None
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
    protocol.nfs_versions = {version}
    protocol.root_escape = None
    protocol.escape_share = None
    protocol.escape_fh = b""
    protocol.authenticated = False
    protocol.credentials = None
    protocol.proto_logger = lambda: None
    return protocol


def test_argument_defaults_select_nfsv3_discovery():
    parser = ArgumentParser()
    proto_args(parser.add_subparsers(dest="protocol"), [])
    args = parser.parse_args(["nfs", "--shares"])
    assert args.nfs_version == 3
    assert args.nfs_auth == "sys"
    assert args.port is None


def test_nfsv4_constructs_raw_backend_without_portmapper(monkeypatch):
    calls = []

    class RawNFSv4:
        def __init__(self, *args):
            calls.append(args)
            self.client = None
            self.port = args[1]

        def connect(self):
            self.client = object()

    monkeypatch.setattr(PROTOCOL_MODULE, "NFSv4", RawNFSv4)
    monkeypatch.setattr(PROTOCOL_MODULE, "Portmap", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("rpcbind used")))
    protocol = make_protocol()
    assert protocol.connect_nfs() is protocol.nfs
    assert calls == [("192.0.2.1", 2049, 5, protocol.auth)]
    assert protocol.port == 2049


def test_nfsv4_full_connection_skips_rpcbind_and_mount(monkeypatch):
    class RawNFSv4:
        def __init__(self, *args):
            self.client = None
            self.port = args[1]

        def connect(self):
            self.client = object()

    monkeypatch.setattr(PROTOCOL_MODULE, "NFSv4", RawNFSv4)
    monkeypatch.setattr(PROTOCOL_MODULE, "Portmap", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("rpcbind used")))
    monkeypatch.setattr(PROTOCOL_MODULE, "Mount", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("MOUNT used")))
    protocol = make_protocol()
    assert protocol.create_conn_obj()
    assert protocol.nfs.client is not None


def test_nfsv3_discovers_raw_backend_through_rpcbind(monkeypatch):
    class Portmap:
        def getport(self, program, version):
            return 2049

    calls = []

    class RawNFSv3:
        def __init__(self, *args):
            calls.append(args)
            self.client = None
            self.port = args[1]

        def connect(self):
            self.client = object()

    monkeypatch.setattr(PROTOCOL_MODULE, "NFSv3", RawNFSv3)
    protocol = make_protocol(version=3)
    protocol.portmap = Portmap()
    protocol.connect_nfs()
    assert calls == [("192.0.2.1", 2049, 5, protocol.auth)]


def test_nfsv3_enumerates_all_rpcbind_nfs_versions():
    class Portmap:
        @staticmethod
        def dump():
            return (
                {"program": PROTOCOL_MODULE.NFS_PROGRAM, "version": 3},
                {"program": PROTOCOL_MODULE.NFS_PROGRAM, "version": 4},
                {"program": 100005, "version": 3},
            )

    protocol = make_protocol(version=3)
    protocol.portmap = Portmap()
    protocol.try_root_escape = lambda: False
    protocol.enum_host_info()
    assert protocol.nfs_versions == {3, 4}
    assert protocol.db.hosts[-1][3] == {3, 4}


def test_nfsv3_enumeration_survives_unavailable_data_and_mount_services(monkeypatch):
    class RawPortmap:
        def __init__(self, *args, **kwargs):
            self.client = None

        def connect(self):
            self.client = object()

        @staticmethod
        def dump():
            return (
                {"program": PROTOCOL_MODULE.NFS_PROGRAM, "version": 3},
                {"program": PROTOCOL_MODULE.NFS_PROGRAM, "version": 4},
            )

        @staticmethod
        def getport(program, version):
            return 2049

    monkeypatch.setattr(PROTOCOL_MODULE, "Portmap", RawPortmap)
    monkeypatch.setattr(PROTOCOL_MODULE, "Mount", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("MOUNT used")))
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSv3", lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionError("NFSv3 unavailable")))
    protocol = make_protocol(version=3)
    protocol.port = None
    assert protocol.create_conn_obj()
    assert protocol.port == 111
    protocol.enum_host_info()
    assert protocol.nfs_versions == {3, 4}
    assert protocol.db.hosts[-1][3] == {3, 4}


def test_host_output_includes_enumerated_and_selected_versions():
    protocol = make_protocol(version=3)
    protocol.nfs_versions = {4, 3}
    protocol.print_host_info()
    assert "Supported NFS versions: (3, 4) NFSv3 sys" in protocol.logger.messages[-1]


def test_nfsv3_auth_none_is_used_for_mount_and_nfs(monkeypatch):
    class RawPortmap:
        def __init__(self, *args, **kwargs):
            pass

        def connect(self):
            pass

        def getport(self, program, version):
            return 2049 if program == PROTOCOL_MODULE.NFS_PROGRAM else 20048

    class RawMount:
        program = 100005
        program_version = 3

        def __init__(self, host, port, timeout, auth):
            self.auth = auth
            self.client = None

        def connect(self):
            self.client = object()

        def mnt(self, share):
            assert self.auth is None
            return {"status": 0, "mountinfo": {"fhandle": b"root"}}

    class RawNFSv3:
        def __init__(self, host, port, timeout, auth):
            assert auth is None
            self.client = None
            self.port = port

        def connect(self):
            self.client = object()

    monkeypatch.setattr(PROTOCOL_MODULE, "Portmap", RawPortmap)
    monkeypatch.setattr(PROTOCOL_MODULE, "Mount", RawMount)
    monkeypatch.setattr(PROTOCOL_MODULE, "NFSv3", RawNFSv3)
    protocol = make_protocol(version=3, auth="none")
    assert protocol.create_conn_obj()
    protocol.connect_nfs()
    assert protocol.root_handle("/export")["mountinfo"]["fhandle"] == b"root"


def test_kerberos_is_established_on_the_raw_backend(monkeypatch):
    calls = []

    class RawNFSv4:
        def __init__(self, host, port, timeout, auth):
            self.auth = auth
            self.client = None
            self.port = port

        def connect(self):
            self.client = object()

        def disconnect(self):
            self.client = None

    class Initiator:
        def __init__(self, host, credentials):
            self.host = host
            self.credentials = credentials

    class Authentication:
        @staticmethod
        def establish(rpc, program, version, initiator, service):
            calls.append((rpc, program, version, initiator, service))
            return "rpcsec-gss"

    monkeypatch.setattr(PROTOCOL_MODULE, "NFSv4", RawNFSv4)
    monkeypatch.setattr(PROTOCOL_MODULE, "RPCSECGSSAuth", Authentication)
    monkeypatch.setitem(sys.modules, "pyNfsClient.kerberos", SimpleNamespace(KerberosInitiator=Initiator))
    protocol = make_protocol(auth="krb5p")
    protocol.try_root_escape = lambda: True
    assert protocol.kerberos_login("NFS.TEST", "nfsclient", password="secret", kdcHost="192.0.2.2")
    assert calls[0][:3] == (protocol.nfs, PROTOCOL_MODULE.NFS_PROGRAM, 4)
    assert calls[0][3].credentials["realm"] == "NFS.TEST"
    assert calls[0][4] == "krb5p"
    assert protocol.nfs.auth == "rpcsec-gss"


def test_nfsv4_share_path_resolves_through_raw_lookup():
    class RawNFS:
        def root_filehandle(self, auth=None):
            assert auth is protocol.rpc_auth
            return b"root"

        def lookup(self, file_handle, component, auth=None):
            assert auth is protocol.rpc_auth
            return {
                "status": 0,
                "resok": {"object": {"data": file_handle + b"/" + component.encode()}},
            }

    protocol = make_protocol(share="/export/data")
    protocol.nfs = RawNFS()
    assert protocol.root_handle("/export/data") == {
        "status": 0,
        "mountinfo": {"fhandle": b"root/export/data"},
    }


def test_root_escape_validation_uses_the_shared_raw_backend():
    class RawNFS:
        def getattr(self, file_handle, auth=None):
            assert auth is protocol.rpc_auth
            return {"status": 0, "attributes": {"type": 2}}

        def readdir(self, file_handle, auth=None):
            assert auth is protocol.rpc_auth
            return {"status": 0, "resok": {}}

    protocol = make_protocol()
    protocol.nfs = RawNFS()
    protocol.exports = lambda: [("/", ["Everyone"])]
    protocol.root_handle = lambda share: {"status": 0, "mountinfo": {"fhandle": b"export"}}
    protocol.get_root_handles = lambda file_handle: [b"forged"]
    assert protocol.try_root_escape() is True
    assert protocol.escape_share == "/"
    assert protocol.escape_fh == b"forged"


def test_nfsv4_named_owner_does_not_replace_auth_sys_numeric_uid():
    class RawNFS:
        def getattr(self, file_handle, auth=None):
            assert auth is protocol.rpc_auth
            return {
                "status": 0,
                "attributes": {"uid": "root@nfs.test", "gid": "root@nfs.test"},
            }

        def access(self, file_handle, access, auth=None):
            assert auth is protocol.rpc_auth
            return {"status": 0, "resok": {"access": access}}

    protocol = make_protocol()
    protocol.nfs = RawNFS()
    assert protocol.list_dir(b"root", "/", recurse=0)[0]["uid"] == "root@nfs.test"
    assert protocol.auth["uid"] == 0
    assert protocol.auth["gid"] == 0


def test_nfsv4_named_owner_is_separated_from_permissions_in_output():
    protocol = make_protocol()
    protocol.update_auth = lambda file_handle: None
    protocol.get_permissions = lambda file_handle: (True, True, False)
    protocol.print_directory(
        [
            {
                "name": b"readme.txt",
                "name_attributes": {
                    "present": True,
                    "attributes": {"uid": "nfsclient@nfs.test", "type": 1, "size": 0},
                },
                "name_handle": {
                    "present": True,
                    "handle": {"data": b"file"},
                },
            }
        ],
        "/nfsclient",
    )
    assert "nfsclient@nfs.test -rw-" in protocol.logger.messages[-1]
    assert protocol.logger.messages[-1].endswith("/nfsclient/readme.txt")


def test_print_directory_restores_directory_identity_between_entries():
    class RawNFS:
        calls = []
        owners = {b"one": (1000, 100), b"two": (2000, 200)}

        def getattr(self, file_handle, auth=None):
            self.calls.append(("getattr", file_handle, auth["uid"], auth["gid"]))
            uid, gid = self.owners[file_handle]
            return {"status": 0, "attributes": {"uid": uid, "gid": gid}}

        def access(self, file_handle, access, auth=None):
            self.calls.append(("access", file_handle, auth["uid"], auth["gid"]))
            return {"status": 0, "resok": {"access": access}}

    protocol = make_protocol()
    protocol.auth.update({"uid": 500, "gid": 50})
    protocol.nfs = RawNFS()
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

    assert RawNFS.calls == [
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
    monkeypatch.setattr(protocol, "format_directory", lambda response: [])
    protocol.nfs = SimpleNamespace(readdirplus=lambda file_handle, auth=None: {})
    handles = protocol.get_root_handles(b"\x01\x00\x00\x4d" + b"12345678")
    assert len(handles) == 18
    assert handles[2][20:24] == b"\x00\x01\x00\x00"
    assert handles[-1][20:24] == b"\x0f\x01\x00\x00"


def test_netexec_contains_no_facade_or_protocol_adapter():
    source = PROTOCOL_PATH.read_text()
    assert "NFSClient" not in source
    assert "NFSProtocolClient" not in source
    assert not (Path(__file__).parents[1] / "nxc" / "protocols" / "nfs" / "client.py").exists()


@pytest.mark.parametrize("version", [3, 4])
def test_uid_and_gid_changes_are_passed_to_each_raw_call(version):
    calls = []

    class RawNFS:
        def getattr(self, file_handle, auth=None):
            calls.append(("getattr", file_handle, auth["uid"], auth["gid"]))
            uid, gid = (1000, 100) if file_handle == b"root" else (2000, 200)
            return {"status": 0, "attributes": {"uid": uid, "gid": gid}}

        def lookup(self, file_handle, name, auth=None):
            calls.append(("lookup", file_handle, auth["uid"], auth["gid"]))
            return {
                "status": 0,
                "resok": {
                    "object": {"data": b"file"},
                    "obj_attributes": {"attributes": {"type": PROTOCOL_MODULE.NF3REG}},
                },
            }

        def read(self, file_handle, offset, auth=None):
            calls.append(("read", file_handle, auth["uid"], auth["gid"]))
            return {"status": 0, "resok": {"data": b"data", "eof": True}}

    protocol = make_protocol(version=version)
    protocol.args.cat = "file"
    protocol.nfs = RawNFS()
    protocol.connect_nfs = lambda: protocol.nfs
    protocol.selected_root_handle = lambda: b"root"

    protocol.cat()

    assert calls == [
        ("getattr", b"root", 0, 0),
        ("lookup", b"root", 1000, 100),
        ("getattr", b"file", 1000, 100),
        ("read", b"file", 2000, 200),
    ]


def test_auth_sys_disconnect_delegates_all_state_cleanup_to_raw_client():
    class RawNFS:
        @property
        def opened(self):
            raise AssertionError("current-principal state inspected")

        def disconnect(self):
            self.disconnected = True

    protocol = make_protocol()
    protocol.nfs = RawNFS()
    protocol.nfs.disconnected = False

    protocol.disconnect()

    assert protocol.nfs.disconnected


def test_gss_disconnect_closes_state_before_destroying_context(monkeypatch):
    events = []

    class Authentication:
        def destroy(self, rpc, program, version):
            events.append(("destroy", rpc, program, version))

    class RawNFS:
        opened = {b"file": object()}

        def close_handle(self, file_handle, auth=None):
            events.append(("close", file_handle, auth))

        def disconnect(self):
            events.append(("disconnect",))

    monkeypatch.setattr(PROTOCOL_MODULE, "RPCSECGSSAuth", Authentication)
    protocol = make_protocol(auth="krb5")
    protocol.rpc_auth = Authentication()
    protocol.nfs = RawNFS()

    protocol.disconnect()

    assert events == [
        ("close", b"file", protocol.rpc_auth),
        ("destroy", protocol.nfs, PROTOCOL_MODULE.NFS_PROGRAM, 4),
        ("disconnect",),
    ]
