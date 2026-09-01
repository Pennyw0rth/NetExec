from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join
from unittest.mock import Mock

import pytest


class FakeSocket:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def recv(self, size):
        return next(self.responses, b"")

    def sendall(self, data):
        self.sent.append(data)


@pytest.fixture(scope="module")
def vnc_module():
    spec = spec_from_file_location("vnc_protocol", join(dirname(dirname(__file__)), "nxc", "protocols", "vnc.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_protocol(vnc_module):
    protocol = object.__new__(vnc_module.vnc)
    protocol.host = "192.0.2.1"
    protocol.port = 5900
    protocol.iosettings = Mock()
    protocol.logger = Mock()
    protocol.RFBversion = None
    protocol.noauth = False
    protocol.stype = None
    protocol.target = None
    protocol.conn = None
    return protocol


@pytest.mark.parametrize("responses", [[b""], [b"HTTP/1.1 200"]])
def test_create_conn_obj_rejects_missing_or_malformed_rfb_banner(vnc_module, monkeypatch, responses):
    protocol = make_protocol(vnc_module)
    target = Mock()
    connection = Mock()
    monkeypatch.setattr(vnc_module.socket, "create_connection", Mock(return_value=FakeSocket(responses)))
    monkeypatch.setattr(vnc_module, "RDPTarget", target)
    monkeypatch.setattr(vnc_module, "VNCConnection", connection)

    assert protocol.create_conn_obj() is False
    assert protocol.RFBversion is None
    target.assert_not_called()
    connection.assert_not_called()


def test_create_conn_obj_accepts_fragmented_valid_rfb_banner(vnc_module, monkeypatch):
    protocol = make_protocol(vnc_module)
    target = Mock(return_value=Mock())
    connection = Mock(return_value=Mock())
    monkeypatch.setattr(vnc_module.socket, "create_connection", Mock(return_value=FakeSocket([b"RFB 003", b".008\n", b"\x02", b"\x01\x10"])))
    monkeypatch.setattr(vnc_module, "RDPTarget", target)
    monkeypatch.setattr(vnc_module, "VNCConnection", connection)

    assert protocol.create_conn_obj() is True
    assert protocol.RFBversion == pytest.approx(3.8)
    assert protocol.stype == [1, 16]

    protocol.enum_host_info()

    assert protocol.noauth is True
    target.assert_called_once_with(ip=protocol.host, port=protocol.port)
    connection.assert_called_once()
