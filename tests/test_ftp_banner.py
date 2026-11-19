"""Regression tests for FTP welcome banner parsing (nxc/protocols/ftp.py).

Background: enum_host_info stripped the reply code with
``line.split("220", 1)[1]``. An FTP multiline reply is ``220-first line``,
zero or more continuation lines that carry no code at all, then ``220 last
line`` (RFC 959 4.2), so a continuation line has no ``220`` to split on and the
lookup raised ``IndexError: list index out of range``. Servers that did not
crash still kept the ``-`` separator in the banner and lost the line breaks.
"""

from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join
from types import SimpleNamespace

import pytest


def _load_ftp():
    spec = spec_from_file_location(
        "ftp_banner_test",
        join(dirname(dirname(__file__)), "nxc", "protocols", "ftp.py"),
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ftp


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        ("220 ProFTPD 1.3.5 Server ready", "ProFTPD 1.3.5 Server ready"),
        (
            "220-Welcome to the FTP service\r\nThis is a continuation line\r\n220 Ready",
            "Welcome to the FTP service This is a continuation line Ready",
        ),
        (
            "220-FileZilla Server 1.0\r\n220 Please visit https://filezilla-project.org/",
            "FileZilla Server 1.0 Please visit https://filezilla-project.org/",
        ),
        ("220 one\r\n220 two", "one two"),
        ("220", ""),
        ("", ""),
    ],
)
def test_enum_host_info_parses_banner(banner, expected):
    ftp = _load_ftp()

    obj = ftp.__new__(ftp)
    obj.welcome_banner = ""
    obj.conn = SimpleNamespace(getwelcome=lambda: banner)
    obj.logger = SimpleNamespace(debug=lambda *args, **kwargs: None)

    obj.enum_host_info()

    assert obj.welcome_banner == expected
