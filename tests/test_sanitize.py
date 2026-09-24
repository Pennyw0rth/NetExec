import ntpath
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path, PureWindowsPath
import re
from types import SimpleNamespace
from unicodedata import normalize
from unittest.mock import patch

import pytest
from impacket import ntlm
from impacket.ldap import ldapasn1 as ldapasn1_impacket

from nxc.helpers.bloodhound import _add_with_domain, _add_without_domain
from nxc.helpers.misc import sanitize_dns
from nxc.helpers.negotiate_parser import parse_challenge
from nxc.helpers.path import sanitize_path_component
from nxc.parsers.ldap_results import parse_result_attributes


class Logger:
    def __init__(self):
        self.messages = []
        self.extra = {}

    def fail(self, message):
        self.messages.append(message)

    def debug(self, message):
        self.messages.append(message)

    def highlight(self, message):
        self.messages.append(message)

    def display(self, message):
        self.messages.append(message)

    def success(self, message):
        self.messages.append(message)

    def error(self, message):
        self.messages.append(message)


class RaisingLogger:
    def fail(self, message):
        raise RuntimeError(message)


class Unstringable:
    def __str__(self):
        raise ValueError


class Challenge:
    fields = {}

    def __getitem__(self, key):
        return {"TargetInfoFields": b"x", "TargetInfoFields_len": 1}[key]


class AVPairs:
    def __init__(self, pairs):
        self.pairs = pairs

    def __getitem__(self, key):
        return self.pairs.get(key)


class QueryResult:
    def __init__(self, data):
        self.result = data

    def data(self):
        return self.result


class Transaction:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, query, **parameters):
        self.calls.append((query, parameters))
        return QueryResult(self.responses.pop(0))


class SMBItem:
    def __init__(self, name, directory=False):
        self.name = name
        self.directory = directory

    def get_longname(self):
        return self.name

    def is_directory(self):
        return self.directory


class SMBConnection:
    def __init__(self, name):
        self.item = SMBItem(name)
        self.remote_path = None

    def listPath(self, share, path):
        return [self.item]

    def getFile(self, share, remote_path, callback, shareAccessMode=None):
        self.remote_path = remote_path
        callback(b"content")


class RecursiveSMBConnection:
    def __init__(self):
        self.remote_path = None

    def listPath(self, share, path):
        if path == ntpath.join("root", "*"):
            return [SMBItem(r"C:\outside", directory=True)]
        return [SMBItem("proof.txt")]

    def getFile(self, share, remote_path, callback, shareAccessMode=None):
        self.remote_path = remote_path
        callback(b"content")


class EnumerationSMBConnection:
    def getSMBServer(self):
        return SimpleNamespace(get_socket=lambda: SimpleNamespace(getsockname=lambda: ("192.0.2.10", 445)))

    def login(self, username, password):
        return None

    def getServerDNSHostName(self):
        return "HOST/../../evil.example"

    def getServerName(self):
        return "NETBIOS"

    def getServerDNSDomainName(self):
        return "example\n#injected"

    def getServerOS(self):
        return "Windows 11"

    def getServerOSMajor(self):
        return 10

    def getServerOSMinor(self):
        return 0

    def getServerOSBuild(self):
        return 26100

    def logoff(self):
        return None


@pytest.fixture(scope="module")
def smb_class():
    spec = spec_from_file_location("sanitize_test_smb_protocol", Path(__file__).parents[1] / "nxc" / "protocols" / "smb.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.smb


@pytest.mark.parametrize(
    "hostname",
    [
        "server",
        "SRV-01",
        "3com",
        "123",
        "host.example.com",
        "host_name",
        "münchen.example",
        "-odd-",
        "name$@!%^&(),+~`",
        "a" * 253,
    ],
)
def test_sanitize_dns_preserves_safe_and_noncompliant_names(hostname):
    logger = Logger()
    assert sanitize_dns(hostname, logger) == hostname
    assert logger.messages == []


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        (None, "_"),
        ("", "_"),
        (".", "_"),
        ("..", "__"),
        ("host.", "host_"),
        ("host name", "host_name"),
        ("../../pwn", ".._.._pwn"),
        (r"..\..\pwn", ".._.._pwn"),
        ("/tmp/pwn", "_tmp_pwn"),
        (r"C:\temp", "C__temp"),
        ("{output_folder}", "_output_folder_"),
        ("host\uff0fname", "host_name"),
        (b"server", "server"),
    ],
)
def test_sanitize_dns_returns_safe_strings(hostname, expected):
    assert sanitize_dns(hostname, Logger()) == expected


def test_sanitize_dns_replaces_config_and_control_characters():
    logger = Logger()
    sanitized = sanitize_dns("host name\n\x00\x1b#comment;[section]={value}'\"", logger)
    assert sanitized == "host_name____comment__section___value___"
    assert len(logger.messages) == 1
    assert "\n" not in logger.messages[0]
    assert "\x00" not in logger.messages[0]
    assert "\x1b" not in logger.messages[0]
    assert r"\n" in logger.messages[0]
    assert r"\x00" in logger.messages[0]
    assert r"\x1b" in logger.messages[0]


@pytest.mark.parametrize("name", ["CON", "NUL.txt", "PRN", "AUX.log", "COM1", "LPT9.txt", "COM¹.txt", "CONIN$", "CONOUT$"])
def test_sanitize_dns_neutralizes_windows_device_names(name):
    assert sanitize_dns(name, Logger()).startswith("_")


def test_sanitize_dns_bounds_long_values_with_stable_hash():
    name = "é" * 200
    sanitized = sanitize_dns(name, Logger())
    assert len(sanitized.encode("utf-8")) <= 253
    assert sanitized == sanitize_dns(name, Logger())
    assert sanitized != name
    assert len(sanitized.rsplit("_", 1)[1]) == 12


def test_sanitize_dns_replaces_malformed_bytes():
    assert sanitize_dns(b"host\xffname", Logger()) == "host_name"


def test_sanitize_dns_always_returns_a_string():
    assert sanitize_dns(Unstringable(), Logger()) == "_"
    assert sanitize_dns("../host", None) == ".._host"
    assert sanitize_dns("../host", RaisingLogger()) == ".._host"


@pytest.mark.parametrize(
    "hostname",
    ["\n", "host\n", "host\x00name", "host\u202ename", "../../x", r"..\..\x", "{output_folder}", "host name", "\uff23\uff2f\uff2e"],
)
def test_sanitize_dns_postconditions(hostname):
    sanitized = sanitize_dns(hostname, Logger())
    normalized = normalize("NFKC", sanitized)
    normalized_stem = normalized.split(".", 1)[0].upper()
    assert isinstance(sanitized, str)
    assert sanitized
    assert len(sanitized.encode("utf-8")) <= 253
    assert all(character.isprintable() and not character.isspace() for character in sanitized)
    assert not any(character in '<>:"/\\|?*{}[]=#;\'' for character in sanitized)
    assert all(
        normalized_character.isprintable()
        and not normalized_character.isspace()
        and normalized_character not in '<>:"/\\|?*{}[]=#;\''
        for character in sanitized
        for normalized_character in normalize("NFKC", character)
    )
    assert normalized not in (".", "..")
    assert not normalized.endswith(".")
    assert normalized_stem not in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    assert re.fullmatch(r"(?:COM|LPT)[1-9]", normalized_stem) is None
    assert sanitize_dns(sanitized, Logger()) == sanitized


def test_parse_challenge_keeps_dns_and_netbios_names_distinct():
    pairs = AVPairs({
        ntlm.NTLMSSP_AV_HOSTNAME: (0, "NETBIOS_NAME".encode("utf-16le")),
        ntlm.NTLMSSP_AV_DNS_HOSTNAME: (0, "server.example.com".encode("utf-16le")),
        ntlm.NTLMSSP_AV_DNS_DOMAINNAME: (0, "example.com".encode("utf-16le")),
    })
    with patch("nxc.helpers.negotiate_parser.ntlm.NTLMAuthChallenge", return_value=Challenge()), patch("nxc.helpers.negotiate_parser.ntlm.AV_PAIRS", return_value=pairs):
        result = parse_challenge(b"challenge")

    assert result["hostname"] == "NETBIOS_NAME"
    assert result["dns_hostname"] == "server.example.com"
    assert result["domain"] == "example.com"


def test_parse_challenge_handles_missing_names():
    with patch("nxc.helpers.negotiate_parser.ntlm.NTLMAuthChallenge", return_value=Challenge()), patch("nxc.helpers.negotiate_parser.ntlm.AV_PAIRS", return_value=AVPairs({})):
        result = parse_challenge(b"challenge")

    assert result["hostname"] is None
    assert result["dns_hostname"] is None
    assert result["domain"] is None


def test_ldap_dns_hostname_remains_raw_at_parse_boundary():
    entry = ldapasn1_impacket.SearchResultEntry()
    entry["objectName"] = ""
    entry["attributes"][0]["type"] = "dNSHostName"
    entry["attributes"][0]["vals"][0] = "../../evil\n"

    result = parse_result_attributes([entry])

    assert result == [{"dNSHostName": "../../evil\n"}]


@pytest.mark.parametrize(
    ("function", "user_info", "domain", "first_result", "expected"),
    [
        (_add_with_domain, {"username": "HOST' OR 1=1$"}, "EXAMPLE' OR 1=1", [{"c": {"owned": False}}], "HOST' OR 1=1.EXAMPLE' OR 1=1"),
        (_add_without_domain, {"username": "USER' OR 1=1"}, None, [{"c": {"owned": False, "name": "USER' OR 1=1@EXAMPLE"}}], "USER' OR 1=1"),
    ],
)
def test_bloodhound_uses_parameters_for_untrusted_names(function, user_info, domain, first_result, expected):
    transaction = Transaction([first_result, [{"name": expected}]])
    if domain is None:
        function(user_info, transaction, Logger())
    else:
        function(user_info, domain, transaction, Logger())

    assert len(transaction.calls) == 2
    assert all(expected not in query for query, _ in transaction.calls)
    assert transaction.calls[0][1]["user_owned"] == expected
    assert transaction.calls[1][1]["user_owned"] in (expected, "USER' OR 1=1@EXAMPLE")


def test_smb_hosts_file_sanitizes_at_sink_without_mutating_values(tmp_path, smb_class):
    connection = smb_class.__new__(smb_class)
    connection.host = "192.0.2.1"
    connection.hostname = "../../HOST\n"
    connection.targetDomain = "[evil]\n"
    connection.domain = connection.targetDomain
    connection.signing = False
    connection.smbv1 = False
    connection.no_ntlm = False
    connection.is_guest = False
    connection.isdc = False
    connection.null_auth = False
    connection.server_os = "Windows"
    connection.os_arch = 64
    connection.logger = Logger()
    connection.args = SimpleNamespace(generate_hosts_file=str(tmp_path / "hosts"), generate_krb5_file=None)

    result = connection.print_host_info()

    assert result == (connection.host, "../../HOST\n", "[evil]\n")
    assert (tmp_path / "hosts").read_text().splitlines() == ["192.0.2.1     .._.._HOST_._evil__ .._.._HOST_"]


def test_smb_enum_host_info_sanitizes_remote_names(smb_class):
    connection = smb_class.__new__(smb_class)
    connection.conn = EnumerationSMBConnection()
    connection.host = "192.0.2.10"
    connection.hostname = connection.host
    connection.domain = None
    connection.no_ntlm = False
    connection.isdc = False
    connection.os_arch = 0
    connection.smbv1 = False
    connection.kerberos = False
    connection.kdcHost = "192.0.2.10"
    connection.logger = Logger()
    connection.db = SimpleNamespace(add_host=lambda *args: None)
    connection.args = SimpleNamespace(generate_hosts_file=None, generate_krb5_file=None, domain=None, use_kcache=False, local_auth=False)
    connection.is_host_dc = lambda aggressive_check=False: None
    connection._is_signing_required = lambda: False
    connection.get_os_arch = lambda: 64

    connection.enum_host_info()

    assert connection.hostname == "HOST_"
    assert connection.targetDomain == "example__injected"


def test_smb_download_sanitizes_only_the_local_path(tmp_path, smb_class):
    remote_name = r"..\..\escape.txt"
    connection = smb_class.__new__(smb_class)
    connection.conn = SMBConnection(remote_name)
    connection.logger = Logger()
    connection.args = SimpleNamespace(share="SHARE", append_host=False)

    connection.download_folder("root", str(tmp_path), silent=True)

    assert connection.conn.remote_path == ntpath.join("root", remote_name)
    assert (tmp_path / ".._.._escape.txt").read_bytes() == b"content"
    assert not (tmp_path.parent / "escape.txt").exists()


def test_smb_download_sanitizes_recursive_directory_components(tmp_path, smb_class):
    connection = smb_class.__new__(smb_class)
    connection.conn = RecursiveSMBConnection()
    connection.logger = Logger()
    connection.args = SimpleNamespace(share="SHARE", append_host=False)

    connection.download_folder("root", str(tmp_path), recursive=True, silent=True)

    assert connection.conn.remote_path == ntpath.join(r"C:\outside", "proof.txt")
    assert (tmp_path / "C_" / "outside" / "proof.txt").read_bytes() == b"content"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("CON", "_CON"),
        ("NUL.txt", "_NUL.txt"),
        ("../pwn", ".._pwn"),
        (r"..\pwn", ".._pwn"),
        ("{hostname}", "_hostname_"),
        ("host\u202ename", "host_name"),
        ("münchen.example", "münchen.example"),
        ("CON .txt", "_CON .txt"),
    ],
)
def test_sanitize_path_component_handles_cross_platform_names(name, expected):
    assert sanitize_path_component(name) == expected


def test_sanitize_path_component_replaces_malformed_bytes():
    assert sanitize_path_component(b"host\xffname") == "host_name"


@pytest.mark.parametrize("name", ["../../x", r"C:\x", "\uff23\uff2f\uff2e.txt", "name. ", "x\uff0fy", "{output_folder}"])
def test_sanitize_path_component_postconditions(name):
    sanitized = sanitize_path_component(name)
    normalized = normalize("NFKC", sanitized)
    normalized_stem = normalized.split(".", 1)[0].rstrip(" ").upper()
    assert sanitized
    assert len(sanitized.encode("utf-8")) <= 255
    assert all(character.isprintable() for character in sanitized)
    assert not any(character in '<>:"/\\|?*{}' for character in sanitized)
    assert all(
        normalized_character.isprintable() and normalized_character not in '<>:"/\\|?*{}'
        for character in sanitized
        for normalized_character in normalize("NFKC", character)
    )
    assert normalized not in (".", "..")
    assert not normalized.endswith(".")
    assert not normalized[-1].isspace()
    assert normalized_stem not in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    assert re.fullmatch(r"(?:COM|LPT)[1-9]", normalized_stem) is None
    assert sanitize_path_component(sanitized) == sanitized


def test_sanitize_path_component_bounds_long_names_and_preserves_extension():
    sanitized = sanitize_path_component(f"{'a' * 300}.log")
    assert len(sanitized.encode("utf-8")) <= 255
    assert sanitized.endswith(".log")
    assert len(sanitized.rsplit("_", 1)[1].removesuffix(".log")) == 12


def test_sanitize_path_component_keeps_paths_inside_base(tmp_path):
    sanitized = sanitize_path_component("../../outside")
    output = tmp_path / sanitized
    assert output.parent == tmp_path
    assert PureWindowsPath("C:/base", sanitized).parent == PureWindowsPath("C:/base")


def test_sanitize_path_component_is_safe_in_output_template(tmp_path):
    template = str(Path(tmp_path) / "{output_folder}" / sanitize_path_component("{hostname}"))
    assert template.format(output_folder="sam") == str(Path(tmp_path) / "sam" / "_hostname_")


def test_sanitize_path_component_honors_custom_budget():
    sanitized = sanitize_path_component("a" * 300, max_bytes=220)
    assert len(sanitized.encode("utf-8")) <= 220
    assert sanitized == sanitize_path_component("a" * 300, max_bytes=220)


def test_sanitize_path_component_drops_extension_that_exceeds_budget():
    sanitized = sanitize_path_component(f"{'a' * 30}.abcdefghijklmnopqrstuvwx", max_bytes=20)
    assert sanitized != "_"
    assert len(sanitized.encode("utf-8")) <= 20
    assert sanitize_path_component(sanitized, max_bytes=20) == sanitized
