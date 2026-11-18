"""Regression tests for hostname resolution (nxc/connection.py).

Background: the system-resolver branch of ``get_host_addr_info`` made a single
``AF_UNSPEC`` ``getaddrinfo`` call with no fallback. glibc fails an ``AF_UNSPEC``
lookup with ``EAI_AGAIN`` when one family's UDP answer is truncated, even though
querying each family on its own succeeds. NetExec then reported the name as
unresolvable, which left ``self.kdcHost`` unset and broke Kerberos operations.

The dnspython branch already queried A and AAAA separately; the fix makes the
system-resolver branch behave the same way.
"""
from socket import AF_INET, AF_INET6, AF_UNSPEC, EAI_AGAIN, gaierror

import pytest

from nxc.connection import get_host_addr_info

HOST = "dc.example.com"


def addrinfo(family, address, canonname=""):
    return (family, 2, 17, canonname, (address, 0) if family == AF_INET else (address, 0, 0, 0))


def fake_getaddrinfo(responses):
    """Build a getaddrinfo stub driven by a {family: result-or-exception} map."""
    def stub(target, port, family, *args, **kwargs):
        outcome = responses[family]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    return stub


def resolve(monkeypatch, responses, force_ipv6=False):
    monkeypatch.setattr("nxc.connection.getaddrinfo", fake_getaddrinfo(responses))
    return get_host_addr_info(HOST, force_ipv6, None, False, 3)


TRUNCATED_AF_UNSPEC = {
    AF_UNSPEC: gaierror(EAI_AGAIN, "Temporary failure in name resolution"),
    AF_INET: [addrinfo(AF_INET, "10.0.0.1", HOST)],
    AF_INET6: [addrinfo(AF_INET6, "2001:db8::1", HOST)],
}


def test_af_unspec_failure_falls_back_to_per_family(monkeypatch):
    """The regression: AF_UNSPEC fails but both families resolve on their own."""
    result = resolve(monkeypatch, TRUNCATED_AF_UNSPEC)
    assert result["host"] == "10.0.0.1"
    assert result["is_ipv6"] is False


def test_af_unspec_failure_falls_back_for_ipv6(monkeypatch):
    result = resolve(monkeypatch, TRUNCATED_AF_UNSPEC, force_ipv6=True)
    assert result["host"] == "2001:db8::1"
    assert result["is_ipv6"] is True


def test_af_unspec_success_is_not_retried(monkeypatch):
    """A working AF_UNSPEC lookup must not trigger the per-family fallback."""
    calls = []
    responses = {AF_UNSPEC: [addrinfo(AF_INET, "10.0.0.1", HOST)]}

    def stub(target, port, family, *args, **kwargs):
        calls.append(family)
        return responses[family]

    monkeypatch.setattr("nxc.connection.getaddrinfo", stub)
    result = get_host_addr_info(HOST, False, None, False, 3)
    assert result["host"] == "10.0.0.1"
    assert calls == [AF_UNSPEC]


def test_first_address_of_each_family_is_kept(monkeypatch):
    """Matches the dnspython branch, which keeps answers[0] per family."""
    responses = {
        AF_UNSPEC: [
            addrinfo(AF_INET, "10.0.0.1", HOST),
            addrinfo(AF_INET, "10.0.0.2"),
            addrinfo(AF_INET6, "2001:db8::1"),
            addrinfo(AF_INET6, "2001:db8::2"),
        ]
    }
    assert resolve(monkeypatch, responses)["host"] == "10.0.0.1"
    assert resolve(monkeypatch, responses, force_ipv6=True)["host"] == "2001:db8::1"


def test_link_local_ipv6_uses_canonical_name(monkeypatch):
    """The canonical name comes from the first record, the only one glibc fills."""
    responses = {
        AF_UNSPEC: [
            addrinfo(AF_INET6, "fe80::1", HOST),
            addrinfo(AF_INET6, "fe80::2"),
        ]
    }
    result = resolve(monkeypatch, responses, force_ipv6=True)
    assert result["host"] == HOST
    assert result["is_link_local_ipv6"] is True


def test_every_family_failing_raises(monkeypatch):
    responses = dict.fromkeys(
        (AF_UNSPEC, AF_INET, AF_INET6),
        gaierror(EAI_AGAIN, "Temporary failure in name resolution"),
    )
    with pytest.raises(Exception, match="The DNS query name does not exist"):
        resolve(monkeypatch, responses)


def test_ip_targets_skip_resolution(monkeypatch):
    def stub(*args, **kwargs):
        raise AssertionError("getaddrinfo must not be called for an IP target")

    monkeypatch.setattr("nxc.connection.getaddrinfo", stub)
    assert get_host_addr_info("10.0.0.1", False, None, False, 3)["host"] == "10.0.0.1"
    assert get_host_addr_info("2001:db8::1", False, None, False, 3)["host"] == "2001:db8::1"


def test_getaddrinfo_by_family_skips_failing_family(monkeypatch):
    from nxc.connection import getaddrinfo_by_family

    responses = {
        AF_INET: gaierror(EAI_AGAIN, "Temporary failure in name resolution"),
        AF_INET6: [addrinfo(AF_INET6, "2001:db8::1", HOST)],
    }
    monkeypatch.setattr("nxc.connection.getaddrinfo", fake_getaddrinfo(responses))
    addresses, canonname = getaddrinfo_by_family(HOST, (AF_INET, AF_INET6))
    assert addresses == {"AF_INET": "", "AF_INET6": "2001:db8::1"}
    assert canonname == HOST
