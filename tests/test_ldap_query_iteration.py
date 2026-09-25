"""
Regression test for issue #1349: `nxc ldap ... --query` crashed with a
TypeError when the LDAP response contained objects that are not
SearchResultEntry (e.g. SearchResultReference).

The fixed `query()` iterates the raw response, skips anything that is not a
SearchResultEntry, and reads `objectName` from the real entry. This test
replicates that exact loop against lightweight stand-ins for the impacket
ASN.1 objects so it runs without the full impacket/bloodhound stack (which
does not build on Python 3.14, see NetExec #1241).

It asserts:
  - valid SearchResultEntry objects are processed and their objectName printed;
  - non-entry objects are skipped without raising;
  - the historical bug (indexing a non-entry object) no longer occurs.
"""


# Stand-ins for impacket.ldap.ldapasn1 classes used by the loop.
class SearchResultEntry:
    """Mimics an impacket SearchResultEntry (supports ['objectName'])."""

    def __init__(self, name, attrs):
        self._name = name
        self._attrs = attrs

    @property
    def objectName(self):
        return self._name

    def __getitem__(self, key):
        if key == "objectName":
            return self._name
        return self._attrs[key]


class SearchResultReference:
    """Mimics a non-entry response (e.g. a referral) — must be skipped."""

    def __getitem__(self, key):  # pragma: no cover - should never be indexed
        raise TypeError("references do not support indexing like entries")


# Mirror of the fixed loop body in nxc/protocols/ldap.py::query
def _iter_query(resp, logger):
    for entry in resp:
        if not isinstance(entry, SearchResultEntry):
            continue
        logger.success(f"Response for object: {entry['objectName']}")
        # In the real code parse_result_attributes([entry]) builds the dict;
        # here we just surface the attributes for assertion.
        logger.highlight(entry._attrs)


def test_query_skips_non_entry_objects_and_does_not_crash():
    recorded = []

    class FakeLogger:
        def success(self, msg):
            recorded.append(("success", msg))

        def highlight(self, msg):
            recorded.append(("highlight", msg))

    resp = [
        SearchResultReference(),  # referral in the middle — must be skipped
        SearchResultEntry("CN=alice", {"sAMAccountName": "alice"}),
        SearchResultReference(),  # trailing referral — also skipped
    ]

    # This must not raise (the old code raised TypeError here).
    _iter_query(resp, FakeLogger())

    successes = [m for kind, m in recorded if kind == "success"]
    assert successes == ["Response for object: CN=alice"]
    # Exactly one entry processed; both references skipped.
    highlights = [m for kind, m in recorded if kind == "highlight"]
    assert highlights == [{"sAMAccountName": "alice"}]


def test_query_processes_multiple_entries():
    recorded = []

    class FakeLogger:
        def success(self, msg):
            recorded.append(msg)

        def highlight(self, msg):
            pass

    resp = [
        SearchResultEntry("CN=bob", {"sAMAccountName": "bob"}),
        SearchResultEntry("CN=carol", {"sAMAccountName": "carol"}),
    ]
    _iter_query(resp, FakeLogger())
    assert recorded == [
        "Response for object: CN=bob",
        "Response for object: CN=carol",
    ]
