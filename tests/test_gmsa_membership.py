from impacket.ldap import ldaptypes

from nxc.protocols.ldap.gmsa import GMSA_PASSWORD_READ_MASK, add_gmsa_member


def make_descriptor(aces):
    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 2
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = aces

    descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR()
    descriptor["Revision"] = b"\x01"
    descriptor["Sbz1"] = b"\x00"
    descriptor["Control"] = 0x8004
    descriptor["Sacl"] = b""
    descriptor["Dacl"] = dacl
    descriptor["OwnerSid"] = b""
    descriptor["GroupSid"] = b""
    return descriptor.getData()


def test_adds_password_reader_ace():
    sid = "S-1-5-21-1-2-3-1104"
    updated, changed = add_gmsa_member(make_descriptor([]), sid)

    descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=updated)
    assert changed is True
    assert descriptor["Dacl"].aces[0]["Ace"]["Sid"].formatCanonical() == sid
    assert descriptor["Dacl"].aces[0]["Ace"]["Mask"]["Mask"] == GMSA_PASSWORD_READ_MASK


def test_is_idempotent():
    sid = "S-1-5-21-1-2-3-1104"
    original, _ = add_gmsa_member(make_descriptor([]), sid)
    updated, changed = add_gmsa_member(original, sid)

    assert changed is False
    assert updated == original
