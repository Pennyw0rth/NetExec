from impacket.ldap import ldaptypes
from impacket.structure import Structure


# Rights stored in the gMSA membership security descriptor for password reads.
GMSA_READ_PROPERTY = 0x00000010
GMSA_CONTROL_ACCESS = 0x00000100
GMSA_PASSWORD_READ_MASK = GMSA_READ_PROPERTY | GMSA_CONTROL_ACCESS


def add_gmsa_member(security_descriptor, member_sid):
    """Grant a principal the rights required to read a gMSA password."""
    descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(security_descriptor))
    dacl = descriptor["Dacl"]

    if dacl == b"":
        dacl = ldaptypes.ACL()
        dacl["AclRevision"] = 2
        dacl["Sbz1"] = 0
        dacl["Sbz2"] = 0
        dacl.aces = []
        descriptor["Dacl"] = dacl
        descriptor["Control"] |= 0x0004  # SE_DACL_PRESENT

    for ace in dacl.aces:
        if ace["AceType"] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
            continue
        if ace["Ace"]["Sid"].formatCanonical().lower() != member_sid.lower():
            continue

        current_mask = ace["Ace"]["Mask"]["Mask"]
        updated_mask = current_mask | GMSA_PASSWORD_READ_MASK
        if current_mask == updated_mask:
            return bytes(descriptor.getData()), False

        ace["Ace"]["Mask"]["Mask"] = updated_mask
        return bytes(descriptor.getData()), True

    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0
    ace["Ace"] = ldaptypes.ACCESS_ALLOWED_ACE()
    ace["Ace"]["Mask"] = ldaptypes.ACCESS_MASK()
    ace["Ace"]["Mask"]["Mask"] = GMSA_PASSWORD_READ_MASK
    ace["Ace"]["Sid"] = ldaptypes.LDAP_SID()
    ace["Ace"]["Sid"].fromCanonical(member_sid)
    dacl.aces.append(ace)

    return bytes(descriptor.getData()), True


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ("Version", "<H"),
        ("Reserved", "<H"),
        ("Length", "<L"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", ":"),
        ("PreviousPassword", ":"),
        ("QueryPasswordInterval", ":"),
        ("UnchangedPasswordInterval", ":"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)

        endData = self["QueryPasswordIntervalOffset"] if self["PreviousPasswordOffset"] == 0 else self["PreviousPasswordOffset"]

        self["CurrentPassword"] = self.rawData[self["CurrentPasswordOffset"]:][: endData - self["CurrentPasswordOffset"]]
        if self["PreviousPasswordOffset"] != 0:
            self["PreviousPassword"] = self.rawData[self["PreviousPasswordOffset"]:][: self["QueryPasswordIntervalOffset"] - self["PreviousPasswordOffset"]]

        self["QueryPasswordInterval"] = self.rawData[self["QueryPasswordIntervalOffset"]:][: self["UnchangedPasswordIntervalOffset"] - self["QueryPasswordIntervalOffset"]]
        self["UnchangedPasswordInterval"] = self.rawData[self["UnchangedPasswordIntervalOffset"]:]
