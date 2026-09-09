import re

from impacket.ldap import ldapasn1 as ldapasn1_impacket
from uuid import UUID

# AD returns ranged attribute names (e.g. "member;range=0-1499") when a
# multi-valued attribute exceeds MaxValRange (default 1500).  Group 1 is
# the base attribute name, group 2 is the range end ("*" on the final page).
RANGE_ATTR_RE = re.compile(r"^(.+);range=\d+-(\d+|\*)$")


def parse_result_attributes(ldap_response):
    parsed_response = []
    for entry in ldap_response:
        # SearchResultReferences may be returned
        if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
            continue
        # Strip ";range=X-Y" suffixes and merge values under the base name.
        accumulated = {}
        for attribute in entry["attributes"]:
            raw_name = str(attribute["type"])
            range_match = RANGE_ATTR_RE.match(raw_name)
            attr_name = range_match.group(1) if range_match else raw_name

            accumulated.setdefault(attr_name, [])
            for val in attribute["vals"].components:
                # Typical Byte objects we know how to decode
                if attr_name == "objectGUID":
                    val_decoded = UUID(bytes=val.__bytes__())
                elif attr_name == "objectSid":
                    val_decoded = sid_to_str(val.__bytes__())
                elif attr_name == "dNSProperty":
                    val_decoded = val.__bytes__()
                else:
                    # For the rest we try to decode the value with its encoding
                    try:
                        encoding = val.encoding
                        val_decoded = str(val).encode(encoding).decode("utf-8")
                    except UnicodeDecodeError:
                        # If we can't decode the value, we'll just return the bytes
                        val_decoded = val.__bytes__()
                accumulated[attr_name].append(val_decoded)

        # Unwrap single-value attributes to match the original API contract
        attribute_map = {name: (vals[0] if len(vals) == 1 else vals) for name, vals in accumulated.items()}
        parsed_response.append(attribute_map)
    return parsed_response


def sid_to_str(sid):
    try:
        # revision
        revision = int(sid[0])
        # count of sub authorities
        sub_authorities = int(sid[1])
        # big endian
        identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
        # If true then it is represented in hex
        if identifier_authority >= 2**32:
            identifier_authority = hex(identifier_authority)

        # loop over the count of small endians
        sub_authority = "-" + "-".join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder="little")) for i in range(sub_authorities)])
        return "S-" + str(revision) + "-" + str(identifier_authority) + sub_authority
    except Exception:
        pass
    return sid
