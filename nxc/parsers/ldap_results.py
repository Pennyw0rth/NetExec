from impacket.ldap import ldapasn1 as ldapasn1_impacket
from uuid import UUID


def parse_result_attributes(ldap_response):
    parsed_response = []
    for entry in ldap_response:
        # SearchResultReferences may be returned
        if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
            continue
        attribute_map = {}
        for attribute in entry["attributes"]:
            val_list = []
            for val in attribute["vals"].components:
                # Typical Byte objects we know how to decode
                if str(attribute["type"]) == "objectGUID":
                    val_decoded = UUID(bytes=val.__bytes__())
                elif str(attribute["type"]) == "objectSid":
                    val_decoded = sid_to_str(val.__bytes__())
                elif str(attribute["type"]) == "dNSProperty":
                    val_decoded = val.__bytes__()
                else:
                    # For the rest we try to decode the value with its encoding
                    try:
                        encoding = val.encoding
                        val_decoded = str(val).encode(encoding).decode("utf-8")
                    except UnicodeDecodeError:
                        # If we can't decode the value, we'll just return the bytes
                        val_decoded = val.__bytes__()
                val_list.append(val_decoded)
            if len(val_list) == 1:
                attribute_map[str(attribute["type"])] = val_list[0]
            else:
                attribute_map[str(attribute["type"])] = val_list
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
