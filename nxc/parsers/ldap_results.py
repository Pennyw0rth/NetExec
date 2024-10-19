from impacket.ldap import ldapasn1 as ldapasn1_impacket


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
                try:
                    encoding = val.encoding
                    val_decoded = str(val).encode(encoding).decode("utf-8")
                except UnicodeDecodeError:
                    # If we can't decode the value, we'll just return the bytes
                    val_decoded = val.__bytes__()
                val_list.append(val_decoded)
            attribute_map[str(attribute["type"])] = val_list if len(val_list) > 1 else val_list[0]
        parsed_response.append(attribute_map)
    return parsed_response
