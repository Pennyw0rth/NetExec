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
                    # Attempt to decode as UTF-8
                    decoded_val = val.decode("utf-8")
                except (UnicodeDecodeError, AttributeError):
                    # If it fails, fall back to hexadecimal representation
                    decoded_val = val.hex() if isinstance(val, bytes) else str(val)
                val_list.append(decoded_val)
            attribute_map[str(attribute["type"])] = val_list if len(val_list) > 1 else val_list[0]
        parsed_response.append(attribute_map)
    return parsed_response
