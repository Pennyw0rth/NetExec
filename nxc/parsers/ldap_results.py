from impacket.ldap import ldapasn1 as ldapasn1_impacket

def parse_result_attributes(ldap_response):
    parsed_response = []
    for entry in ldap_response:
        # SearchResultReferences may be returned
        if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
            continue
        attribute_map = {}
        for attribute in entry["attributes"]:
            val = [str(val).encode(val.encoding).decode("utf-8") for val in attribute["vals"].components]
            attribute_map[str(attribute["type"])] = val if len(val) > 1 else val[0]
        parsed_response.append(attribute_map)
    return parsed_response