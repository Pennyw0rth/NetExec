from impacket.ldap import ldapasn1 as ldapasn1_impacket

def parse_result_attributes(ldap_response):
    parsed_response = []
    for entry in ldap_response:
        # SearchResultReferences may be returned
        if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
            continue
        attribute_map = {}
        for attribute in entry["attributes"]:
            attribute_map[str(attribute["type"])] = str(attribute["vals"][0])
        parsed_response.append(attribute_map)
    return parsed_response