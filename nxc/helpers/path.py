import hashlib
from pathlib import PurePosixPath
import re
from unicodedata import normalize


def sanitize_path_component(name, max_bytes=255):
    """Return one portable, bounded path component from untrusted input."""
    # Reserve enough space for one character and the collision-resistant suffix.
    if max_bytes < 14:
        raise ValueError("max_bytes must be at least 14")

    # Always provide a safe fallback, even for missing or unstringable input.
    try:
        name = name.decode("utf-8", errors="surrogateescape") if isinstance(name, bytes) else str(name) if name is not None else ""
    except Exception:
        name = ""
    if not name:
        return "_"

    # Replace path, formatting, control, and Unicode-equivalent metacharacters.
    unsafe_characters = '<>:"/\\|?*{}'  # Portable filename and format-string metacharacters
    sanitized = "".join(
        character if character.isprintable()
        and character not in unsafe_characters
        and all(
            normalized_character.isprintable() and normalized_character not in unsafe_characters
            for normalized_character in normalize("NFKC", character)
        )
        else "_"
        for character in name
    )

    # Neutralize traversal-only names and Windows-trimmed trailing dots or spaces.
    if normalize("NFKC", sanitized) in (".", ".."):
        sanitized = "_" * len(sanitized)
    while sanitized and (
        sanitized[-1] == "."
        or sanitized[-1].isspace()
        or normalize("NFKC", sanitized[-1]).endswith(".")
        or any(character.isspace() for character in normalize("NFKC", sanitized[-1]))
    ):
        sanitized = f"{sanitized[:-1]}_"

    # Avoid Windows device names, including names followed by an extension.
    normalized_stem = normalize("NFKC", sanitized).split(".", 1)[0].rstrip(" ").upper()
    if normalized_stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"} or re.fullmatch(r"(?:COM|LPT)[1-9]", normalized_stem):
        sanitized = f"_{sanitized}"

    # Bound the byte length with a stable digest while preserving short extensions.
    if len(sanitized.encode("utf-8")) > max_bytes:
        digest = f"_{hashlib.sha256(name.encode('utf-8', errors='surrogatepass')).hexdigest()[:12]}"
        extension = ""
        extension_index = sanitized.rfind(".")
        if (
            extension_index > 0
            and len(sanitized[extension_index:].encode("utf-8")) <= 32
            and len(sanitized[extension_index:].encode("utf-8")) <= max_bytes - len(digest)
        ):
            extension = sanitized[extension_index:]
            sanitized = sanitized[:extension_index]
        byte_length = 0
        truncated = []
        for character in sanitized:
            character_length = len(character.encode("utf-8"))
            if byte_length + character_length > max_bytes - len(digest) - len(extension.encode("utf-8")):
                break
            truncated.append(character)
            byte_length += character_length
        sanitized = f"{''.join(truncated)}{digest}{extension}"

    # Fail closed if a future change violates any output invariant.
    normalized = normalize("NFKC", sanitized)
    normalized_stem = normalized.split(".", 1)[0].rstrip(" ").upper()
    if (
        not sanitized
        or not normalized
        or len(sanitized.encode("utf-8")) > max_bytes
        or normalized in (".", "..")
        or normalized.endswith(".")
        or normalized[-1].isspace()
        or normalized_stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
        or re.fullmatch(r"(?:COM|LPT)[1-9]", normalized_stem)
        or any(
            not character.isprintable()
            or character in unsafe_characters
            or any(
                not normalized_character.isprintable() or normalized_character in unsafe_characters
                for normalized_character in normalize("NFKC", character)
            )
            for character in sanitized
        )
    ):
        return "_"
    return sanitized


def sanitize_filename(name: str) -> str:
    """Strip path traversal components from an SMB filename.

    Follows the pattern from spider_plus.py — filters '..' and '.' from
    PurePosixPath.parts to prevent directory traversal attacks from
    malicious SMB servers.
    """
    parts = PurePosixPath(name.replace("\\", "/")).parts
    clean = [p for p in parts if p not in ("..", ".", "/")]
    return str(PurePosixPath(*clean)) if clean else ""
