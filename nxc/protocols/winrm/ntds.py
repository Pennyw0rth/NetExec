"""DiskShadow helpers for WinRM --ntds vss."""

import re

from impacket import winregistry

_ALIAS_LINE_RE = re.compile(
    r"^\s*->\s+%(?P<alias>[^%]+)%\s+=\s+\{(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}",
    re.IGNORECASE | re.MULTILINE,
)

# DiskShadow may print the alias in two formats.
_ALIAS_ENVVAR_RE = re.compile(
    r"^\s*Alias\s+(?P<alias>\S+)\s+for\s+shadow\s+ID\s+\{(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}\s+set\s+as\s+environment\s+variable",
    re.IGNORECASE | re.MULTILINE,
)

# DiskShadow can return success without exposing the snapshot.
EXPOSE_CONFIRM_RE = re.compile(
    r"(?im)^[ \t]*the[ \t]+shadow[ \t]+copy[ \t]+was[ \t]+successfully[ \t]+exposed[ \t]+as[ \t]+([A-Za-z]):\\\.[ \t\r]*$"
)

# Confirm that the exact snapshot GUID was deleted.
CLEANUP_DELETING_RE = re.compile(
    r"deleting shadow copy \{([^}]+)\}\.\.\.", re.IGNORECASE
)
CLEANUP_COUNT_RE = re.compile(r"1 shadow cop(?:y|ies) deleted", re.IGNORECASE)

_CRLF = "\r\n"


def parse_alias_guid(stdout: str, alias: str) -> str | None:
    """Return the snapshot GUID for the alias, or None if it is missing.

    Raise ValueError if the alias matches more than one GUID.
    """
    guids: set[str] = set()
    for pattern in (_ALIAS_LINE_RE, _ALIAS_ENVVAR_RE):
        for m in pattern.finditer(stdout):
            if m.group("alias").lower() == alias.lower():
                guids.add(m.group("guid").upper())
    if not guids:
        return None
    if len(guids) > 1:
        raise ValueError(
            f"Ambiguous: alias %{alias}% resolved to {len(guids)} distinct GUIDs"
        )
    return guids.pop()


def read_ntds_path(system_hive: str) -> str | None:
    """Read the configured NTDS database path from a saved SYSTEM hive."""
    reg = winregistry.get_registry_parser(system_hive, False)
    current = reg.getValue("\\Select\\Current")
    if current is None:
        return None
    value = reg.getValue(f"\\ControlSet{current[1]:03d}\\Services\\NTDS\\Parameters\\DSA Database file")
    if value is None:
        return None
    path = value[1].decode("utf-16le").rstrip("\x00")
    return path if re.match(r"^[A-Za-z]:\\", path) else None


def build_create_script(alias: str, volume: str, drive_letter: str, metadata_path: str) -> str:
    """Build the DiskShadow creation script."""
    lines = [
        "set verbose on",
        "set context persistent nowriters",
        f'set metadata "{metadata_path}"',
        f"add volume {volume} alias {alias}",
        "create",
        f"expose %{alias}% {drive_letter}:",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


def build_cleanup_script(drive_letter: str, shadow_guid: str) -> str:
    """Build the cleanup script for an exposed snapshot."""
    lines = [
        "set verbose on",
        f"unexpose {drive_letter}:",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


def build_delete_only_script(shadow_guid: str) -> str:
    """Build the cleanup script for an unexposed snapshot."""
    lines = [
        "set verbose on",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF
