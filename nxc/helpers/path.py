from pathlib import PurePosixPath


def sanitize_filename(name: str) -> str:
    """Strip path traversal components from an SMB filename.

    Follows the pattern from spider_plus.py — filters '..' and '.' from
    PurePosixPath.parts to prevent directory traversal attacks from
    malicious SMB servers.
    """
    parts = PurePosixPath(name.replace("\\", "/")).parts
    clean = [p for p in parts if p not in ("..", ".", "/")]
    return str(PurePosixPath(*clean)) if clean else ""
