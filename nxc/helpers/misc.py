import random
import string
import re
import inspect
import os

from ipaddress import ip_address


def identify_target_file(target_file):
    with open(target_file) as target_file_handle:
        for i, line in enumerate(target_file_handle):
            if i == 1:
                if line.startswith("<NessusClientData"):
                    return "nessus"
                elif line.endswith("nmaprun>\n"):
                    return "nmap"

    return "unknown"


def gen_random_string(length=10):
    return "".join(random.sample(string.ascii_letters, int(length)))


def validate_ntlm(data):
    allowed = re.compile(r"^[0-9a-f]{32}", re.IGNORECASE)
    return bool(allowed.match(data))


def called_from_cmd_args():
    for stack in inspect.stack():
        if stack[3] == "print_host_info":
            return True
        if stack[3] == "plaintext_login" or stack[3] == "hash_login" or stack[3] == "kerberos_login":
            return True
        if stack[3] == "call_cmd_args":
            return True
    return False


# Stolen from https://github.com/pydanny/whichcraft/
def which(cmd, mode=os.F_OK | os.X_OK, path=None):
    """Find the path which conforms to the given mode on the PATH for a command.

    Given a command, mode, and a PATH string, return the path which conforms to the given mode on the PATH, or None if there is no such file.
    `mode` defaults to os.F_OK | os.X_OK. `path` defaults to the result of os.environ.get("PATH"), or can be overridden with a custom search path.
    Note: This function was backported from the Python 3 source code.
    """

    # Check that a given file can be accessed with the correct mode.
    # Additionally check that `file` is not a directory, as on Windows
    # directories pass the os.access check.
    def _access_check(fn, mode):
        return os.path.exists(fn) and os.access(fn, mode) and not os.path.isdir(fn)

    # If we're given a path with a directory part, look it up directly
    # rather than referring to PATH directories. This includes checking
    # relative to the current directory, e.g. ./script
    if os.path.dirname(cmd):
        if _access_check(cmd, mode):
            return cmd
        return None

    if path is None:
        path = os.environ.get("PATH", os.defpath)
    if not path:
        return None
    path = path.split(os.pathsep)

    files = [cmd]

    seen = set()
    for p in path:
        normdir = os.path.normcase(p)
        if normdir not in seen:
            seen.add(normdir)
            for thefile in files:
                name = os.path.join(p, thefile)
                if _access_check(name, mode):
                    return name


def get_bloodhound_info():
    """
    Detect which BloodHound package is installed (regular or CE) and its version.

    Returns
    -------
        tuple: (package_name, version, is_ce)
            - package_name: Name of the installed package ('bloodhound', 'bloodhound-ce', or None)
            - version: Version string of the installed package (or None if not installed)
            - is_ce: Boolean indicating if it's the Community Edition
    """
    import importlib.metadata
    import importlib.util

    # First check if any BloodHound package is available to import
    if importlib.util.find_spec("bloodhound") is None:
        return None, None, False

    # Try to get version info from both possible packages
    version = None
    package_name = None
    is_ce = False

    # Check for bloodhound-ce first
    try:
        version = importlib.metadata.version("bloodhound-ce")
        package_name = "bloodhound-ce"
        is_ce = True
    except importlib.metadata.PackageNotFoundError:
        # Check for regular bloodhound
        try:
            version = importlib.metadata.version("bloodhound")
            package_name = "bloodhound"

            # Even when installed as 'bloodhound', check if it's actually the CE version
            if version and ("ce" in version.lower() or "community" in version.lower()):
                is_ce = True
        except importlib.metadata.PackageNotFoundError:
            # No bloodhound package found via metadata
            pass

    # In case we can import it but metadata is not working, check the module itself
    if not version:
        try:
            import bloodhound
            version = getattr(bloodhound, "__version__", "unknown")
            package_name = "bloodhound"

            # Check if it's CE based on version string
            if "ce" in version.lower() or "community" in version.lower():
                is_ce = True
                package_name = "bloodhound-ce"
        except ImportError:
            pass

    return package_name, version, is_ce


def detect_if_ip(target):
    try:
        ip_address(target)
        return True
    except Exception:
        return False

