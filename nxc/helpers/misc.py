from enum import Enum
import random
import string
import re
import inspect
import os
from termcolor import colored
from ipaddress import ip_address
from nxc.logger import nxc_logger
from time import strftime, gmtime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps


def threaded_enumeration(items_param="items", max_workers=None, progress_threshold=100, show_progress=True):
    """
    Decorator to add multi-threading support to enumeration methods.

    This decorator transforms a sequential enumeration function into a concurrent one,
    automatically handling threading, progress bars, and result aggregation.

    Args:
        items_param (str): Name of the parameter containing the list of items to enumerate.
                          Default: "items"
        max_workers (int): Maximum number of concurrent threads. If None, uses self.args.threads
                          from the instance, or defaults to 10 if not available. Default: None
        progress_threshold (int): Minimum number of items before showing progress bar.
                                 Set to 0 to always show. Default: 100
        show_progress (bool): Whether to show progress bar. Default: True

    Usage:
        # Use explicit max_workers
        @threaded_enumeration(items_param="usernames", max_workers=20, progress_threshold=50)
        def enumerate_users(self, usernames):
            '''Process a single username and return result'''
            result = self.check_username(username)
            return {"username": username, "valid": result}

        # Or use None to automatically use self.args.threads
        @threaded_enumeration(items_param="usernames", progress_threshold=50)
        def enumerate_users(self, usernames):
            '''Process a single username and return result'''
            result = self.check_username(username)
            return {"username": username, "valid": result}

    The decorated function should:
        1. Accept an iterable as a parameter (name specified by items_param)
        2. Process ONE item from that iterable
        3. Return a result dict or None

    The decorator will:
        1. Extract the items list from function parameters
        2. Call the function once per item in parallel threads
        3. Show progress bar if enabled and threshold met
        4. Return a list of all results (excluding None values)

    Returns:
        list: Aggregated results from all thread executions (None values filtered out)

    Example:
        @threaded_enumeration(items_param="users", max_workers=15)
        def check_users(self, users):
            # This function processes ONE user at a time
            # Called automatically by the decorator for each user in the list
            is_valid = self.kerberos_check(users)
            if is_valid:
                self.logger.highlight(f"Valid: {users}")
                return {"user": users, "valid": True}
            return None

        # Call like normal - the decorator handles threading
        results = connection.check_users(["admin", "user1", "user2"])
        # results = [{"user": "admin", "valid": True}, ...]
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get the instance (self) if it's a method
            instance = args[0] if args else None

            # Extract the items list from parameters
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            if items_param not in bound_args.arguments:
                raise ValueError(
                    f"Parameter '{items_param}' not found in function {func.__name__}. "
                    f"Available parameters: {list(bound_args.arguments.keys())}"
                )

            items = bound_args.arguments[items_param]

            # Validate items is iterable
            if not hasattr(items, "__iter__") or isinstance(items, (str, bytes)):
                raise TypeError(
                    f"Parameter '{items_param}' must be an iterable (list, tuple, etc.), "
                    f"got {type(items).__name__}"
                )

            items_list = list(items)
            total = len(items_list)

            if total == 0:
                return []

            results = []

            # Determine max_workers: use decorator parameter, then self.args.threads, then default 10
            workers = max_workers
            if workers is None:
                if instance and hasattr(instance, "args") and hasattr(instance.args, "threads"):
                    workers = instance.args.threads
                    nxc_logger.debug(f"Using {workers} threads from --threads argument")
                else:
                    workers = 10
                    nxc_logger.debug(f"Using default {workers} threads")

            # Determine if we should show progress
            use_progress = show_progress and total > progress_threshold

            def process_item(item):
                """Process a single item by calling the original function"""
                # Create new args with just the single item
                new_kwargs = bound_args.arguments.copy()
                new_kwargs[items_param] = item

                # Remove 'self' from kwargs if present
                new_kwargs.pop("self", None)

                # Call function with instance if it's a method
                if instance is not None:
                    return func(instance, **new_kwargs)
                else:
                    return func(**new_kwargs)

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(process_item, item): item for item in items_list}

                if use_progress:
                    # Import here to avoid circular imports
                    from rich.progress import Progress
                    from nxc.console import nxc_console

                    with Progress(console=nxc_console) as progress:
                        task = progress.add_task(
                            f"[cyan]Processing {total} {items_param}",
                            total=total
                        )

                        for future in as_completed(futures):
                            try:
                                result = future.result()
                                if result is not None:
                                    results.append(result)
                            except Exception as e:
                                item = futures[future]
                                nxc_logger.error(f"Error processing {item}: {e}")
                            finally:
                                progress.update(task, advance=1)
                else:
                    # No progress bar - just collect results
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result is not None:
                                results.append(result)
                        except Exception as e:
                            item = futures[future]
                            nxc_logger.error(f"Error processing {item}: {e}")

            return results

        return wrapper
    return decorator


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


def d2b(a):
    """
    Function used to convert password property flags from decimal to binary
    format for easier interpretation of individual flag bits.
    """
    tbin = []
    while a:
        tbin.append(a % 2)
        a //= 2

    t2bin = tbin[::-1]
    if len(t2bin) != 8:
        for _x in range(6 - len(t2bin)):
            t2bin.insert(0, 0)
    return "".join([str(g) for g in t2bin])


def convert(low, high, lockout=False):
    """
    Convert Windows FILETIME (64-bit) values to human-readable time strings.

    Windows stores time intervals as 64-bit values representing 100-nanosecond
    intervals since January 1, 1601. This function converts these values to
    readable format like "30 days 5 hours 15 minutes".

    Args:
        low (int): Low 32 bits of the FILETIME value
        high (int): High 32 bits of the FILETIME value
        lockout (bool): If True, treats the value as a lockout duration (simpler conversion)

    Returns:
        str: Human-readable time string (e.g., "42 days 5 hours 30 minutes") or
             special values like "Not Set", "None", or "[-] Invalid TIME"
    """
    time = ""
    tmp = 0

    if (low == 0 and high == -0x8000_0000) or (low == 0 and high == -0x8000_0000_0000_0000):
        return "Not Set"
    if low == 0 and high == 0:
        return "None"

    if not lockout:
        if low != 0:
            high = abs(high + 1)
        else:
            high = abs(high)
            low = abs(low)

        tmp = low + (high << 32)  # convert to 64bit int
        tmp *= 1e-7  # convert to seconds
    else:
        tmp = abs(high) * (1e-7)

    try:
        minutes = int(strftime("%M", gmtime(tmp)))
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp))) - 1
    except ValueError:
        return "[-] Invalid TIME"

    if days > 1:
        time += f"{days} days "
    elif days == 1:
        time += f"{days} day "
    if hours > 1:
        time += f"{hours} hours "
    elif hours == 1:
        time += f"{hours} hour "
    if minutes > 1:
        time += f"{minutes} minutes "
    elif minutes == 1:
        time += f"{minutes} minute "
    return time


def display_modules(args, modules):
    for category, color in {CATEGORY.ENUMERATION: "green", CATEGORY.CREDENTIAL_DUMPING: "cyan", CATEGORY.PRIVILEGE_ESCALATION: "magenta"}.items():
        # Add category filter for module listing
        if args.list_modules and args.list_modules.lower() != category.name.lower():
            continue
        if len([module for module in modules.values() if module["category"] == category]) > 0:
            nxc_logger.highlight(colored(f"{category.name}", color, attrs=["bold"]))
        for name, props in sorted(modules.items()):
            if props["category"] == category:
                nxc_logger.display(f"{name:<25} {props['description']}")


class CATEGORY(Enum):
    ENUMERATION = "Enumeration"
    CREDENTIAL_DUMPING = "Credential Dumping"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
