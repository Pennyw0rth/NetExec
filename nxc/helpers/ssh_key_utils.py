"""
SSH utility functions for NetExec.

Provides:
- SSH key type detection
- Retrieval of SSH server allowed authentication methods
- Explicit pKey type instantiation with Paramiko to enhance NetExec's SSH protocol reliability

Author: @Mercury0
"""

import os
import re
import contextlib
import tempfile
import warnings

import paramiko
from paramiko.ssh_exception import PasswordRequiredException, AuthenticationException, SSHException

# Suppress CryptographyDeprecationWarning for DSA keys
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography.hazmat.primitives.asymmetric.dsa")
warnings.filterwarnings("ignore", message="SSH DSA keys are deprecated and will be removed in a future release")

# Import cryptography modules for key type detection
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Module-level constants for key markers
OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
DSA_HEADER = "-----BEGIN DSA PRIVATE KEY-----"
RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
EC_HEADER = "-----BEGIN EC PRIVATE KEY-----"
VALID_HEADERS = ["-----BEGIN", "PRIVATE KEY", "SSH PRIVATE KEY", "OPENSSH", "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2"]

# Helper functions
def log_debug(logger, message: str) -> None:
    if logger:
        logger.debug(message)

def read_file(file_path: str, logger=None) -> bytes | None:
    """Expand the file path, check for existence, and return its bytes content."""
    expanded = os.path.expanduser(file_path)
    if not os.path.isfile(expanded):
        log_debug(logger, f"File not found: {expanded}")
        return None
    try:
        with open(expanded, "rb") as f:
            return f.read()
    except Exception as e:
        log_debug(logger, f"Error reading file {expanded}: {e}")
        return None

def normalize_password(password: str | list[str] | None) -> bytes | None:
    """Convert a password (or list with a password) into bytes, or return None."""
    if not password:
        return None
    if isinstance(password, list):
        return password[0].encode() if password and password[0] else None
    if isinstance(password, str):
        return password.encode() if password else None
    return None

def is_passphrase_error(error_msg: str) -> bool:
    """Return True if the error message indicates a passphrase issue."""
    return any(substr in error_msg.lower() for substr in ["password", "passphrase", "passphrase required"])

def is_incorrect_passphrase_error(error_msg: str) -> bool:
    """Return True if the error message indicates an incorrect passphrase."""
    return any(substr in error_msg.lower() for substr in ["broken checksum", "corrupt data", "bad decrypt"])

# Main functions

def detect_key_type(key_file: str, password: str | None = None, logger=None) -> str | None:
    """
    Detect the type of SSH key using the cryptography module.
    
    Args:
    ----
        key_file: Path to the SSH key file.
        password: Optional passphrase for encrypted keys.
        logger: Optional logger for debug messages.
        
    Returns:
    -------
        str: Description of the key type or an error message if detection fails.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        log_debug(logger, "Cryptography module not available for key type detection")
        return None
        
    key_data = read_file(key_file, logger)
    if key_data is None:
        return "File not found"
    if not key_data.strip():
        log_debug(logger, "Key file is empty")
        return "Empty file"
            
    key_str = key_data.decode("utf-8", errors="ignore")
    if not any(header in key_str for header in VALID_HEADERS):
        log_debug(logger, "Key file does not appear to be a valid SSH key")
        return "Invalid key format"
            
    key_password = normalize_password(password)
            
    try:
        private_key = serialization.load_ssh_private_key(
            key_data, password=key_password, backend=default_backend()
        )
        if isinstance(private_key, rsa.RSAPrivateKey | dsa.DSAPrivateKey):
            return f"{'RSA' if isinstance(private_key, rsa.RSAPrivateKey) else 'DSA'} {private_key.key_size}-bit"
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return f"ECDSA ({private_key.curve.name})"
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return "Ed25519"
        if isinstance(private_key, ed448.Ed448PrivateKey):
            return "Ed448"
        return "Unknown key type"
    except ValueError as e:
        error_msg = str(e).lower()
        if is_passphrase_error(error_msg):
            return "Passphrase-protected key"
        if is_incorrect_passphrase_error(error_msg):
            if any(substr in key_str.lower() for substr in ["encrypted", "proc-type: 4,encrypted"]):
                return "Passphrase-protected key (incorrect password)"
            if OPENSSH_HEADER in key_str:
                return "Passphrase-protected key (incorrect password)"
        log_debug(logger, f"Error parsing key: {e}")
        return "DSA (legacy format - may be unsupported)" if DSA_HEADER in key_str else "Invalid or unsupported key format"
    except Exception as e:
        log_debug(logger, f"Error loading key with cryptography: {e}")
        if DSA_HEADER in key_str:
            return "DSA (legacy format - may be unsupported)"
        if RSA_HEADER in key_str:
            return "RSA (legacy format)"
        if EC_HEADER in key_str:
            return "ECDSA (legacy format)"
        if OPENSSH_HEADER in key_str:
            if any(substr in key_str for substr in ["ssh-dss", "ssh-dsa"]) or any(substr in key_data for substr in [b"ssh-dss", b"ssh-dsa"]):
                return "DSA (OpenSSH format - may be unsupported)"
            return "OpenSSH format"
        return "Unrecognized key format"
                
                
def load_ecdsa_key(key_file: str, password: str | None = None, logger=None) -> paramiko.ECDSAKey | None:
    """
    Load an ECDSA key using various methods, including a cryptography conversion fallback.
    
    Args:
    ----
        key_file: Path to the ECDSA key file.
        password: Optional passphrase for encrypted keys.
        logger: Optional logger for debug messages.
        
    Returns:
    -------
        paramiko.ECDSAKey or None: The loaded key object or None if all methods fail.
    """
    log_debug(logger, f"Attempting to load ECDSA key from: {key_file}")
    expanded_key_path = os.path.expanduser(key_file)
    
    # Read key data as bytes.
    key_data = read_file(expanded_key_path, logger)
    if key_data is None:
        log_debug(logger, "Key data is None.")
        return None

    try:
        key_str = key_data.decode("utf-8", errors="ignore").lstrip()
    except Exception as e:
        log_debug(logger, f"Error decoding key data: {e}")
        return None

    log_debug(logger, f"Key header: {key_str[:30]}...")
    
    # If the key is in OpenSSH format, skip direct Paramiko load.
    if key_str.startswith(OPENSSH_HEADER):
        log_debug(logger, "Key detected as OpenSSH format; using cryptography conversion fallback")
    else:
        # Attempt direct load using Paramiko's ECDSAKey.
        try:
            with open(expanded_key_path, "rb") as f:
                key = paramiko.ECDSAKey.from_private_key(f, password=password or None)
                log_debug(logger, "Direct Paramiko load succeeded.")
                return key
        except Exception as e:
            log_debug(logger, f"Direct Paramiko load failed: {e}")
            if "unpack requires a buffer" in str(e).lower():
                try:
                    with open(expanded_key_path, "rb") as f:
                        key = paramiko.ECDSAKey.from_private_key(f, password=password or None, validate_point=False)
                        log_debug(logger, "Direct load with validate_point succeeded.")
                        return key
                except Exception as e2:
                    log_debug(logger, f"Direct load with validate_point failed: {e2}")

    # Fallback: Use cryptography conversion if available.
    if CRYPTOGRAPHY_AVAILABLE:
        try:
            log_debug(logger, "Attempting cryptography conversion fallback.")
            key_pass = password.encode() if password else None
            crypto_key = serialization.load_ssh_private_key(key_data, password=key_pass, backend=default_backend())
            log_debug(logger, f"Crypto key type: {type(crypto_key)}")
            pem_data = crypto_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            log_debug(logger, f"PEM data length: {len(pem_data)}")
            # Write the PEM data to a temporary file.
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
                temp_file.write(pem_data.decode("utf-8"))
                temp_path = temp_file.name
            log_debug(logger, f"Temporary PEM file created at: {temp_path}")
            try:
                with open(temp_path, "rb") as f_temp:
                    key = paramiko.ECDSAKey.from_private_key(f_temp, password=password or None)
                    log_debug(logger, "Key loaded from PEM conversion.")
                    return key
            finally:
                with contextlib.suppress(Exception):
                    os.unlink(temp_path)
        except PasswordRequiredException:
            log_debug(logger, "Password required for key, but none provided.")
            return None
        except Exception as crypto_e:
            log_debug(logger, f"Cryptography conversion error: {crypto_e}")

    # Last resort: Try loading as an alternative key type.
    try:
        log_debug(logger, "Attempting alternative key type loading.")
        with open(expanded_key_path, "rb") as f:
            try:
                key = paramiko.RSAKey.from_private_key(f, password=password or None)
                log_debug(logger, "Alternative load as RSA succeeded.")
                return key
            except Exception as e:
                log_debug(logger, f"Alternative RSA load failed: {e}")
                f.seek(0)
                try:
                    key = paramiko.DSSKey.from_private_key(f, password=password or None)
                    log_debug(logger, "Alternative load as DSS succeeded.")
                    return key
                except Exception as e2:
                    log_debug(logger, f"Alternative DSS load failed: {e2}")
                    f.seek(0)
                    try:
                        key = paramiko.Ed25519Key.from_private_key(f, password=password or None)
                        log_debug(logger, "Alternative load as Ed25519 succeeded.")
                        return key
                    except Exception as e3:
                        log_debug(logger, f"Alternative load as Ed25519 failed: {e3}")
    except Exception as alt_e:
        log_debug(logger, f"Alternative key type loading exception: {alt_e}")
    
    log_debug(logger, "All ECDSA key loading methods failed, returning None.")
    return None

def get_server_auth_methods(transport, logger=None) -> list:
    """
    Determine the authentication methods supported by the SSH server.
    
    Args:
    ----
        transport: SSH transport object.
        logger: Optional logger for debug messages.
        
    Returns:
    -------
        list: A list of supported authentication methods.
    """
    try:
        auth_methods = transport.auth_none("__probe__")
        log_debug(logger, f"Server reports auth methods: {auth_methods}")
        return auth_methods
    except Exception as e:
        error_msg = str(e).lower()
        log_debug(logger, f"Error probing auth methods: {e}")
        match = re.search(r"allowed types: \[(.*?)\]", error_msg)
        if match:
            methods = [m.strip("'") for m in match.group(1).split(", ")]
            log_debug(logger, f"Extracted auth methods from error: {methods}")
            return methods
        return ["publickey", "password"]

def authenticate_with_key(ssh_client, host, port, username, key_file, password=None, timeout=10, logger=None) -> tuple[bool, str | None]:
    """
    Authenticate to an SSH server using key-based authentication.
    
    Args:
    ----
        ssh_client: Paramiko SSH client object.
        host: Target host.
        port: Target port.
        username: Username to authenticate with.
        key_file: Path to the SSH key file.
        password: Optional passphrase for encrypted keys.
        timeout: Connection timeout.
        logger: Optional logger for debug messages.
        
    Returns:
    -------
        tuple: (True, None) on success, (False, error message) on failure.
    """
    log_debug(logger, f"Attempting key authentication for {host} as {username}")
    expanded_key_path = os.path.expanduser(key_file)
    if not os.path.isfile(expanded_key_path):
        return False, "Key file not found"
    
    key_type = detect_key_type(key_file, password, logger)
    log_debug(logger, f"Detected key type: {key_type}")
    
    if key_type and "DSA" in key_type and "ECDSA" not in key_type:
        log_debug(logger, f"DSA key detected: {key_type}")
        return False, "DSA key auth not supported"
    
    if key_type and "passphrase" in key_type.lower():
        if not password:
            return False, "Key requires passphrase but none provided"
        if "incorrect" in key_type.lower():
            return False, "Incorrect passphrase for key"
    
    if key_type and any(phrase in key_type.lower() for phrase in ["unsupported", "legacy format", "invalid", "unrecognized"]):
        return False, f"Key file format issue: {key_type}. Try converting with: ssh-keygen -p -f keyfile -m pem"
    
    pkey = None
    try:
        with open(expanded_key_path) as f:
            if key_type and "RSA" in key_type:
                log_debug(logger, "Loading RSA key")
                pkey = paramiko.RSAKey.from_private_key(f, password=password or None)
            elif key_type and "DSA" in key_type and "ECDSA" not in key_type:
                log_debug(logger, "Loading DSA key")
                pkey = paramiko.DSSKey.from_private_key(f, password=password or None)
            elif key_type and "ECDSA" in key_type:
                log_debug(logger, "Loading ECDSA key with specialized loader")
                pkey = load_ecdsa_key(key_file, password, logger)
                if pkey is None:
                    log_debug(logger, "ECDSA key loading failed, will use key_filename parameter")
            elif key_type and "Ed25519" in key_type:
                log_debug(logger, "Loading Ed25519 key")
                pkey = paramiko.Ed25519Key.from_private_key(f, password=password or None)
            else:
                log_debug(logger, "Using key_filename parameter as key type couldn't be determined precisely")
                pkey = None
        if pkey is None and CRYPTOGRAPHY_AVAILABLE:
            log_debug(logger, "Attempting to load key with cryptography")
            key_data = read_file(expanded_key_path, logger)
            if key_data is None:
                raise Exception("Key file read error")
            key_pass = password.encode() if password else None
            private_key = serialization.load_ssh_private_key(key_data, password=key_pass, backend=default_backend())
            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
                temp_file.write(pem_data.decode("utf-8"))
                temp_path = temp_file.name
            try:
                with open(temp_path) as f_temp:
                    if isinstance(private_key, rsa.RSAPrivateKey):
                        pkey = paramiko.RSAKey.from_private_key(f_temp)
                    elif isinstance(private_key, dsa.DSAPrivateKey):
                        pkey = paramiko.DSSKey.from_private_key(f_temp)
                    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                        pkey = paramiko.ECDSAKey.from_private_key(f_temp)
                    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                        pkey = paramiko.Ed25519Key.from_private_key(f_temp)
                    else:
                        f_temp.seek(0)
                        pkey = paramiko.PKey.from_private_key(f_temp)
                log_debug(logger, "Successfully loaded key using cryptography conversion")
            finally:
                with contextlib.suppress(Exception):
                    os.unlink(temp_path)
            if not pkey:
                raise Exception("Key conversion failed: pkey not loaded")
    except PasswordRequiredException:
        return False, "Key passphrase required"
    except Exception as e:
        log_debug(logger, f"Error loading key: {e}")
    
    if pkey and logger and hasattr(pkey, "get_fingerprint"):
        try:
            fingerprint = pkey.get_fingerprint().hex()
            log_debug(logger, f"Key fingerprint: {fingerprint}")
        except Exception as e:
            log_debug(logger, f"Error getting key fingerprint: {e}")
    
    try:
        log_debug(logger, f"Connecting to {host}:{port} as {username} with {'loaded key object' if pkey else 'key file'}")
        ssh_client.connect(
            host,
            port=port,
            username=username,
            passphrase=password or None,
            pkey=pkey,
            key_filename=None if pkey else key_file,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=timeout,
        )
        log_debug(logger, f"Successfully authenticated to {host} as {username} using key")
        return True, None
    except AuthenticationException as e:
        error_msg = str(e).lower()
        log_debug(logger, f"Authentication exception: {error_msg}")
        if any(phrase in error_msg for phrase in ["encrypted", "passphrase required", "need passphrase"]):
            return False, "Key passphrase required"
        elif "authentication failed" in error_msg:
            if key_type and "DSA" in key_type and "ECDSA" not in key_type:
                return False, "DSA key authentication failed (DSA keys are deprecated in modern OpenSSH)"
            else:
                return False, ("Key validation error. Possible owner mismatch", "magenta")
        elif any(phrase in error_msg for phrase in ["user not found", "unknown user", "invalid user"]):
            return False, f"User '{username}' does not exist"
        else:
            return False, f"Key authentication failed: {e}"
    except SSHException as e:
        error_msg = str(e).lower()
        log_debug(logger, f"SSH Exception: {error_msg}")
        if "connection reset by peer" in error_msg:
            return False, "Connection reset by server - possible rate limiting or blocking"
        elif "connection timed out" in error_msg:
            return False, "Connection timed out"
        elif any(phrase in error_msg for phrase in ["invalid key", "bad passphrase", "wrong passphrase", "cannot decrypt"]):
            return False, "Invalid passphrase"
        elif "unpack requires a buffer" in error_msg:
            return False, "ECDSA key format issue - try converting with: ssh-keygen -p -f keyfile -m pem"
        else:
            return False, f"SSH error with key authentication: {e}"
    except Exception as e:
        error_str = str(e)
        log_debug(logger, f"Exception during key auth: {error_str}")
        if "q must be exactly" in error_str.lower():
            return False, "Key validation error. Possible owner mismatch"
        elif any(phrase in error_str.lower() for phrase in ["key validation", "invalid key format"]):
            return False, "Key format validation failed - key may not be compatible with server"
        elif "unpack requires a buffer" in error_str.lower():
            return False, "ECDSA key format issue - try converting with: ssh-keygen -p -f keyfile -m pem"
        elif "no such file" in error_str.lower():
            return False, f"Key file not found: {key_file}"
        else:
            return False, f"Error with key authentication: {e}"