import io
import pytest
import textwrap
import paramiko
import logging
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from unittest.mock import MagicMock, patch, mock_open
from nxc.helpers.ssh_key_utils import (
    detect_key_type,
    load_ecdsa_key,
    get_server_auth_methods,
    authenticate_with_key,
    read_file
)
from paramiko import ECDSAKey

logger = logging.getLogger("test")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

@pytest.fixture()
def mock_logger():
    """Fixture to create a mock logger."""
    return MagicMock()

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║            Key Detection                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@pytest.mark.key_detection()
def test_detect_key_type_valid_openssh_rsa(mock_logger):
    """Test detecting a valid RSA key stored in OpenSSH format."""
    mock_openssh_rsa_key = b"""------BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAw9GvspPGXhuzuQTIxDvh52qbnMneC2RDGshJrYMZWUjpb1URkWW9
WDpUTl+/sDEBkx/c/KC9ApSVFD9UKVZJJny8PPuckHE8ft9SIpC+3mvcIdUpXsFdIxoAo0
FMCgwzErzQjC14JpCeJ8U/EfyNCTI97yLRj2m6tUvOHMntzC5wb0XlYIBI2nNQ7JTcwJ9M
REqKOQFD4gHZ6BKpG/y/LaFm2YlMfBqOhtjbXhXwq37fw2cZN+awir55Bu2BSGuWAFLiGz
LjQ1jwLwE7zmphp2zFAmUvSnmbfWYRJWmcUIPDqPX/OUWldIh3wmf2DEl6DSoAsjJbNNru
Tf9jhgX9a1MEvHkw0x/euiWiWGTqH2rNoTw2NI5+M1fmSDtbhd3pnIxvGUq5Pq3C4jLhaM
GL8KVexmrd3jM/bYecsM6+48ycYsdZxVIxbGw91NAWPNzIjaIiuLX+N8YeNAClXnip0RGd
AVWQgU1tHZC7W3jHYCJc618qNkJszTAAHSzUkayLAAAFiKZinJymYpycAAAAB3NzaC1yc2
EAAAGBAMPRr7KTxl4bs7kEyMQ74edqm5zJ3gtkQxrISa2DGVlI6W9VEZFlvVg6VE5fv7Ax
AZMf3PygvQKUlRQ/VClWSSZ8vDz7nJBxPH7fUiKQvt5r3CHVKV7BXSMaAKNBTAoMMxK80I
wteCaQnifFPxH8jQkyPe8i0Y9purVLzhzJ7cwucG9F5WCASNpzUOyU3MCfTERKijkBQ+IB
2egSqRv8vy2hZtmJTHwajobY214V8Kt+38NnGTfmsIq+eQbtgUhrlgBS4hsy40NY8C8BO8
5qYadsxQJlL0p5m31mESVpnFCDw6j1/zlFpXSId8Jn9gxJeg0qALIyWzTa7k3/Y4YF/WtT
BLx5MNMf3rololhk6h9qzaE8NjSOfjNX5kg7W4Xd6ZyMbxlKuT6twuIy4WjBi/ClXsZq3d
4zP22HnLDOvuPMnGLHWcVSMWxsPdTQFjzcyI2iIri1/jfGHjQApV54qdERnQFVkIFNbR2Q
u1t4x2AiXOtfKjZCbM0wAB0s1JGsiwAAAAMBAAEAAAGAH4jTHJUDqwAXD0Kf+koSdSwL51
Hy+i6pR9TdWJ32JRTC0vUGIT4bIewyy3RL8FnUARduhRh1l8bJwzr3mLiWiyYnQkLa0cAK
l/vqxDo/Ip6IEsK7KNFG6HI1jBTl4/BXATt68jgYU02SyqDPKVxcchCvPKWEze2e7bdJeA
Vk0C7iWGkPKV0/Xj6X16GZc0O0CoNegxObFPhrWR44MZOgTf7iC0I7GPlF3p1pplsuKNAD
xPoDa6cw4wcNgnoZCcqZU1Dc72oYC5yfWTyQVBv2IGVSalzJ7b73eET95e6XJTQOyv7d3g
Z7DxWSDncRB0XZjDlEeLwgR8XYzvgn/XTIjefS9wXEiNkMNwQE/D3oCVfac4PpHRRZV9Ow
XppCWf2R/0QoZkNd7MlmEw8WXcOR+75jARjy82qBSPfsMZMSfM28cj2ItzSXgvGnzWk8YH
zhVP4rOlpf7X0ZFgnT1S+dpgrRAw+9KoB4TZDBKXkD1V/J+z3MbwlC/5VffFa+qNuxAAAA
wA/aj4Vh2K7Y6r8N8zp2y4n6JqqyeeeNU3b1A/M+FD++2XGJOgUUyTRFV5URu2vWAEs4cT
z+nb2nlLim1LloK3P0OoojkOeJ05IgDigqlu+YxHUXoG+bPVFyKwIVzGIDPVcqsuJ8M5Ew
mzdwWwTlL0mi6sPpqUGCShJf2ozykgxHsd2yMl7olHxoE27FhJdUQviRGaBld2eiHRP57B
ivNVsEnKyBXO3v92iUpyzPJCuHOxQrgFZv2c1OkuWme0xtXAAAAMEA3HpsPFd85/21EeYA
XP5szsSX1d7fA+rB91XbWG8ypTpUZFyUdbconfaxwDfi3wcCCXCz4soVlMH8OHbrknGwA9
R5UfSU4EuQSMTjOQtHW69MozHEVjejPmpya39WYvCuZ9dcsOT0iKGEULiRBEDKHQQFAiQw
/WEoMrs67wS8MbmceVPjKk1ZGpk8KpHRILjk1ZSU49C08lg87jgchZKp0hqEWUhFYutY92
nFa9QFeCDg5fcPx4NX3E/1/cDJ0ZJFAAAAwQDjXjP75Bi+f+IMXyj99INd+4BIiR7HrSP1
0yED1Xf8OZI4SQ8/cugDO+1mVrP8udaD00kr9Fnn8PUSdBHwdKwJCA5hClHzwt1b4ZhzpK
EVuJkeSvN4O9LZ1SSiaEO2HYBdQorOLqdbfdbvRcn+GER8vE4vS6vA6aaYvNRnbaQySX9O
W3mYaoJ2wyxg6nIWbwok1HMWsCiHVSxXnR57xJprVKa0KWzUN2qxvslx2LsnUtr7wg2a5m
yt60S7k/GImI8AAAAQcm9vdEBjb3p5aG9zdGluZwECAw==
-----END OPENSSH PRIVATE KEY-----"""

    with patch("builtins.open", new_callable=mock_open, read_data=mock_openssh_rsa_key), \
         patch("os.path.isfile", return_value=True):
        result = detect_key_type("/home/kali/Desktop/cozyhost.key", None, mock_logger)
        assert "RSA 3072-bit" in result

@pytest.mark.key_detection()
def test_detect_key_type_file_not_found(mock_logger):
    with patch("os.path.isfile", return_value=False):
        result = detect_key_type("nonexistent.key", None, mock_logger)
        assert result == "File not found"

@pytest.mark.key_detection()
def test_detect_key_type_empty_file(mock_logger):
    with patch("builtins.open", new_callable=mock_open, read_data=b""), \
         patch("os.path.isfile", return_value=True):
        result = detect_key_type("empty.key", None, mock_logger)
        assert result == "Empty file"

@pytest.mark.key_detection()
def test_detect_key_type_invalid_format(mock_logger):
    with patch("builtins.open", new_callable=mock_open, read_data=b"Not a valid key content"), \
         patch("os.path.isfile", return_value=True):
        result = detect_key_type("invalid.key", None, mock_logger)
        assert result == "Invalid key format"

@pytest.mark.key_detection()
def test_detect_key_type_passphrase_protected(mock_logger):
    error = ValueError("This key is password protected")
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=error), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=b"-----BEGIN RSA PRIVATE KEY-----"):
        result = detect_key_type("pass.key", "wrongpass", mock_logger)
        assert result == "Passphrase-protected key"

class FakeTransport:
    def auth_none(self, probe):
        return ["publickey", "password"]

@pytest.mark.key_detection()
def test_detect_key_type_dsa_legacy_error(mock_logger):
    """Test detection of legacy DSA key format when an error occurs."""
    mock_dsa_key = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCDSCXGHSQbV5q3lXeaLfWAymJVbBJbwHjLk0LMgJHRVfr01Xwd
WFUZULDQxJEFfl5LH3FQP13zUDN9BQ2aHsHzOgwLrQmIwX0JF/+1W5liv3YEjhXA
Bk1aYIFnYeBkxF5vfvbV13WmeJYB7g/BkT/MdAF/QH7iae1YLSAqE6aCNQIVALbd
-----END DSA PRIVATE KEY-----"""
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=ValueError("Invalid key")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_dsa_key):
        
        result = detect_key_type("dsa_legacy.key", None, mock_logger)
        assert result == "DSA (legacy format - may be unsupported)"

@pytest.mark.key_detection()
def test_detect_key_type_generic_error(mock_logger):
    """Test handling generic errors during key detection."""
    mock_key = b"""-----BEGIN PRIVATE KEY-----
InvalidKeyContent
-----END PRIVATE KEY-----"""
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Generic error")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_key):
        
        result = detect_key_type("invalid.key", None, mock_logger)
        assert result == "Unrecognized key format"

@pytest.mark.key_detection()
def test_detect_key_type_legacy_formats(mock_logger):
    """Test detection of various legacy key formats."""
    # Legacy RSA
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Error")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=b"-----BEGIN RSA PRIVATE KEY-----\nContent\n-----END RSA PRIVATE KEY-----"):
        
        result = detect_key_type("rsa_legacy.key", None, mock_logger)
        assert result == "RSA (legacy format)"
    
    # Legacy EC
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Error")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"):
        
        result = detect_key_type("ec_legacy.key", None, mock_logger)
        assert result == "ECDSA (legacy format)"
    
    # OpenSSH DSA
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Error")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=b"-----BEGIN OPENSSH PRIVATE KEY-----\nssh-dss AAAAB3NzaC1kc3MAAACBAJlXv5ZegV78\n-----END OPENSSH PRIVATE KEY-----"):
        
        result = detect_key_type("openssh_dsa.key", None, mock_logger)
        assert result == "DSA (OpenSSH format - may be unsupported)"
    
    # Generic OpenSSH
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Error")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=b"-----BEGIN OPENSSH PRIVATE KEY-----\nContent\n-----END OPENSSH PRIVATE KEY-----"):
        
        result = detect_key_type("openssh.key", None, mock_logger)
        assert result == "OpenSSH format"
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Error")), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=b"-----BEGIN UNKNOWN KEY FORMAT-----\nContent\n-----END UNKNOWN KEY FORMAT-----"):
        
        result = detect_key_type("unknown.key", None, mock_logger)
        assert result == "Unrecognized key format"

@pytest.mark.key_detection()
def test_detect_key_type_ecdsa(mock_logger):
    """Test detecting an ECDSA key."""
    mock_ecdsa_key = b"""-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB6najtIwf21ob8fzK3e+MZu0RsGJzEA9dH3n6C2+UK8CSAK6SdD4I
znOz23TGg4RuRcfLltpuP69ijXk2m3g7HfkBgaUwgaICAQEwLAYHKoZIzj0BAQIh
AP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAA
AAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D
2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL
8rzQ4cDGHaKOFFQ
-----END EC PRIVATE KEY-----"""
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key") as mock_load, \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_ecdsa_key):
        
        mock_ec_key = MagicMock()
        mock_ec_key.curve.name = "secp256k1"
        mock_ec_key.__class__ = ec.EllipticCurvePrivateKey
        mock_load.return_value = mock_ec_key
        
        result = detect_key_type("ecdsa.key", None, mock_logger)
        assert result == "ECDSA (secp256k1)"

@pytest.mark.key_detection()
def test_detect_key_type_ed25519(mock_logger):
    """Test detecting an Ed25519 key."""
    mock_ed25519_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACB1jdR7SFkK4SxA0P8tuFQlFjmZTWaX5ldwgK+P/ohEmQAA
AIgVCTFuFQkxbgAAAAtzc2gtZWQyNTUxOQAAACB1jdR7SFkK4SxA0P8tuFQlFjmZ
TWaX5ldwgK+P/ohEmQAAAEAr9aDJAIBzgYnPHDrQM9PnCCvs6v0MBtl4Yoo0ZbXB
cnWN1HtIWQrhLEDQ/y24VCUWOZlNZpfmV3CAr4/+iESZAAAADHVzZXJAZXhhbXBs
ZQECAwQ=
-----END OPENSSH PRIVATE KEY-----"""
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key") as mock_load, \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_ed25519_key):
        
        mock_key = MagicMock()
        mock_key.__class__ = ed25519.Ed25519PrivateKey
        mock_load.return_value = mock_key
        
        result = detect_key_type("ed25519.key", None, mock_logger)
        assert result == "Ed25519"

@pytest.mark.key_detection()
def test_detect_key_type_ed448(mock_logger):
    """Test detecting an Ed448 key."""
    mock_ed448_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAQwAAAAtz
c2gtZWQ0NDgAAAAgJfK0NDi4wWCIoLnJ6bLQz4rKpIbV1FBtCRcXfjeSuRcAAADI
RcM6F0XDOhcAAAALc3NoLWVkNDQ4AAAAICXytDQ4uMFgiKC5yemy0M+KyqSG1dRQ
bQkXF343krkXAAAAQKQ13dAcaDPDP/1xBJyc+T7HobiAfEUQnroKCQAAAATHjBIf
e+k/IbtS28YNxJY9VdkQFjL1FZgSQHpzQRGKhGCJfK0NDi4wWCIoLnJ6bLQz4rKp
IbV1FBtCRcXfjeSuRcAAAA0dXNlckBleGFtcGxlAQID
-----END OPENSSH PRIVATE KEY-----"""
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key") as mock_load, \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_ed448_key):
        
        mock_key = MagicMock()
        mock_key.__class__ = ed448.Ed448PrivateKey
        mock_load.return_value = mock_key
        
        result = detect_key_type("ed448.key", None, mock_logger)
        assert result == "Ed448"

@pytest.mark.key_detection()
def test_detect_key_type_unknown(mock_logger):
    """Test detecting an unknown key type."""
    mock_key = b"""-----BEGIN UNKNOWN PRIVATE KEY-----
SomeRandomContentThatIsNotReallyAKey
-----END UNKNOWN PRIVATE KEY-----"""
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key") as mock_load, \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_key):
        
        mock_unknown_key = MagicMock()
        mock_load.return_value = mock_unknown_key
        
        result = detect_key_type("unknown.key", None, mock_logger)
        assert result == "Unknown key type"

@pytest.mark.key_detection()
def test_detect_key_type_encrypted_by_content(mock_logger):
    """Test detect_key_type when key string contains encryption indicators."""
    # PEM file with "ENCRYPTED" in the header
    encrypted_pem = b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIByjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIS2S+xZ8aXW4CAggA
MBQGCCqGSIb3DQMHBAihHZNEgRLEkASCAWisJ0EgpzYuRDwM9Smq2sweuH5FH8c2
YFNrV7N5GZ1XlyO1gIrj6qW6Xm1mQc9QdO0GBen+IUwSl8iLTHLJ7tFzWruu4u6g
MKVTGaz4BPfwG13M9Lho1azB+6sme1HjwBvNdNJ3NYp6XKy2ZV/9CQgyOkpfFZFU
H9NoZqf7a/j/5/2dH+/Mw02tf+h0HN79QZ/kxCBmMsLFjLaBMPMkGj5QkCRL2UjR
S1pT7QrxIKxkR2RNThxZW5k10WDQQBTAZlv5Ht9O7m4/bYstgvs5sCTF8KWXOcIV
9pUxHRtuWNbNRBw84kkL+eGzEmCa5DgBhtjkfHB5oK5+qZ8+ut+NZ2ru0/vbx0y7
IVIW4PvEwpgPWWVq/elKy+OWmojgK/vJPFRytFR3HQIRbVP5+KWgp8YxtRBcZ3vK
J4yfI5Npbo4t8KE=
-----END ENCRYPTED PRIVATE KEY-----"""

    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=encrypted_pem), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=ValueError("bad decrypt")), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=True):
        
        result = detect_key_type("encrypted.key", "wrongpass", mock_logger)
        assert result == "Passphrase-protected key (incorrect password)"

    # PEM file with "Proc-Type: 4,ENCRYPTED" header (legacy OpenSSH format)
    legacy_encrypted = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,5C6F2B3B3D2D3A393C3F2B387C7E2B3D

MIIEogIBAAKCAQEAwML/WmqYHs6JfbwjQH2fZCcmakaI9pJGAYDt9btSfLqTJMKl
u5rHuMPP2D3yJzHSoBgpBrZUM3THtpKzRDjaf3MSBnO4YX91S32xJgCC9AVRZ8C3
js89LlP8J8hn/z1BKs5CzfQKIyC2FtqCrDgzZA1QLnUFXUFse1I4dAKpPqEJAQKB
gGCfUvdPupk9QIJ/H7lBEXXLRV5Ng9OVX8ZIhIYAG1W4AR1n5YbFTjOo5Rnw+TVj
MFIzfp1xP0+cGnuPan4hf5JiOzvf26J5KRGxlQGD9YOT5UUt9MrMMxGU8SDwxXoK
MHBJi3yXZedl5NcvgOOggUGQCWXl6QlOMeMc3UQDAkB
-----END RSA PRIVATE KEY-----"""
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=legacy_encrypted), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=ValueError("Custom error")), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=True):
        
        result = detect_key_type("legacy_encrypted.key", "wrongpass", mock_logger)
        assert result == "Passphrase-protected key (incorrect password)"

@pytest.mark.key_detection()
def test_detect_key_type_dsa_legacy_value_error(mock_logger):
    """Test detection of legacy DSA key format specifically in the ValueError path."""
    mock_dsa_key = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCDSCXGHSQbV5q3lXeaLfWAymJVbBJbwHjLk0LMgJHRVfr01Xwd
WFUZULDQxJEFfl5LH3FQP13zUDN9BQ2aHsHzOgwLrQmIwX0JF/+1W5liv3YEjhXA
Bk1aYIFnYeBkxF5vfvbV13WmeJYB7g/BkT/MdAF/QH7iae1YLSAqE6aCNQIVALbd
-----END DSA PRIVATE KEY-----"""
    
    specific_value_error = ValueError("Invalid key format or structure")
    
    with patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=specific_value_error), \
         patch("nxc.helpers.ssh_key_utils.contains_passphrase_error", return_value=False), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_dsa_key):
        
        result = detect_key_type("dsa_legacy.key", None, mock_logger)
        assert result == "DSA (legacy format - may be unsupported)"

@pytest.mark.key_detection()
def test_detect_key_type_no_cryptography(mock_logger):
    """Test detect_key_type when cryptography module is not available."""
    mock_key_data = b"-----BEGIN OPENSSH PRIVATE KEY-----\nsome key data\n-----END OPENSSH PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", new_callable=mock_open, read_data=mock_key_data), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False):
        
        result = detect_key_type("test.key", None, mock_logger)
        assert result is None
        mock_logger.debug.assert_called_with("Cryptography module not available for key type detection")

@pytest.mark.key_detection()
def test_detect_key_type_openssh_passphrase_error(mock_logger):
    """Test detect_key_type when OpenSSH key is password-protected but the initial error is not recognized."""
    # OpenSSH encrypted key with the proper header
    openssh_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB+1Q6V55
CziJNf5mY8qdfJAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJf9LiZLVZuvXkrd
oLNcGmYKh3lCpwQEj2EgNoZKnpqcAAAAoJOQFi1wCDnN7TUXxQz0B4lkJnL4fL7VTXvJ
1gDY8B5YQJ2+nJJg89c4jnjxLQ71KwbCm+6phhPYHTPUaBpdBGvlIu3H3NB5x2Ef5uXm
aFGJJ6VoGT/wOGfIggqVIiQg+6Q0M3jovorhbsATy4+i1SANlYs9jIh14X0+oHVXf0JH
xf7LsrKcwtFfN5PUK4Y2y0PjAIRVl54WOpM=
-----END OPENSSH PRIVATE KEY-----"""
    
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=openssh_key), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=ValueError("bad decrypt")), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=True):
        
        result = detect_key_type("openssh_encrypted.key", "wrongpass", mock_logger)
        
        assert result == "Passphrase-protected key (incorrect password)"

@pytest.mark.key_detection()
def test_detect_key_type_dsa_header_direct_return(mock_logger):
    """Test detect_key_type's direct return for DSA headers without going through other error paths."""
    # Create a key with DSA header but trigger a non-passphrase, non-bad decrypt error
    dsa_key = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD0Ot4BKcZ+WwUhgPXtW1WxHWs5TSGz72prGsJnYw3ygw3a0l6/
c1cDEaKi2MtQAk3gR435yv4ab1UkQ30XaOcmkO+7VIEDKSRmDnRwS/sGQzGOrXmF
JSVz3nJP9C5lnj3M0zJEs4jeb7v8HVjz/I7N4oVJ16BqjVJpT7hxS4qwCwIVAPNe
3h6SQNXUHPmNxlBgM4OZfclhAoGBALBqj36breG8r7XRmZAUzEvF9e6GLCxM6tzc
+3+M3y4AxYIvj5RfMdYDutDbFXQOXvFwvskDRfCMn07vKxbG35TiYJ8q4PjfoEr1
CD0jkP4sJx9KVt4R6XmUbQPiLSn6sQfElzdU2dqV86sh8YMvZPwU+AhPZQhWqZZH
FqNkeWvDAoGAPFgUBOZIaaXw2uZ7qhmc3X5+fVIyiuiKrNQQEX3jHwXphC76jUiS
sZmnBxFd/Wtuqxcsd/78CZP/tKsAtzc/XG3Jo8kJpFfTOkJAg+fMYMHVFBk1fIJv
Xu9nIYgKGcZIrNWCtvYBpEPt1uQWI9PIY9ps3dBcpoWJU+DMEqrFJXsCFAI+CiHT
EkJe1qYX8CMiRmXwsVcy
-----END DSA PRIVATE KEY-----"""
    
    # Test that when DSA_HEADER is in the key string and a ValueError occurs,
    # but it's not a passphrase error, we directly return the DSA legacy format message
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=dsa_key), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=ValueError("Custom error not related to passphrase")), \
         patch("nxc.helpers.ssh_key_utils.contains_passphrase_error", return_value=False), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=False):
        
        result = detect_key_type("dsa.key", None, mock_logger)
        assert result == "DSA (legacy format - may be unsupported)"

@pytest.mark.key_detection()
def test_detect_key_type_dsa_header_in_value_error(mock_logger):
    """Test detect_key_type's DSA header detection in the ValueError path."""
    dsa_key = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD0Ot4BKcZ+WwUhgPXtW1WxHWs5TSGz72prGsJnYw3ygw3a0l6/
c1cDEaKi2MtQAk3gR435yv4ab1UkQ30XaOcmkO+7VIEDKSRmDnRwS/sGQzGOrXmF
JSVz3nJP9C5lnj3M0zJEs4jeb7v8HVjz/I7N4oVJ16BqjVJpT7hxS4qwCwIVAPNe
3h6SQNXUHPmNxlBgM4OZfclhAoGBALBqj36breG8r7XRmZAUzEvF9e6GLCxM6tzc
+3+M3y4AxYIvj5RfMdYDutDbFXQOXvFwvskDRfCMn07vKxbG35TiYJ8q4PjfoEr1
CD0jkP4sJx9KVt4R6XmUbQPiLSn6sQfElzdU2dqV86sh8YMvZPwU+AhPZQhWqZZH
FqNkeWvDAoGAPFgUBOZIaaXw2uZ7qhmc3X5+fVIyiuiKrNQQEX3jHwXphC76jUiS
sZmnBxFd/Wtuqxcsd/78CZP/tKsAtzc/XG3Jo8kJpFfTOkJAg+fMYMHVFBk1fIJv
Xu9nIYgKGcZIrNWCtvYBpEPt1uQWI9PIY9ps3dBcpoWJU+DMEqrFJXsCFAI+CiHT
EkJe1qYX8CMiRmXwsVcy
-----END DSA PRIVATE KEY-----"""
    
    # Trigger a ValueError in the load_ssh_private_key function
    # This tests the specific path where we check for DSA_HEADER in the ValueError block
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=dsa_key), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=ValueError("Bad key format")), \
         patch("nxc.helpers.ssh_key_utils.contains_passphrase_error", return_value=False), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=False):
        
        result = detect_key_type("dsa.key", None, mock_logger)
        assert result == "DSA (legacy format - may be unsupported)"

@pytest.mark.key_detection()
def test_detect_key_type_dsa_header_in_exception(mock_logger):
    """Test detect_key_type's DSA header detection in the general Exception path."""
    dsa_key = b"""-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD0Ot4BKcZ+WwUhgPXtW1WxHWs5TSGz72prGsJnYw3ygw3a0l6/
c1cDEaKi2MtQAk3gR435yv4ab1UkQ30XaOcmkO+7VIEDKSRmDnRwS/sGQzGOrXmF
JSVz3nJP9C5lnj3M0zJEs4jeb7v8HVjz/I7N4oVJ16BqjVJpT7hxS4qwCwIVAPNe
3h6SQNXUHPmNxlBgM4OZfclhAoGBALBqj36breG8r7XRmZAUzEvF9e6GLCxM6tzc
+3+M3y4AxYIvj5RfMdYDutDbFXQOXvFwvskDRfCMn07vKxbG35TiYJ8q4PjfoEr1
CD0jkP4sJx9KVt4R6XmUbQPiLSn6sQfElzdU2dqV86sh8YMvZPwU+AhPZQhWqZZH
FqNkeWvDAoGAPFgUBOZIaaXw2uZ7qhmc3X5+fVIyiuiKrNQQEX3jHwXphC76jUiS
sZmnBxFd/Wtuqxcsd/78CZP/tKsAtzc/XG3Jo8kJpFfTOkJAg+fMYMHVFBk1fIJv
Xu9nIYgKGcZIrNWCtvYBpEPt1uQWI9PIY9ps3dBcpoWJU+DMEqrFJXsCFAI+CiHT
EkJe1qYX8CMiRmXwsVcy
-----END DSA PRIVATE KEY-----"""
    
    # Trigger a general Exception in the load_ssh_private_key function
    # This tests the specific path where we check for DSA_HEADER in the Exception block
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=dsa_key), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Some cryptography error")):
        
        result = detect_key_type("dsa.key", None, mock_logger)
        assert result == "DSA (legacy format - may be unsupported)"

@pytest.mark.key_detection()
def test_detect_key_type_pem_rsa_key(mock_logger):
    """Test detecting a PEM format RSA key."""
    mock_pem_rsa_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzJuoU7snv8K6uRLpLbgJGXXB4XFuSRG+4FM6AxwdIBlUxXtn
F07g6ZWn5SWK+sJnKFX1XWYbQgTD4tpZ5A8Z3QdN3XmuKtEwGJJxJjca+7QULLxz
JvUSWGJzYLTjTdK3fhHw+f5I5eW2y7hqVXbZ+I2FrdeUJ2ilO/JMYLEbNHD61duO
/1BwdlAa6/YJKCrnzZ9Wzu+f7iIw33PozHNn2wEqQnPFXu2MjVJvSVcOvhjrMS3w
KnlGldvlKl4Jfx3bHXI3Xowr5M+FutvgHWNMLFbZih+X2HXZl/9JnpTUpctPBZUK
BIPMz+k4fxWYk4Dp3f7v9KpJWZ7vUGMhpPPKTwIDAQABAoIBAHcXILEM1QS7U3mK
mPvNoOqRiHqrKID56H6m6C5yxCwrYFe7fvLQKz2UDSkxZcUYLUcbj14d/uiXRELi
4w7nJf5GoO0y/MdnM/QYYIo68QFsA4BDB0nYVOiGkoSFZD5ZmfzdZKYKXP2aFcTa
xfkBvx/SzsiP4FQHg2xkPzIyBGkj/iVsRQM+oETr9+WJL70kUyFxOx6LALD8AKXs
vNUaZrNZvIm/rN+b+Lpp1zJEibqj/mzm7gnEm1X5+K64iJcPQBdGEsARyYrVzPCJ
b0zlm9czexz6/6/vKLx48pIQ/12nI/iuWKqwOTIe6a3oJIAwRn1MuOvQD9jvqG/W
4sN9kAECgYEA6fXSA4R4/2fUJKKmUkoymDA0CxMJH3bpdzyqSC6Bvwg6SI/Wf8tQ
hZKvmyfszgTKn1MUjRSK4xFBDW+kFQBQAKUkLWZCrDfRN6cWgv6TBbQ49m4CqS9/
ZkQ4t+5lYCTVWuuIm9L2BkH+3Z/3n+BK+uI2LCl91douNBEXDNmoPO8CgYEA36oB
yiqH+PXubZEfLkpK7BEYxR1HJAkS0ZbCCNwG2Kju+G3vl9OIcRnSUzJVt+w9F0Xe
Z8yKF9b0rQPuQ9J01hcb/5s1xiLQOIidLRAxczcNzcfDjDPl36RZM51NS1xF9KgQ
Wvqzcl3rpUUVjL9gPJErmDQxJOTwQAcCyJJXFJECgYEAnMjLJRSGfiJL0cvEk262
9Ir8WjW2iXhKXENVDfxJZ3MT//FW6Cf4dl7BPnZkcZOQ9HYZUVHbQY1bU6a8+vLT
FQQk9zQ5AKKYZrLl8CkIZcRdtLiIFy2+sZZcBkxodPUK8fFCYZwjC3Z9UGwW3dYV
/jJzf0EKhjXv+yNVoLUyT7UCgYEA3sEUkO1b/2BcYx6YUlYOLQCb8mmK8vdL88Fm
0fRKN+jI54HQiQBSEGDM+iaxvPcMKQphzMAwrWuRo1mCxhYO95ioMJ6AFYEpHLdZ
47NvXOZkZsLdKNR1IkR2Mab1jFffd1xEuWBYDdjVpH05vkMuCJNE7S7FJCHUgOzx
OPuV5NECgYBWEzAG0s3fffQYF6YB+EAOpTsxCnkQP3Ukxni81zq/agT9LO3FSbPf
Z2JqiTeEb99d6U6cxpNp8WnLbP4M5OQKrMup4x7+XrFFLMQEhzI/RNj2xwkY8HNY
Q9WgELJGrGVus3TLZ2LlR5EUKqMO5GlTfLfYVMbgLq5jgvW9BGDwrA==
-----END RSA PRIVATE KEY-----"""

    with patch("nxc.helpers.ssh_key_utils.read_file") as mock_read_file, \
         patch("nxc.helpers.ssh_key_utils.RSA_HEADER", b"-----BEGIN RSA PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True):
        
        mock_read_file.return_value = mock_pem_rsa_key
        
        result = detect_key_type("pem_rsa.key", None, mock_logger)
        assert result == "RSA (PEM format)"
        mock_logger.debug.assert_any_call("Detected RSA key in PEM format")

@pytest.mark.key_detection()
def test_detect_key_type_pem_rsa_passphrase_protected(mock_logger):
    """Test detecting a passphrase-protected PEM format RSA key."""
    mock_encrypted_pem_rsa_key = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,94C9C14C7651F45E9682DB502E4FADC1

9A9qLPRaFJB0Cj0u1VH0YRPQ0ZE9bWKg/FE6kA9i20svvtPMP4Rw4QcfMvSS1u1L
MrQkGbWLVlK4pavOk6Y7S9H5UpS3Yl0+ILx9itbLczfJ7MJsLsJdtKY14KBNgGOQ
ZPsdCyJZHHm15v7WBdGv5vJR1RUXpKI+KLvEMjWz4ZWZzl7AbgYD9J5q0/gXp1yL
wDgFe9pDuJ5MGzZ3dODyPMg4hNQKuRcZhoSQJXtQwDk9ia5Ql1eXneVz56FsLEYX
lTwbUbYxUYSRq5uzouFXRvbJFiDNbyFQnIJOCyKlGeM0eS7Jjmy1tJLJPvZt+tkk
N6QE1kwnfPcjpLiIrfpQ3jVM4SzJp7FEF/UVbVSL7hOV3EDJSW52JpNgRN8XqWsc
F4wvRiih/p8B3GWXxFWqrXZ9iKI+E0aHmKhwXvsmHfHjl9L6Ci9BIcscTI0cAs1g
xEBTYYWnFXY9YSbGZf8As+OLbZbmdeJm3SvX0IyOjJ8D9klt3B5dJHYUQWhNhD8l
jWSwC+RyWJ4DoXmkzWx9v4L2/OXhTRMD7OIGHsN3ZK9zZUVr7Q1tMJjJQz1cVmJr
nSv3jpyuGtYn3k1pKjE7ogdPXX5hHEA6r0XJYTqNi8oYGmgRhIIxPPepd1GV0qIv
f9Nc2WEShPRb4QFJxV3+ABVlx5MvSFWOzKXrkUDnVA2Q9QEMeoSMOCqTgLM2mWpn
9cWDcpTJFmGJFGKhiSYQca8a+iyd3qOfiX3tFbKPGK6S4XXegIJFWbz5Z1MUo7P8
yHrQ+g3ZNgE6Y3XcVbCJgZy4MbEzVSZ/Lwx08SQveGJ9hSJBBmFmCIKCJU+WEfDj
yPgKTAWT/H0D6g79WIu4Dw0DawDALXxKCgHqBvEr/KgMOJdRQ+3UchIgQfHOAKaG
RDWf8QkvPzDoKIm+JwO5wgxIeSbxRyF8XKoKKTJQOGOYNJtkypYbDrSNpCa93Hbm
2YHhVtL9lOKPOFecHYlIWDpD6jlLTZ/T8nzvSPXxuT99/tE/7zCFZglPZITgRz02
pAQz6/+o6O8VGdMxmRR8cJJdDL624ifkXbUAJ9HdBm72QKvcTOMxvXIV5rsBGvDh
d76Ht2b+7kLCqoO8D5cpZUMKhcQQNdLDdLCEHFS5/3C2UfmIGBJuHgkTxr3sisHZ
3/GRb6WGjKnLioYMzO73R/iLFy+NhOE8QkSCgUCjyByd9QM+xWkyQfzL0yJaEyGI
MPPiD1A6/Sr1JrUXAU9WYeHUj0aSKAe6Xva+pisLD+RnKUlKb2a7mSTk0TRO/R25
5bQfBkK0i3Bm8YxrVUm7v1AdwOgLjNP4xxL/l1XwYJRUBHn3kR/vEPvN8YP36gFa
LhIHVHhV5JIl/qgWAtEyN1xyNVFCdkKTKlnXxdN7LHbCGwPkLQr3hBLNFhGvXpz/
TYbIED4KvXvDiLKAhx3JcDz62vFUcqxQwVYtfkKGUXCQVUAoJkizt9wHMtZNTu8h
ZSuAjCzGPJIaCdXwCxdQqFZ/8PwimV/Z2MWMvEGw8FJkLQNzJFPmrQfALVzyRgTo
m5AO31iYxnE7F+MpvdE9YEsatH8TJdXgTMbQeXCRMOXaSJVOVoVp8Bf5hRdh7mRZ
-----END RSA PRIVATE KEY-----"""

    with patch("nxc.helpers.ssh_key_utils.read_file") as mock_read_file, \
         patch("nxc.helpers.ssh_key_utils.RSA_HEADER", b"-----BEGIN RSA PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key",
               side_effect=ValueError("Bad password or password required")), \
         patch("nxc.helpers.ssh_key_utils.contains_passphrase_error", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True):
        
        mock_read_file.return_value = mock_encrypted_pem_rsa_key
        
        result = detect_key_type("encrypted_pem_rsa.key", None, mock_logger)
        assert result == "RSA (PEM format, passphrase protected)"
        mock_logger.debug.assert_any_call("Detected RSA key in PEM format")
        mock_logger.debug.assert_any_call("Key is passphrase-protected")

@pytest.mark.key_detection()
def test_detect_key_type_pem_rsa_incorrect_passphrase(mock_logger):
    """Test detecting a PEM format RSA key with incorrect passphrase."""
    mock_encrypted_pem_rsa_key = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,94C9C14C7651F45E9682DB502E4FADC1

9A9qLPRaFJB0Cj0u1VH0YRPQ0ZE9bWKg/FE6kA9i20svvtPMP4Rw4QcfMvSS1u1L
MrQkGbWLVlK4pavOk6Y7S9H5UpS3Yl0+ILx9itbLczfJ7MJsLsJdtKY14KBNgGOQ
ZPsdCyJZHHm15v7WBdGv5vJR1RUXpKI+KLvEMjWz4ZWZzl7AbgYD9J5q0/gXp1yL
-----END RSA PRIVATE KEY-----"""

    error = ValueError("Bad decrypt. Incorrect password?")
    
    with patch("nxc.helpers.ssh_key_utils.read_file") as mock_read_file, \
         patch("nxc.helpers.ssh_key_utils.RSA_HEADER", b"-----BEGIN RSA PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.contains_passphrase_error", return_value=False), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=error), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True):
        
        mock_read_file.return_value = mock_encrypted_pem_rsa_key
        
        result = detect_key_type("encrypted_pem_rsa.key", "wrong_pass", mock_logger)
        
        assert result == "RSA (PEM format, passphrase protected)"
        
        mock_logger.debug.assert_any_call("Detected RSA key in PEM format")
        mock_logger.debug.assert_any_call("Key is passphrase-protected")

@pytest.mark.key_detection()
def test_detect_key_type_openssh_encrypted_incorrect_passphrase(mock_logger):
    """Test detecting an OpenSSH encrypted key with incorrect passphrase."""
    mock_encrypted_openssh_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCPsGyRZh
RTbTJIAmujPWDTAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDkJbw12OYV69OZV
FxXmf4xb9OYW0Z3SmToK0Gq0/A5TAAAAoGYXIhIDSc1zFQZ/PwRpNqyMtQVfQGxvVhk/RC
vXAe3qa8VgUqPbfmqXRkO8RXzGHYlBR9YAMx0MlK1SCpGjgPJBk++LXuCnbI8mLYVLnJB8
Hs/JgJVOQ4lP6GBDKsfnVnFVu9TGz8yQ9fOret+38gxfNzEQI3YZn3Ljxaa2uLJUUZd21P
kS3NpwNLXa4deFd9PHe/wGDXLDPGsRkxI=
-----END OPENSSH PRIVATE KEY-----"""

    error = ValueError("OpenSSH private key passphrase incorrect")
    
    with patch("nxc.helpers.ssh_key_utils.read_file") as mock_read_file, \
         patch("nxc.helpers.ssh_key_utils.OPENSSH_HEADER", b"-----BEGIN OPENSSH PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.contains_passphrase_error", return_value=False), \
         patch("nxc.helpers.ssh_key_utils.contains_incorrect_passphrase_error", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=error), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True):
        
        mock_read_file.return_value = mock_encrypted_openssh_key
        
        result = detect_key_type("encrypted_openssh.key", "wrong_pass", mock_logger)
        assert result == "Passphrase-protected key (incorrect password)"
        mock_logger.debug.assert_any_call("Key is passphrase-protected (incorrect password provided)")

@pytest.mark.key_detection()
def test_detect_pem_format_rsa_key_from_openssh_error(mock_logger):
    """Test detection of a PEM format RSA key when encountering 'not openssh private key' error."""
    mock_pem_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890ABCDEF
-----END RSA PRIVATE KEY-----"""

    error = ValueError("not openssh private key")

    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_pem_key), \
         patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.RSA_HEADER", b"-----BEGIN RSA PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.OPENSSH_HEADER", b"-----BEGIN OPENSSH PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=error), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True):

        result = detect_key_type("pem_rsa.key", None, mock_logger)
        assert result == "RSA (PEM format)"
        mock_logger.debug.assert_any_call("Detected RSA key in PEM format")

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║            Server Allowed Auth Methods                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.server_checks()
def test_get_server_auth_methods_success(mock_logger):
    fake_transport = FakeTransport()
    methods = get_server_auth_methods(fake_transport, mock_logger)
    assert "publickey" in methods
    assert "password" in methods

@pytest.mark.server_checks()
def test_get_server_auth_methods_from_error(mock_logger):
    error = Exception("Authentication failed. allowed types: ['publickey']")
    fake_transport = type("FakeTransport", (), {"auth_none": lambda self, probe: (_ for _ in ()).throw(error)})()
    methods = get_server_auth_methods(fake_transport, mock_logger)
    assert "publickey" in methods

@pytest.mark.server_checks()
def test_get_server_auth_methods_fallback(mock_logger):
    """Test get_server_auth_methods when no auth methods can be extracted from error."""
    error = Exception("Connection refused")
    fake_transport = type("FakeTransport", (), {"auth_none": lambda self, probe: (_ for _ in ()).throw(error)})()
    methods = get_server_auth_methods(fake_transport, mock_logger)

    assert "publickey" in methods
    assert "password" in methods
    assert len(methods) == 2

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║            Key Loading                                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.key_loading()
def test_load_ecdsa_key_valid(mock_logger):
    valid_ecdsa = textwrap.dedent("""\
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
        1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQB6najtIwf21ob8fzK3e+MZu0RsGJz
        EA9dH3n6C2+UK8CSAK6SdD4IznOz23TGg4RuRcfLltpuP69ijXk2m3g7HfkB/q9dV+B9xC
        AJe02nVQTeEB45vbLwn2g19+vjfg6FfXyy3FJrn9dCswfiEMFIwcALijDfJlmKXGJfb5HO
        yEI71U8AAAEIPWXWuz1l1rsAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
        AAAIUEAep2o7SMH9taG/H8yt3vjGbtEbBicxAPXR95+gtvlCvAkgCuknQ+CM5zs9t0xoOE
        bkXHy5babj+vYo15Npt4Ox35Af6vXVfgfcQgCXtNp1UE3hAeOb2y8J9oNffr434OhX18st
        xSa5/XQrMH4hDBSMHAC4ow3yZZilxiX2+RzshCO9VPAAAAQUJSZ0gUFadhHR18Czaixs5T
        chYCALYy4JBTF+DQAaNZHWWk+puV2O5pUjHInUSug/bNcsfIjXadl6JF5LhebNBCAAAACW
        thbGlAa2FsaQEC
        -----END OPENSSH PRIVATE KEY-----""").encode("utf-8")
    
    mock_file = MagicMock()
    mock_file.__enter__.return_value = io.BytesIO(valid_ecdsa)
    mock_ecdsa_key = MagicMock(spec=ECDSAKey)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", return_value=mock_file), \
         patch("os.path.isfile", return_value=True), \
         patch("paramiko.ECDSAKey.from_private_key", return_value=mock_ecdsa_key):
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is not None, "Expected a valid ECDSA key object"
        assert key is mock_ecdsa_key

@pytest.mark.key_loading()
def test_load_ed25519_key(mock_logger):
    """Test loading an Ed25519 key."""
    valid_ed25519 = textwrap.dedent("""\
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACB1jdR7SFkK4SxA0P8tuFQlFjmZTWaX5ldwgK+P/ohEmQAAAJgVCTFuFQkx
        bgAAAAtzc2gtZWQyNTUxOQAAACB1jdR7SFkK4SxA0P8tuFQlFjmZTWaX5ldwgK+P/ohEmQ
        AAAEAr9aDJAIBzgYnPHDrQM9PnCCvs6v0MBtl4Yoo0ZbXBcnWN1HtIWQrhLEDQ/y24VCUW
        OZlNZpfmV3CAr4/+iESZAAAAEXVzZXJAZXhhbXBsZS5ob3N0AQIDBA==
        -----END OPENSSH PRIVATE KEY-----""").encode("utf-8")
    
    mock_file = MagicMock()
    mock_file.__enter__.return_value = io.BytesIO(valid_ed25519)
    mock_ed25519_key = MagicMock(spec=paramiko.Ed25519Key)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ed25519), \
         patch("builtins.open", return_value=mock_file), \
         patch("os.path.isfile", return_value=True), \
         patch("paramiko.Ed25519Key.from_private_key", return_value=mock_ed25519_key):
        
        # Test it through authenticate_with_key which should use the Ed25519 path
        ssh_client = MagicMock()
        with patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Ed25519"):
            success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "ed25519.key", None, 10, mock_logger)
            assert success is True
            assert msg is None

@pytest.mark.key_loading()
def test_load_ecdsa_key_none_data(mock_logger):
    """Test load_ecdsa_key when key data is None."""
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=None):
        key = load_ecdsa_key("/tmp/nonexistent_key", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Key data is None.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_direct_paramiko_error(mock_logger):
    """Test load_ecdsa_key when direct Paramiko load fails."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Normal error")), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Direct Paramiko load failed: Normal error")

@pytest.mark.key_loading()
def test_load_ecdsa_key_unpack_buffer_error(mock_logger):
    """Test load_ecdsa_key with 'unpack requires a buffer' error."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    mock_ecdsa_key = MagicMock(spec=ECDSAKey)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", 
               side_effect=[Exception("unpack requires a buffer"), mock_ecdsa_key]):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is mock_ecdsa_key
        mock_logger.debug.assert_any_call("Direct load with validate_point succeeded.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_unpack_buffer_double_error(mock_logger):
    """Test load_ecdsa_key when both normal and validate_point attempts fail."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", 
               side_effect=[Exception("unpack requires a buffer"), Exception("validate_point error")]), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Direct load with validate_point failed: validate_point error")

@pytest.mark.key_loading()
def test_load_ecdsa_key_password_required(mock_logger):
    """Test load_ecdsa_key when password is required."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=paramiko.PasswordRequiredException()):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Password required for key, but none provided.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_cryptography_error(mock_logger):
    """Test load_ecdsa_key when cryptography conversion fails."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Crypto error")):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Cryptography conversion error: Crypto error")

@pytest.mark.key_loading()
def test_load_ecdsa_key_alternative_rsa_success(mock_logger):
    """Test load_ecdsa_key with successful alternative RSA loading."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    mock_rsa_key = MagicMock(spec=paramiko.RSAKey)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Crypto error")), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is mock_rsa_key
        mock_logger.debug.assert_any_call("Alternative load as RSA succeeded.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_alternative_dss_success(mock_logger):
    """Test load_ecdsa_key with successful alternative DSS loading."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    mock_dss_key = MagicMock(spec=paramiko.DSSKey)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Crypto error")), \
         patch("paramiko.RSAKey.from_private_key", side_effect=Exception("RSA error")), \
         patch("paramiko.DSSKey.from_private_key", return_value=mock_dss_key):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is mock_dss_key
        mock_logger.debug.assert_any_call("Alternative load as DSS succeeded.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_alternative_ed25519_success(mock_logger):
    """Test load_ecdsa_key with successful alternative Ed25519 loading."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    mock_ed25519_key = MagicMock(spec=paramiko.Ed25519Key)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Crypto error")), \
         patch("paramiko.RSAKey.from_private_key", side_effect=Exception("RSA error")), \
         patch("paramiko.DSSKey.from_private_key", side_effect=Exception("DSS error")), \
         patch("paramiko.Ed25519Key.from_private_key", return_value=mock_ed25519_key):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is mock_ed25519_key
        mock_logger.debug.assert_any_call("Alternative load as Ed25519 succeeded.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_all_alternatives_fail(mock_logger):
    """Test load_ecdsa_key when all alternative loading methods fail."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Crypto error")), \
         patch("paramiko.RSAKey.from_private_key", side_effect=Exception("RSA error")), \
         patch("paramiko.DSSKey.from_private_key", side_effect=Exception("DSS error")), \
         patch("paramiko.Ed25519Key.from_private_key", side_effect=Exception("Ed25519 error")):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Alternative load as Ed25519 failed: Ed25519 error")
        mock_logger.debug.assert_any_call("All ECDSA key loading methods failed, returning None.")

@pytest.mark.key_loading()
def test_load_ecdsa_key_alternative_loading_exception(mock_logger):
    """Test load_ecdsa_key when there's an exception in the alternative loading block."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", side_effect=[mock_open(read_data=valid_ecdsa).return_value, Exception("File error")]), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("Direct load error")), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", 
               side_effect=Exception("Crypto error")):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call("Alternative key type loading exception: File error")

@pytest.mark.key_loading()
def test_load_ecdsa_key_decode_error(mock_logger):
    """Test load_ecdsa_key when there's an error decoding the key data."""
    # Create a mock that will raise a UnicodeDecodeError when decode is called
    mock_data = MagicMock()
    decode_error = UnicodeDecodeError("utf-8", b"\xff\xfe\x00\x01", 0, 1, "Invalid start byte")
    mock_data.decode.side_effect = decode_error
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_data):
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is None
        mock_logger.debug.assert_any_call(f"Error decoding key data: {decode_error}")

@pytest.mark.key_loading()
def test_load_ecdsa_key_direct_paramiko_success(mock_logger):
    """Test successful direct loading with Paramiko in load_ecdsa_key."""
    valid_ecdsa = b"-----BEGIN EC PRIVATE KEY-----\nContent\n-----END EC PRIVATE KEY-----"
    mock_ecdsa_key = MagicMock(spec=ECDSAKey)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ecdsa), \
         patch("builtins.open", mock_open(read_data=valid_ecdsa)), \
         patch("paramiko.ECDSAKey.from_private_key", return_value=mock_ecdsa_key):
        
        key = load_ecdsa_key("/tmp/test_ecdsa", None, mock_logger)
        assert key is mock_ecdsa_key
        mock_logger.debug.assert_any_call("Direct Paramiko load succeeded.")

@pytest.mark.key_loading()
def test_direct_dsa_key_loading(mock_logger):
    """Test the direct loading of a DSA key in authenticate_with_key."""    
    from nxc.helpers.ssh_key_utils import log_debug
    test_logger = MagicMock()
    log_debug(test_logger, "Loading DSA key")
    test_logger.debug.assert_called_once_with("Loading DSA key")

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║            Authentication                                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.authentication_checks()
def test_authenticate_with_key_file_not_found(mock_logger):
    # Patch os.path.isfile to return False
    with patch("os.path.isfile", return_value=False):
        success, msg = authenticate_with_key(MagicMock(), "host", 22, "user", "nonexistent.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Key file not found"

@pytest.mark.authentication_checks()
def test_authenticate_with_key_load_error(mock_logger):
    """Test handling key loading errors."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"mock key data"), \
         patch("builtins.open", side_effect=Exception("File open error")), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False), \
         patch.object(ssh_client, "connect", side_effect=Exception("Connect should not be called")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert "Error with key authentication" in msg

@pytest.mark.authentication_checks()
def test_authenticate_with_key_ssh_error(mock_logger):
    """Test SSH connection errors."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.SSHException("SSH connection error")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert "SSH error" in msg

@pytest.mark.authentication_checks()
def test_authenticate_with_key_auth_failure(mock_logger):
    """Test authentication failure."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.AuthenticationException("Authentication failed")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        
        if isinstance(msg, tuple):
            assert "Key validation error" in msg[0]
            assert msg[1] == "magenta"
        else:
            assert "authentication failed" in msg.lower()

@pytest.mark.authentication_checks()
def test_authenticate_with_key_success(mock_logger):
    """Test successful authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA (PEM format)"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key):
        
        ssh_client.connect = MagicMock()
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is True
        assert msg is None

@pytest.mark.authentication_checks()
def test_authenticate_with_key_specific_loading_error(mock_logger):
    """Test specific key loading error scenario."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("paramiko.RSAKey.from_private_key", side_effect=Exception("RSA key loading error")), \
         patch("paramiko.DSSKey.from_private_key", side_effect=Exception("DSS key loading error")), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("ECDSA key loading error")), \
         patch("paramiko.Ed25519Key.from_private_key", side_effect=Exception("Ed25519 key loading error")), \
         patch("nxc.helpers.ssh_key_utils.load_ecdsa_key", return_value=None), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False), \
         patch("builtins.open", return_value=MagicMock()):
        
        ssh_client.connect.side_effect = Exception("Connect should fail")
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert any(s in str(msg) for s in ["key loading error", "Error with key authentication", "Connect should fail"])

@pytest.mark.authentication_checks()
def test_authenticate_dsa_key_not_supported(mock_logger):
    """Test handling of DSA keys that are not supported."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"):
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"

@pytest.mark.authentication_checks()
def test_authenticate_passphrase_required_but_none_provided(mock_logger):
    """Test when key requires passphrase but none is provided."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Passphrase-protected key"):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "protected.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Key requires passphrase but none provided"

@pytest.mark.authentication_checks()
def test_authenticate_incorrect_passphrase(mock_logger):
    """Test when an incorrect passphrase is provided for the key."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Passphrase-protected key (incorrect password)"):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "protected.key", "wrongpass", 10, mock_logger)
        assert success is False
        assert msg == "Incorrect passphrase for key"

@pytest.mark.authentication_checks()
def test_authenticate_key_format_issue(mock_logger):
    """Test when key has format issues like unsupported/legacy format."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Invalid key format"):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "invalid.key", None, 10, mock_logger)
        assert success is False
        assert "Key file format issue" in msg

@pytest.mark.authentication_checks()
def test_authenticate_key_with_cryptography_conversion(mock_logger):
    """Test key authentication using cryptography conversion when initial load fails."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_private_key = MagicMock(spec=rsa.RSAPrivateKey)
    temp_file_mock = MagicMock()
    temp_file_mock.name = "/tmp/mock_temp_file"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("builtins.open", side_effect=Exception("First open fails")), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"valid key data"), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile", return_value=temp_file_mock), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch("os.unlink"):
        
        mock_private_key.__class__ = rsa.RSAPrivateKey
        mock_private_key.private_bytes.return_value = b"-----BEGIN RSA PRIVATE KEY-----\nMockKey\n-----END RSA PRIVATE KEY-----"
        
        with patch("builtins.open", return_value=MagicMock()):
            mock_logger.debug("Attempting to load key with cryptography")
            mock_logger.debug("Successfully loaded key using cryptography conversion")
            
            success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
            assert success is True
            assert msg is None

@pytest.mark.authentication_checks()
def test_authenticate_key_cryptography_conversion_dsa(mock_logger):
    """Test key authentication using cryptography conversion for DSA keys."""
    ssh_client = MagicMock()
    MagicMock()
    MagicMock()
    temp_file_mock = MagicMock()
    temp_file_mock.name = "/tmp/mock_temp_file"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"

@pytest.mark.authentication_checks()
def test_authenticate_key_cryptography_conversion_ecdsa(mock_logger):
    """Test key authentication using cryptography conversion for ECDSA keys."""
    ssh_client = MagicMock()
    mock_ecdsa_key = MagicMock()
    mock_private_key = MagicMock(spec=ec.EllipticCurvePrivateKey)
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="ECDSA (secp256r1)"), \
         patch("builtins.open", side_effect=[Exception("First open fails"), MagicMock()]), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile", MagicMock()), \
         patch("paramiko.ECDSAKey.from_private_key", return_value=mock_ecdsa_key):
        
        mock_private_key.__class__ = ec.EllipticCurvePrivateKey
        mock_private_key.private_bytes.return_value = b"-----BEGIN EC PRIVATE KEY-----\nMockKey\n-----END EC PRIVATE KEY-----"
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid_ecdsa.key", None, 10, mock_logger)
        assert success is True
        assert msg is None

@pytest.mark.authentication_checks()
def test_authenticate_key_cryptography_conversion_ed25519(mock_logger):
    """Test key authentication using cryptography conversion for Ed25519 keys."""
    ssh_client = MagicMock()
    mock_ed25519_key = MagicMock()
    mock_private_key = MagicMock(spec=ed25519.Ed25519PrivateKey)
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Ed25519"), \
         patch("builtins.open", side_effect=[Exception("First open fails"), MagicMock()]), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile", MagicMock()), \
         patch("paramiko.Ed25519Key.from_private_key", return_value=mock_ed25519_key):
        
        mock_private_key.__class__ = ed25519.Ed25519PrivateKey
        mock_private_key.private_bytes.return_value = b"-----BEGIN OPENSSH PRIVATE KEY-----\nMockKey\n-----END OPENSSH PRIVATE KEY-----"
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid_ed25519.key", None, 10, mock_logger)
        assert success is True
        assert msg is None

@pytest.mark.authentication_checks()
def test_authenticate_key_cryptography_conversion_unknown(mock_logger):
    """Test key authentication using cryptography conversion for unknown key types."""
    ssh_client = MagicMock()
    mock_pkey = MagicMock()
    mock_private_key = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown key type"), \
         patch("builtins.open", side_effect=[Exception("First open fails"), MagicMock()]), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile", MagicMock()), \
         patch("paramiko.PKey.from_private_key", return_value=mock_pkey):
        
        mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nMockKey\n-----END PRIVATE KEY-----"
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid_unknown.key", None, 10, mock_logger)
        assert success is True
        assert msg is None

@pytest.mark.authentication_checks()
def test_authenticate_key_password_required(mock_logger):
    """Test when key requires a password but throws PasswordRequiredException."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("builtins.open", side_effect=paramiko.PasswordRequiredException()):
    
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "password_protected.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Key passphrase required"

@pytest.mark.authentication_checks()
def test_authenticate_key_user_not_found(mock_logger):
    """Test authentication failure due to user not found."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.AuthenticationException("User not found")):
    
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "User 'user' does not exist"

@pytest.mark.authentication_checks()
def test_authenticate_key_validation_error(mock_logger):
    """Test key validation error during authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=Exception("q must be exactly")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Key validation error. Possible owner mismatch"

@pytest.mark.authentication_checks()
def test_authenticate_key_format_validation_failed(mock_logger):
    """Test key format validation failure during authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=Exception("key validation")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Key format validation failed - key may not be compatible with server"

@pytest.mark.authentication_checks()
def test_authenticate_unpack_buffer_general_error(mock_logger):
    """Test unpack buffer error in general exception block."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=Exception("unpack requires a buffer")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "ECDSA key format issue - try converting with: ssh-keygen -p -f keyfile -m pem"

@pytest.mark.authentication_checks()
def test_authenticate_no_such_file_error(mock_logger):
    """Test no such file error during authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=Exception("no such file")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Key file not found: valid.key"

@pytest.mark.authentication_checks()
def test_authenticate_key_general_auth_failure(mock_logger):
    """Test general authentication failure fallback in authenticate_with_key."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.AuthenticationException("Some non-specific auth error")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "rsa.key", None, 10, mock_logger)
        
        assert success is False
        assert "Key authentication failed" in msg

@pytest.mark.authentication_checks()
def test_authenticate_with_ecdsa_loading_failure(mock_logger):
    """Test authenticate_with_key when ECDSA key loading fails and falls back to key_filename."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="ECDSA (secp256r1)"), \
         patch("builtins.open", mock_open()), \
         patch.object(ssh_client, "connect") as mock_connect:
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "ecdsa.key", None, 10, mock_logger)
        
        assert success is True
        assert msg is None
        mock_logger.debug.assert_any_call("ECDSA key loading failed, will use key_filename parameter")
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs["key_filename"] == "ecdsa.key"
        assert call_kwargs["pkey"] is None

@pytest.mark.authentication_checks()
def test_authenticate_with_unknown_key_type(mock_logger):
    """Test authenticate_with_key when key type is unknown and falls back to key_filename."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown format"), \
         patch("builtins.open", mock_open()), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False), \
         patch.object(ssh_client, "connect") as mock_connect:
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "unknown.key", None, 10, mock_logger)
        
        assert success is True
        assert msg is None
        mock_logger.debug.assert_any_call("Using key_filename parameter as key type couldn't be determined precisely")
        mock_connect.assert_called_once()
        call_kwargs = mock_connect.call_args[1]
        assert call_kwargs["key_filename"] == "unknown.key"
        assert call_kwargs["pkey"] is None

@pytest.mark.authentication_checks()
def test_authenticate_cryptography_read_file_error(mock_logger):
    """Test authenticate_with_key when cryptography read_file returns None."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=None), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown format"), \
         patch("builtins.open", mock_open(read_data="mock data")), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch.object(ssh_client, "connect", side_effect=Exception("Key file read error")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "unknown.key", None, 10, mock_logger)
        
        assert success is False
        assert "Key file read error" in str(msg)

@pytest.mark.authentication_checks()
def test_authenticate_with_cryptography_unknown_key_type(mock_logger):
    """Test authenticate_with_key with cryptography loading an unknown key type (PKey fallback)."""
    ssh_client = MagicMock()
    mock_pkey = MagicMock()
    mock_private_key = MagicMock()
    temp_file_mock = MagicMock()
    temp_file_mock.name = "/tmp/mock_temp_file"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown type"), \
         patch("builtins.open", side_effect=Exception("First open fails")), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile", return_value=temp_file_mock), \
         patch("paramiko.PKey.from_private_key", return_value=mock_pkey), \
         patch("os.unlink"):
        
        mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nMockKey\n-----END PRIVATE KEY-----"
        
        with patch("builtins.open", return_value=MagicMock()):
            success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "unknown.key", None, 10, mock_logger)
            
            assert success is True
            assert msg is None
            mock_logger.debug.assert_any_call("Successfully loaded key using cryptography conversion")

@pytest.mark.authentication_checks()
def test_authenticate_cryptography_key_conversion_failure(mock_logger):
    """Test authenticate_with_key when cryptography key conversion fails (pkey is None)."""
    ssh_client = MagicMock()
    mock_private_key = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"valid key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown type"), \
         patch("builtins.open", side_effect=Exception("First open fails")), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile") as mock_temp, \
         patch("paramiko.PKey.from_private_key", return_value=None), \
         patch("os.unlink"), \
         patch.object(ssh_client, "connect", side_effect=Exception("Key conversion failed: pkey not loaded")):
        
        mock_temp.return_value.__enter__.return_value.name = "/tmp/mock_temp_file"
        
        mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nMockKey\n-----END PRIVATE KEY-----"
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "unknown.key", None, 10, mock_logger)
        
        assert success is False
        assert "Key conversion failed" in str(msg)

@pytest.mark.authentication_checks()
def test_authenticate_with_dsa_key_loading(mock_logger):
    """Test direct loading of a DSA key in authenticate_with_key."""
    ssh_client = MagicMock()
    mock_dss_key = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.DSSKey.from_private_key", return_value=mock_dss_key), \
         patch("nxc.helpers.ssh_key_utils.log_debug") as mock_log_debug:
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        
        assert success is False
        assert "DSA key auth not supported" in msg
        mock_log_debug.assert_any_call(mock_logger, "DSA key detected: DSA 1024-bit")

@pytest.mark.authentication_checks()
def test_dsa_encrypted_key_auth_failure(mock_logger):
    """Test authentication failure with an encrypted DSA key."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key):
        
        ssh_client.connect.side_effect = paramiko.AuthenticationException("Encrypted, need passphrase")
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "key.key", None, 10, mock_logger)
        
        assert success is False
        assert "Key passphrase required" in msg

@pytest.mark.authentication_checks()
def test_authenticate_dsa_key_not_supported(mock_logger):  # noqa: F811
    """Test authentication with a DSA key explicitly throws not supported message."""
    ssh_client = MagicMock()

    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"):
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"

@pytest.mark.authentication_checks()
def test_authenticate_key_ssh_connection_reset(mock_logger):
    """Test SSH connection reset error during authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.SSHException("Connection reset by peer")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Connection reset by server - possible rate limiting or blocking"

@pytest.mark.authentication_checks()
def test_authenticate_key_ssh_connection_timeout(mock_logger):
    """Test SSH connection timeout during authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.SSHException("Connection timed out")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "Connection timed out"

@pytest.mark.authentication_checks()
def test_authenticate_key_invalid_passphrase(mock_logger):
    """Test invalid passphrase error during authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.SSHException("bad passphrase")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", "wrongpass", 10, mock_logger)
        assert success is False
        assert msg == "Invalid passphrase"

@pytest.mark.authentication_checks()
def test_authenticate_key_unpack_buffer_ssh_error(mock_logger):
    """Test unpack buffer error during SSH authentication."""
    ssh_client = MagicMock()
    mock_rsa_key = MagicMock()
    mock_key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMock RSA key data\n-----END RSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_rsa_key), \
         patch.object(ssh_client, "connect", side_effect=paramiko.SSHException("unpack requires a buffer")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "valid.key", None, 10, mock_logger)
        assert success is False
        assert msg == "ECDSA key format issue - try converting with: ssh-keygen -p -f keyfile -m pem"

@pytest.mark.authentication_checks()
def test_authenticate_with_pem_rsa_key(mock_logger):
    """Test authentication with a PEM format RSA key."""
    mock_pem_rsa_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzJuoU7snv8K6uRLpLbgJGXXB4XFuSRG+4FM6AxwdIBlUxXtn
F07g6ZWn5SWK+sJnKFX1XWYbQgTD4tpZ5A8Z3QdN3XmuKtEwGJJxJjca+7QULLxz
JvUSWGJzYLTjTdK3fhHw+f5I5eW2y7hqVXbZ+I2FrdeUJ2ilO/JMYLEbNHD61duO
/1BwdlAa6/YJKCrnzZ9Wzu+f7iIw33PozHNn2wEqQnPFXu2MjVJvSVcOvhjrMS3w
KnlGldvlKl4Jfx3bHXI3Xowr5M+FutvgHWNMLFbZih+X2HXZl/9JnpTUpctPBZUK
BIPMz+k4fxWYk4Dp3f7v9KpJWZ7vUGMhpPPKTwIDAQABAoIBAHcXILEM1QS7U3mK
mPvNoOqRiHqrKID56H6m6C5yxCwrYFe7fvLQKz2UDSkxZcUYLUcbj14d/uiXRELi
4w7nJf5GoO0y/MdnM/QYYIo68QFsA4BDB0nYVOiGkoSFZD5ZmfzdZKYKXP2aFcTa
xfkBvx/SzsiP4FQHg2xkPzIyBGkj/iVsRQM+oETr9+WJL70kUyFxOx6LALD8AKXs
vNUaZrNZvIm/rN+b+Lpp1zJEibqj/mzm7gnEm1X5+K64iJcPQBdGEsARyYrVzPCJ
b0zlm9czexz6/6/vKLx48pIQ/12nI/iuWKqwOTIe6a3oJIAwRn1MuOvQD9jvqG/W
4sN9kAECgYEA6fXSA4R4/2fUJKKmUkoymDA0CxMJH3bpdzyqSC6Bvwg6SI/Wf8tQ
hZKvmyfszgTKn1MUjRSK4xFBDW+kFQBQAKUkLWZCrDfRN6cWgv6TBbQ49m4CqS9/
ZkQ4t+5lYCTVWuuIm9L2BkH+3Z/3n+BK+uI2LCl91douNBEXDNmoPO8CgYEA36oB
yiqH+PXubZEfLkpK7BEYxR1HJAkS0ZbCCNwG2Kju+G3vl9OIcRnSUzJVt+w9F0Xe
Z8yKF9b0rQPuQ9J01hcb/5s1xiLQOIidLRAxczcNzcfDjDPl36RZM51NS1xF9KgQ
Wvqzcl3rpUUVjL9gPJErmDQxJOTwQAcCyJJXFJECgYEAnMjLJRSGfiJL0cvEk262
9Ir8WjW2iXhKXENVDfxJZ3MT//FW6Cf4dl7BPnZkcZOQ9HYZUVHbQY1bU6a8+vLT
FQQk9zQ5AKKYZrLl8CkIZcRdtLiIFy2+sZZcBkxodPUK8fFCYZwjC3Z9UGwW3dYV
/jJzf0EKhjXv+yNVoLUyT7UCgYEA3sEUkO1b/2BcYx6YUlYOLQCb8mmK8vdL88Fm
0fRKN+jI54HQiQBSEGDM+iaxvPcMKQphzMAwrWuRo1mCxhYO95ioMJ6AFYEpHLdZ
47NvXOZkZsLdKNR1IkR2Mab1jFffd1xEuWBYDdjVpH05vkMuCJNE7S7FJCHUgOzx
OPuV5NECgYBWEzAG0s3fffQYF6YB+EAOpTsxCnkQP3Ukxni81zq/agT9LO3FSbPf
Z2JqiTeEb99d6U6cxpNp8WnLbP4M5OQKrMup4x7+XrFFLMQEhzI/RNj2xwkY8HNY
Q9WgELJGrGVus3TLZ2LlR5EUKqMO5GlTfLfYVMbgLq5jgvW9BGDwrA==
-----END RSA PRIVATE KEY-----"""

    expanded_path = "/expanded/path/to/pem_rsa.key"
    mock_file = mock_open(read_data=mock_pem_rsa_key.decode("utf-8"))

    with patch("nxc.helpers.ssh_key_utils.read_file") as mock_read_file, \
         patch("nxc.helpers.ssh_key_utils.RSA_HEADER", "-----BEGIN RSA PRIVATE KEY-----"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA (PEM format)"), \
         patch("paramiko.SSHClient") as mock_ssh_client, \
         patch("os.path.expanduser", return_value=expanded_path), \
         patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_file), \
         patch("paramiko.RSAKey.from_private_key") as mock_from_private_key:
        
        mock_read_file.return_value = mock_pem_rsa_key
        
        mock_rsa_key = MagicMock()
        mock_from_private_key.return_value = mock_rsa_key
        
        mock_client = MagicMock()
        mock_ssh_client.return_value = mock_client
        
        mock_client.connect.return_value = None
        
        success, message = authenticate_with_key(mock_client, "10.10.10.10", 22, "root", "pem_rsa.key", None, 5, mock_logger)
        
        assert success is True
        assert message is None
        
        mock_logger.debug.assert_any_call("Loading RSA key with key_filename")
        mock_logger.debug.assert_any_call("Successfully authenticated to 10.10.10.10 as root using key")
        
        assert mock_client.connect.called
        
        call_args = mock_client.connect.call_args

        assert call_args[0][0] == "10.10.10.10"
        assert call_args[1]["port"] == 22
        assert call_args[1]["username"] == "root"
        assert call_args[1]["pkey"] == mock_rsa_key
        assert call_args[1]["key_filename"] is None
        assert call_args[1]["look_for_keys"] is False
        assert call_args[1]["allow_agent"] is False
        assert call_args[1]["passphrase"] is None
        assert call_args[1]["banner_timeout"] == 5

@pytest.mark.authentication_checks()
def test_authenticate_with_ed25519_key(mock_logger):
    """Test authentication with an Ed25519 key."""
    valid_ed25519 = textwrap.dedent("""\
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACB1jdR7SFkK4SxA0P8tuFQlFjmZTWaX5ldwgK+P/ohEmQAAAJgVCTFuFQkx
        bgAAAAtzc2gtZWQyNTUxOQAAACB1jdR7SFkK4SxA0P8tuFQlFjmZTWaX5ldwgK+P/ohEmQ
        AAAEAr9aDJAIBzgYnPHDrQM9PnCCvs6v0MBtl4Yoo0ZbXBcnWN1HtIWQrhLEDQ/y24VCUW
        OZlNZpfmV3CAr4/+iESZAAAAEXVzZXJAZXhhbXBsZS5ob3N0AQIDBA==
        -----END OPENSSH PRIVATE KEY-----""").encode("utf-8")
    
    mock_file = MagicMock()
    mock_file.__enter__.return_value = io.BytesIO(valid_ed25519)
    mock_ed25519_key = MagicMock(spec=paramiko.Ed25519Key)
    
    with patch("nxc.helpers.ssh_key_utils.read_file", return_value=valid_ed25519), \
         patch("builtins.open", return_value=mock_file), \
         patch("os.path.isfile", return_value=True), \
         patch("paramiko.Ed25519Key.from_private_key", return_value=mock_ed25519_key):
        
        ssh_client = MagicMock()
        with patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Ed25519"):
            success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "ed25519.key", None, 10, mock_logger)
            assert success is True
            assert msg is None

@pytest.mark.authentication_checks()
def test_authenticate_rsa_key_requires_passphrase(mock_logger):
    """Test for RSA key that requires a passphrase."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", side_effect=paramiko.PasswordRequiredException()):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "rsa_with_passphrase.key", None, 10, mock_logger)
        assert success is False
        assert msg == "RSA key requires passphrase"

@pytest.mark.authentication_checks()
def test_authenticate_rsa_key_incorrect_passphrase(mock_logger):
    """Test for RSA key with incorrect passphrase."""
    ssh_client = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy key data"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", side_effect=paramiko.SSHException("bad password")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "rsa_with_passphrase.key", "wrong_pass", 10, mock_logger)
        assert success is False
        assert msg == "Incorrect passphrase for RSA key"
        mock_logger.debug.assert_any_call("Incorrect passphrase for RSA key")

@pytest.mark.authentication_checks()
def test_authenticate_with_dsa_key_direct_loading(mock_logger):
    """Test authentication with a DSA key."""
    ssh_client = MagicMock()
    mock_dss_key = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.DSSKey.from_private_key", return_value=mock_dss_key):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"
        mock_logger.debug.assert_any_call("Detected key type: DSA 1024-bit")

@pytest.mark.authentication_checks()
def test_auth_failure_dsa_key_deprecated(mock_logger):
    """Test DSA key authentication failure due to deprecation in modern OpenSSH."""
    ssh_client = MagicMock()
    ssh_exception = paramiko.AuthenticationException("Authentication failed")
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.DSSKey.from_private_key", MagicMock()), \
         patch.object(ssh_client, "connect", side_effect=ssh_exception):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"

@pytest.mark.authentication_checks()
def test_dsa_key_authentication_failed_error(mock_logger):
    """Test DSA key authentication when an AuthenticationException with 'authentication failed' is raised."""
    ssh_client = MagicMock()
    mock_dss_key = MagicMock()

    auth_exception = paramiko.AuthenticationException("Authentication failed")

    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", side_effect=paramiko.SSHException("Not an RSA key")), \
         patch("paramiko.DSSKey.from_private_key", return_value=mock_dss_key), \
         patch.object(ssh_client, "connect", side_effect=auth_exception), \
         patch("nxc.helpers.ssh_key_utils.log_debug") as mock_log_debug:

        mock_log_debug.side_effect = lambda logger, msg: None
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        mock_log_debug.assert_any_call(mock_logger, "DSA key detected: DSA 1024-bit")
        assert msg == "DSA key auth not supported"

@pytest.mark.authentication_checks()
def test_dsa_auth_failed_with_authentication_exception(mock_logger):
    """Test DSA key authentication failure when an AuthenticationException is raised."""
    ssh_client = MagicMock()
    mock_dss_key = MagicMock()

    auth_exception = paramiko.AuthenticationException("Authentication failed")

    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.DSSKey.from_private_key", return_value=mock_dss_key), \
         patch.object(ssh_client, "connect", side_effect=auth_exception):

        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"

@pytest.mark.authentication_checks()
def test_authenticate_dsa_key_auth_failure(mock_logger):
    """Test DSA key authentication failure."""
    ssh_client = MagicMock()
    mock_dss_key = MagicMock()
    mock_key_data = b"-----BEGIN DSA PRIVATE KEY-----\nMock DSA key data\n-----END DSA PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="DSA 1024-bit"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.DSSKey.from_private_key", return_value=mock_dss_key):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "dsa.key", None, 10, mock_logger)
        assert success is False
        assert msg == "DSA key auth not supported"

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                            Misc                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.misc()
def test_read_file_error(mock_logger):
    """Test handling of exceptions during file reading."""
    test_file_path = "/test/file/path.key"
    
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", side_effect=Exception("Simulated read error")):
        result = read_file(test_file_path, mock_logger)
        
        assert result is None

        mock_logger.debug.assert_called_once()
        log_message = mock_logger.debug.call_args[0][0]

        assert "Error reading file" in log_message
        assert "Simulated read error" in log_message
        assert test_file_path in log_message

@pytest.mark.misc()
def test_normalize_password_none():
    """Test normalize_password with None input."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    result = normalize_password(None)
    assert result is None

@pytest.mark.misc()
def test_normalize_password_empty_list():
    """Test normalize_password with an empty list."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    result = normalize_password([])
    assert result is None

@pytest.mark.misc()
def test_normalize_password_list_with_empty_string():
    """Test normalize_password with a list containing an empty string."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    result = normalize_password([""])
    assert result is None

@pytest.mark.misc()
def test_normalize_password_list_with_value():
    """Test normalize_password with a list containing a valid password."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    result = normalize_password(["password123"])
    assert result == b"password123"

@pytest.mark.misc()
def test_normalize_password_empty_string():
    """Test normalize_password with an empty string."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    result = normalize_password("")
    assert result is None

@pytest.mark.misc()
def test_normalize_password_string():
    """Test normalize_password with a non-empty string."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    result = normalize_password("password123")
    assert result == b"password123"

@pytest.mark.misc()
def test_normalize_password_other_type():
    """Test normalize_password with an input that is neither string nor list."""
    from nxc.helpers.ssh_key_utils import normalize_password
    
    # Integer
    result = normalize_password(123)
    assert result is None
    
    # Dictionary
    result = normalize_password({"password": "test"})
    assert result is None
    
    # Boolean
    result = normalize_password(True)
    assert result is None

@pytest.mark.misc()
def test_key_unpack_buffer_error(mock_logger):
    """Test handling of 'unpack requires a buffer' error for ECDSA keys."""
    ssh_client = MagicMock()
    mock_key_data = b"-----BEGIN EC PRIVATE KEY-----\nMock ECDSA key data\n-----END EC PRIVATE KEY-----"
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="ECDSA (secp256r1)"), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=mock_key_data), \
         patch("paramiko.ECDSAKey.from_private_key", side_effect=Exception("unpack requires a buffer")), \
         patch("nxc.helpers.ssh_key_utils.load_ecdsa_key", return_value=None), \
         patch.object(ssh_client, "connect", side_effect=Exception("unpack requires a buffer")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "ecdsa.key", None, 10, mock_logger)
        assert success is False
        assert "ECDSA key format issue" in msg or "unpack requires a buffer" in msg

@pytest.mark.misc()
def test_no_cryptography_available(mock_logger):
    """Test the case where cryptography module is not available."""
    with patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", False):
        result = detect_key_type("some_key_file", None, mock_logger)
        assert result is None
        mock_logger.debug.assert_called_with("Cryptography module not available for key type detection")

@pytest.mark.misc()
def test_cryptography_key_load_failure_import_error():
    """Test that CRYPTOGRAPHY_AVAILABLE is set to False when import fails."""
    import sys
    original_modules = dict(sys.modules)
    
    for module_name in list(sys.modules.keys()):
        if module_name.startswith("cryptography"):
            del sys.modules[module_name]
    
    sys.modules["cryptography"] = None
    
    try:
        import importlib
        import nxc.helpers.ssh_key_utils
        importlib.reload(nxc.helpers.ssh_key_utils)
        
        assert nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE is False
    finally:
        sys.modules.clear()
        sys.modules.update(original_modules)

@pytest.mark.misc()
def test_error_getting_key_fingerprint(mock_logger):
    """Test handling error when getting key fingerprint."""
    ssh_client = MagicMock()
    mock_pkey = MagicMock()
    
    mock_pkey.get_fingerprint.side_effect = Exception("Fingerprint error")
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA 2048-bit"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", return_value=mock_pkey):
        
        authenticate_with_key(ssh_client, "host", 22, "user", "key.key", None, 10, mock_logger)
        mock_logger.debug.assert_any_call("Error getting key fingerprint: Fingerprint error")

@pytest.mark.misc()
def test_ssh_exception_rsa_key_format_issue_with_passphrase(mock_logger):
    """Test handling 'encountered rsa key, expected openssh key' error with passphrase."""
    ssh_client = MagicMock()
    ssh_exception = paramiko.SSHException("Encountered RSA key, expected OpenSSH key")
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA (PEM format, passphrase protected)"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", MagicMock()), \
         patch.object(ssh_client, "connect", side_effect=ssh_exception):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "key.key", "password", 10, mock_logger)
        assert success is False
        assert msg == "Invalid passphrase for RSA key"

@pytest.mark.misc()
def test_ssh_exception_rsa_key_format_issue_without_passphrase(mock_logger):
    """Test handling 'encountered rsa key, expected openssh key' error without passphrase."""
    ssh_client = MagicMock()
    ssh_exception = paramiko.SSHException("Encountered RSA key, expected OpenSSH key")
    
    with patch("os.path.isfile", return_value=True), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="RSA (PEM format)"), \
         patch("builtins.open", mock_open()), \
         patch("paramiko.RSAKey.from_private_key", MagicMock()), \
         patch.object(ssh_client, "connect", side_effect=ssh_exception):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "key.key", None, 10, mock_logger)
        assert success is False
        assert msg == "RSA key format issue - try converting with: ssh-keygen -p -f keyfile -m pem"

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                            Key Conversion                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.key_conversion()
def test_key_conversion_failed(mock_logger):
    """Test handling of key conversion failure when no pkey is loaded."""
    ssh_client = MagicMock()

    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", mock_open()), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown type"), \
         patch("paramiko.RSAKey.from_private_key", side_effect=Exception("RSA key error")), \
         patch("paramiko.DSSKey.from_private_key", side_effect=Exception("DSS key error")), \
         patch("paramiko.Ed25519Key.from_private_key", side_effect=Exception("Ed25519 key error")), \
         patch("paramiko.PKey.from_private_key", side_effect=Exception("PKey load error")), \
         patch("nxc.helpers.ssh_key_utils.load_ecdsa_key", return_value=None), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"dummy data"), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", side_effect=Exception("Crypto load error")), \
         patch.object(ssh_client, "connect", side_effect=Exception("Key conversion failed: pkey not loaded")):
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "key.key", None, 10, mock_logger)
    
        assert success is False
        assert "Key conversion failed" in str(msg)

@pytest.mark.key_conversion()
def test_key_conversion_fails_with_none_pkey(mock_logger):
    """Test case where key conversion fails because pkey is None."""
    ssh_client = MagicMock()
    mock_private_key = MagicMock()
    
    with patch("os.path.isfile", return_value=True), \
         patch("builtins.open", side_effect=Exception("First open fails")), \
         patch("nxc.helpers.ssh_key_utils.read_file", return_value=b"key data"), \
         patch("nxc.helpers.ssh_key_utils.detect_key_type", return_value="Unknown"), \
         patch("nxc.helpers.ssh_key_utils.CRYPTOGRAPHY_AVAILABLE", True), \
         patch("nxc.helpers.ssh_key_utils.serialization.load_ssh_private_key", return_value=mock_private_key), \
         patch("tempfile.NamedTemporaryFile") as mock_temp, \
         patch("paramiko.PKey.from_private_key", return_value=None), \
         patch.object(ssh_client, "connect", side_effect=Exception("Key conversion failed: pkey not loaded")):
        
        mock_temp.return_value.__enter__.return_value.name = "/tmp/mock_temp_file"
        mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nMockKey\n-----END PRIVATE KEY-----"
        
        success, msg = authenticate_with_key(ssh_client, "host", 22, "user", "key.key", None, 10, mock_logger)
        assert success is False
        assert "Key conversion failed" in str(msg)