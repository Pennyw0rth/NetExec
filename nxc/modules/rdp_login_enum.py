"""Enumerate usernames from RDP login screens when NLA is disabled.

Captures the login screen via aardwolf (unauthenticated) and optionally
extracts usernames using OCR (pytesseract).

No credentials are required - this module connects before authentication.

Usage:
    nxc rdp 192.168.1.0/24 -u '' -p '' -M rdp_login_enum
    nxc rdp 192.168.1.0/24 -u '' -p '' -M rdp_login_enum -o OCR=true
    nxc rdp 192.168.1.0/24 -u '' -p '' -M rdp_login_enum -o SCREENTIME=10 RES=1920x1080
    nxc rdp 10.10.10.100   -u '' -p '' -M rdp_login_enum -o OCR=true OUTPUT=/tmp/rdp_enum

Optional dependencies (only needed if OCR=true):
    pip install pytesseract
    apt install tesseract-ocr tesseract-ocr-fra
"""

import asyncio
import contextlib
import io
import os
import re
import socket
import struct
import sys
from datetime import datetime, timezone

from nxc.helpers.misc import CATEGORY

# Noise words to filter out from OCR (Windows login screen UI text, FR + EN)
_NOISE = frozenset({
    "sign in", "sign-in", "password", "mot de passe",
    "other user", "autre utilisateur",
    "how do i sign in", "comment me connecter",
    "accessibility", "accessibilité",
    "shut down", "arrêter", "restart", "redémarrer",
    "ease of access", "options d'ergonomie",
    "windows", "microsoft", "cancel", "annuler",
    "ok", "submit", "connexion", "se connecter",
    "network", "réseau", "switch user", "changer d'utilisateur",
    "power", "alimentation", "lock", "verrouiller",
    "remote desktop", "bureau à distance", "connected", "connecté",
    "eng", "fra", "deu", "enu", "server", "r2",
    "windows server", "windows server 2012", "windows server 2012 r2",
    "windows server 2008", "windows server 2016", "windows server 2019",
    "windows server 2022", "windows server 2025",
    "windows 7", "windows 8", "windows 10", "windows 11",
    "professionnel", "professional", "enterprise", "entreprise",
    "home", "education", "ultimate", "starter",
    "server2012r2", "server2016", "server2019", "server2022",
    "windows professionnel", "windows professional",
    "windows 7 professionnel", "windows 7 professional",
    "windows 10 professionnel", "windows 10 professional",
    "tly", "sm", "ee", "po", "ci", "in", "es", "lp", "pax", "ad", "bs",
    "meer", "connect", "ministrateur", "connecté connecté",
})

# X.224 negotiation failure codes
_FAILURE_REASONS = {
    0x01: "SSL_REQUIRED_BY_SERVER",
    0x02: "SSL_NOT_ALLOWED_BY_SERVER",
    0x03: "SSL_CERT_NOT_ON_SERVER",
    0x04: "INCONSISTENT_FLAGS",
    0x05: "HYBRID_REQUIRED_BY_SERVER",
    0x06: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}


class NXCModule:
    """Enumerate usernames from RDP login screens when NLA is disabled."""

    name = "rdp_login_enum"
    description = "Enumerate usernames from RDP login screens (NLA disabled, no creds needed)"
    supported_protocols = ["rdp"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.ocr = False
        self.screentime = 5
        self.width = 1024
        self.height = 768
        self.output_dir = None

    def options(self, context, module_options):
        """OCR         Enable OCR username extraction (requires pytesseract + tesseract-ocr). Default: false
        SCREENTIME  Seconds to wait for the login screen to render. Default: 5
        RES         Screenshot resolution in WIDTHxHEIGHT format. Default: 1024x768
        OUTPUT      Output directory for screenshots. Default: ~/.nxc/screenshots
        """
        self.ocr = module_options.get("OCR", "false").lower() in ("true", "1", "yes")
        self.screentime = int(module_options.get("SCREENTIME", "5"))

        res = module_options.get("RES", "1024x768")
        try:
            self.width, self.height = map(int, res.lower().split("x"))
        except ValueError:
            context.log.fail(f"Invalid resolution format: {res} (expected WIDTHxHEIGHT)")
            return

        self.output_dir = module_options.get("OUTPUT", "")
        if not self.output_dir:
            self.output_dir = os.path.join(os.path.expanduser("~/.nxc"), "screenshots")

        os.makedirs(self.output_dir, exist_ok=True)

    def on_login(self, context, connection):
        """Called by NXC for each target. Performs unauthenticated RDP login screen capture."""
        host = connection.host
        port = getattr(connection, "port", 3389)

        # Step 1: Check NLA status
        nla_disabled, nla_info = self._check_nla(host, port)

        if nla_disabled is None:
            context.log.display(f"Could not determine NLA status: {nla_info}")
            context.log.display("Attempting capture anyway...")
        elif not nla_disabled:
            context.log.highlight(f"NLA is ENABLED ({nla_info}) - skipping login screen capture")
            return
        else:
            context.log.display(f"NLA is DISABLED ({nla_info})")

        # Step 2: Capture login screen with dedicated event loop
        context.log.display(f"Capturing login screen (waiting {self.screentime}s)...")
        image = self._run_capture(host, port, context)

        if image is None:
            context.log.fail("Failed to capture login screen")
            return

        # Step 3: Save screenshot
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        filename = f"rdp_loginscreen_{host}_{timestamp}.png"
        filepath = os.path.join(self.output_dir, filename)
        image.save(filepath)
        context.log.success(f"Screenshot saved: {filepath}")

        # Step 4: OCR extraction
        if self.ocr:
            usernames = self._extract_usernames_ocr(image, context)
            if usernames:
                for u in usernames:
                    context.log.highlight(f"Found username: {u}")
            else:
                context.log.display("No usernames extracted via OCR (check screenshot manually)")
        else:
            context.log.display("OCR disabled - use -o OCR=true to extract usernames")

    def _run_capture(self, host, port, context):
        """Run the async capture in a dedicated event loop with proper cleanup."""
        loop = asyncio.new_event_loop()
        loop.set_exception_handler(lambda _loop, _ctx: None)
        image = None
        try:
            image = loop.run_until_complete(self._capture_login_screen(host, port, context))
        except (OSError, ConnectionError) as e:
            context.log.fail(f"Capture failed: {e}")
        finally:
            # Cancel pending aardwolf tasks (__x224_reader, __external_reader)
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            # Suppress aardwolf terminate() RuntimeError on closed loop
            old_stderr = sys.stderr
            sys.stderr = io.StringIO()
            with contextlib.suppress(RuntimeError):
                loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            sys.stderr = old_stderr
        return image

    # -- NLA check (raw X.224 negotiation) --

    def _check_nla(self, host, port=3389, timeout=5):
        """Check NLA status via X.224 Connection Request (PROTOCOL_SSL only)."""
        try:
            return self._check_nla_inner(host, port, timeout)
        except (OSError, ConnectionError, TimeoutError) as e:
            return None, str(e)

    def _check_nla_inner(self, host, port, timeout):
        """Inner NLA check logic."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        response = self._send_x224_request(sock, 0x01)
        sock.close()

        result_type, value = self._parse_x224_response(response)

        if result_type == "accepted_plain":
            return True, "Server accepted plain RDP (no negotiation)"

        if result_type == "response":
            if value in (0x00, 0x01):
                label = "PROTOCOL_RDP" if value == 0x00 else "PROTOCOL_SSL"
                return True, f"{label} (no NLA)"
            if value in (0x02, 0x08):
                return False, "Server forced CredSSP (NLA required)"
            return True, f"Unknown protocol 0x{value:08x}"

        if result_type == "failure":
            reason = _FAILURE_REASONS.get(value, f"code 0x{value:08x}")
            if value == 0x05:
                return False, f"NLA required ({reason})"
            if value == 0x02:
                return self._try_plain_rdp_fallback(host, port, timeout, reason)
            if value == 0x03:
                return True, f"No SSL cert ({reason}), NLA not required"
            return None, f"Negotiation failure: {reason}"

        return None, str(value)

    def _try_plain_rdp_fallback(self, host, port, timeout, reason):
        """Try plain RDP (0x00) when SSL is not allowed."""
        try:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(timeout)
            sock2.connect((host, port))
            resp2 = self._send_x224_request(sock2, 0x00)
            sock2.close()
            r2_type, r2_val = self._parse_x224_response(resp2)
            if r2_type == "accepted_plain" or (r2_type == "response" and r2_val == 0x00):
                return True, "Plain RDP only (no NLA)"
            if r2_type == "failure" and r2_val == 0x05:
                return False, f"NLA required ({reason})"
            return True, "Plain RDP fallback accepted"
        except (OSError, ConnectionError):
            return None, "SSL not allowed, plain fallback failed"

    @staticmethod
    def _send_x224_request(sock, requested_protocols):
        """Send X.224 Connection Request and return raw response."""
        cookie = b"Cookie: mstshash=nxcenum\r\n"
        rdp_neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x0008, requested_protocols)
        x224_payload = cookie + rdp_neg_req
        x224_li = 6 + len(x224_payload)
        x224_cr = struct.pack(">BBHHB", x224_li, 0xE0, 0x0000, 0x0000, 0x00)
        total_length = 4 + len(x224_cr) + len(x224_payload)
        tpkt = struct.pack(">BBH", 3, 0, total_length)
        sock.send(tpkt + x224_cr + x224_payload)
        return sock.recv(1024)

    @staticmethod
    def _parse_x224_response(response):
        """Parse X.224 Connection Confirm. Returns (type, value)."""
        if len(response) < 7:
            return None, "Incomplete response"
        if response[0] != 3:
            return None, f"Invalid TPKT version: {response[0]}"
        if response[5] != 0xD0:
            return None, f"Not Connection Confirm (0x{response[5]:02x})"

        neg_offset = 11
        if len(response) <= neg_offset:
            return "accepted_plain", None

        neg_type = response[neg_offset]
        if neg_type in (0x02, 0x03) and len(response) >= neg_offset + 8:
            val = struct.unpack("<I", response[neg_offset + 4:neg_offset + 8])[0]
            return ("response" if neg_type == 0x02 else "failure"), val

        if neg_type in (0x02, 0x03):
            return None, "Response too short"
        return None, f"Unknown neg type: 0x{neg_type:02x}"

    # -- Login screen capture via aardwolf --

    async def _capture_login_screen(self, host, port, context):
        """Connect to RDP without auth and capture the login screen. Returns PIL Image or None."""
        try:
            from aardwolf.commons.iosettings import RDPIOSettings
            from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
            from aardwolf.commons.target import RDPTarget
            from aardwolf.connection import RDPConnection
            from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
            from asyauth.common.constants import asyauthProtocol, asyauthSecret
            from asyauth.common.credentials import UniCredential
        except ImportError as e:
            context.log.fail(f"Missing dependency: {e}")
            context.log.fail("Install with: pip install aardwolf")
            return None

        iosettings = RDPIOSettings()
        iosettings.channels = []
        iosettings.video_width = self.width
        iosettings.video_height = self.height
        iosettings.video_bpp_min = 15
        iosettings.video_bpp_max = 32
        iosettings.video_out_format = VIDEO_FORMAT.PIL
        iosettings.supported_protocols = SUPP_PROTOCOLS.SSL

        target = RDPTarget(ip=host, port=port, hostname=host, timeout=10)
        credential = UniCredential(
            secret="", username="", domain="",
            stype=asyauthSecret.PASSWORD, protocol=asyauthProtocol.NTLM,
        )

        try:
            conn = RDPConnection(target=target, credentials=credential, iosettings=iosettings)

            old_stderr = sys.stderr
            suppressor = io.StringIO()

            _, err = await conn.connect()
            if err:
                context.log.debug(f"RDP connect returned: {err} (expected for unauth)")

            sys.stderr = suppressor
            await asyncio.sleep(self.screentime)
            sys.stderr = old_stderr

            suppressed = suppressor.getvalue()
            error_count = suppressed.count("Decompression Error")
            if error_count:
                context.log.debug(f"Suppressed {error_count} bitmap decompression errors")

            image = None
            try:
                image = conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
            except (OSError, ValueError) as e:
                context.log.debug(f"get_desktop_buffer failed: {e}")

            try:
                if hasattr(conn, "terminate"):
                    await conn.terminate()
                elif hasattr(conn, "disconnect"):
                    await conn.disconnect()
            except (OSError, RuntimeError, AttributeError):
                pass

            return image

        except (OSError, ConnectionError) as e:
            context.log.fail(f"RDP connection error: {e}")
            return None

    # -- OCR-based username extraction --

    def _extract_usernames_ocr(self, image, context):
        """Extract usernames from the RDP login screen via OCR."""
        try:
            import pytesseract
            from PIL import Image as PILImage
            from PIL import ImageEnhance, ImageFilter, ImageOps
        except ImportError:
            context.log.fail("pytesseract not installed. Run: pip install pytesseract")
            context.log.fail("Also: apt install tesseract-ocr tesseract-ocr-fra")
            return []

        usernames = set()
        seen_lower = set()
        width, height = image.size

        def preprocess(region, scale=2, threshold=120):
            """Invert + scale + sharpen + binarize for OCR on dark backgrounds."""
            region = region.resize((region.width * scale, region.height * scale), PILImage.LANCZOS)
            region = ImageOps.invert(region.convert("RGB"))
            gray = region.convert("L")
            gray = gray.filter(ImageFilter.SHARPEN)
            gray = ImageEnhance.Contrast(gray).enhance(2.0)
            return gray.point(lambda x: 255 if x > threshold else 0)

        def add_username(name):
            """Add username with case-insensitive deduplication."""
            low = name.lower()
            if low not in seen_lower:
                seen_lower.add(low)
                usernames.add(name)

        # OCR regions: (label, crop_box or None for full, scale, threshold, psm)
        regions = [
            ("user list", (int(width * 0.07), int(height * 0.65), int(width * 0.30), int(height * 0.96)), 3, 100, 6),
            ("center", (int(width * 0.2), int(height * 0.45), int(width * 0.8), int(height * 0.6)), 2, 100, 7),
            ("full image", None, 2, 100, 6),
            ("username band", (0, int(height * 0.50), width, int(height * 0.65)), 3, 100, 6),
        ]

        all_text = ""
        for label, crop_box, scale, threshold, psm in regions:
            region = image.crop(crop_box) if crop_box else image
            processed = preprocess(region, scale=scale, threshold=threshold)
            try:
                text = pytesseract.image_to_string(processed, config=f"--psm {psm}")
                context.log.debug(f"OCR [{label}]: {text.strip()!r}")
                all_text += text + "\n"
            except (OSError, RuntimeError) as e:
                context.log.debug(f"OCR [{label}] failed: {e}")

        # Parse and extract usernames
        for line in all_text.strip().split("\n"):
            line = re.sub(r"^[\)\(\]\[\}\{><!|/\\,.:;*#@&%$~`\-_+=\s0-9QqOo]+(?=\s)", "", line)
            line = re.sub(r"^[\)\(\]\[\}\{><!|/\\,.:;*#@&%$~`\-_+=\s]+", "", line)
            line = re.sub(r"^\S\s+", "", line)
            line = re.sub(r"\s+\d\s+", " ", line)
            line = line.strip()

            if not line or len(line) < 2 or len(line) > 200:
                continue
            if line.lower() in _NOISE:
                continue

            # DOMAIN\user
            for domain, user in re.findall(r"([A-Za-z0-9_.-]+)\\([A-Za-z0-9_. -]+)", line):
                user = user.strip()
                if user.lower() not in _NOISE and len(user) > 1:
                    add_username(f"{domain}\\{user}")

            # user@domain.tld
            for user, domain in re.findall(r"([A-Za-z0-9_.+-]+)@([A-Za-z0-9_.-]+\.[A-Za-z]{2,})", line):
                if user.lower() not in _NOISE:
                    add_username(f"{user}@{domain}")

            # Capitalized display names
            if re.match(r"^[A-ZÀ-Ü][a-zà-ü]+(?: [A-ZÀ-Ü][a-zà-ü]+)*$", line) and line.lower() not in _NOISE:
                add_username(line)

            # Single-token alphanumeric usernames
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]{1,30})$", line)
            if m:
                candidate = m.group(1)
                if candidate.lower() not in _NOISE and not candidate.lower().startswith(("windows", "microsoft")):
                    add_username(candidate)

            # Space-separated usernames (Server 2012 style row)
            words = line.split()
            if len(words) >= 2:
                for word in words:
                    word = re.sub(r"^[^A-Za-z0-9]+|[^A-Za-z0-9]+$", "", word)
                    if not word or len(word) < 3 or len(word) > 40:
                        continue
                    if word.lower() in _NOISE:
                        continue
                    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", word):
                        continue
                    if re.match(r"^(windows|server|r2|build|version|sp\d|x64|x86|\d{4,})$", word, re.IGNORECASE):
                        continue
                    add_username(word)

        return sorted(usernames)
