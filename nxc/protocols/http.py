import re
import contextlib
import hashlib
import secrets

import requests
import urllib3
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from termcolor import colored

from nxc.config import process_secret, host_info_colors
from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.logger import NXCAdapter


DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) NetExec/HTTP"
SSL_PORTS = {443, 8443, 4443, 9443}
TITLE_MAX_LEN = 120
BASELINE_MIN_SIZE_FOR_PCT = 1024  # below this size, require exact hash match


def _compile(patterns):
    return [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in patterns]


SERVER_FINGERPRINTS = _compile([
    ("nginx", r"nginx"),
    ("apache", r"apache"),
    ("iis", r"microsoft-iis"),
    ("lighttpd", r"lighttpd"),
    ("caddy", r"caddy"),
    ("openresty", r"openresty"),
    ("tomcat", r"tomcat|coyote"),
    ("jetty", r"jetty"),
    ("gunicorn", r"gunicorn"),
    ("werkzeug", r"werkzeug"),
    ("envoy", r"envoy"),
    ("cloudflare", r"cloudflare"),
    ("akamai", r"akamai"),
])

HEADER_FINGERPRINTS = [
    ("php", "x-powered-by", re.compile(r"php", re.IGNORECASE)),
    ("asp.net", "x-powered-by", re.compile(r"asp\.net", re.IGNORECASE)),
    ("express", "x-powered-by", re.compile(r"express", re.IGNORECASE)),
    ("jboss", "x-powered-by", re.compile(r"jboss|undertow", re.IGNORECASE)),
    ("cloudflare", "cf-ray", re.compile(r".+")),
    ("cloudfront", "x-amz-cf-id", re.compile(r".+")),
    ("varnish", "via", re.compile(r"varnish", re.IGNORECASE)),
    ("kubernetes", "x-kubernetes-pf-prioritylevel-uid", re.compile(r".+")),
]

COOKIE_FINGERPRINTS = _compile([
    ("php", r"\bPHPSESSID\b"),
    ("asp.net", r"\bASP\.NET_SessionId\b"),
    ("java", r"\bJSESSIONID\b"),
    ("django", r"\bcsrftoken\b|\bdjango"),
    ("laravel", r"\blaravel_session\b"),
    ("wordpress", r"wordpress_|wp-settings"),
    ("rails", r"_rails_session|_session_id"),
])

BODY_FINGERPRINTS = _compile([
    ("wordpress", r"wp-content/|wp-includes/|/wp-json/"),
    ("drupal", r"Drupal\.settings|/sites/default/files/"),
    ("joomla", r"/components/com_|Joomla!"),
    ("magento", r"Mage\.Cookies|/skin/frontend/"),
    ("phpmyadmin", r"<title>phpMyAdmin|phpMyAdmin\.css"),
    ("jenkins", r"X-Jenkins:|Jenkins ver\."),
    ("gitlab", r"GitLab Community Edition|GitLab Enterprise Edition"),
    ("grafana", r'<title>Grafana</title>|"grafanaBootData"'),
    ("kibana", r"<title>Kibana</title>|kbn-injected-metadata"),
    ("jira", r"jira\.app\.|jira-frontend"),
    ("confluence", r"<title>.*Confluence|confluence-page"),
    ("tomcat", r"Apache Tomcat/"),
    ("nextcloud", r"<title>Nextcloud|/apps/files/"),
    ("owncloud", r"<title>ownCloud|/owncloud/"),
    ("vmware-vcenter", r"VMware vSphere|VMware vCenter"),
    ("printer-cups", r"<title>Home - CUPS"),
    ("router-mikrotik", r"RouterOS v\d|mikrotik\.com"),
])


def _content_hash(data):
    """Hash of the raw response bytes (or text)."""
    if isinstance(data, str):
        data = data.encode(errors="ignore")
    return hashlib.md5(data or b"").hexdigest()


def _read_capped(response, max_bytes):
    """Read up to max_bytes of the response body without loading everything
    into memory. Returns raw bytes.
    """
    chunks = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            response.close()
    body = b"".join(chunks)
    return body[:max_bytes]


def _decode(body_bytes, response):
    """Decode response body bytes using the response-declared encoding."""
    encoding = response.encoding or response.apparent_encoding or "utf-8"
    try:
        return body_bytes.decode(encoding, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return body_bytes.decode("utf-8", errors="replace")


def _build_url(scheme, host, port, path, is_ipv6=False):
    """Build a URL safely handling IPv6 zone-ids."""
    default_port = 443 if scheme == "https" else 80
    host_part = host
    if is_ipv6:
        # Percent-encode the zone-id separator per RFC 6874
        host_part = host.replace("%", "%25")
        host_part = f"[{host_part}]"
    port_part = "" if port == default_port else f":{port}"
    request_path = path if path is not None else "/"
    if not request_path.startswith("/"):
        request_path = "/" + request_path
    return f"{scheme}://{host_part}{port_part}{request_path}"


class _Baseline:
    """Captured response from a known-nonexistent path, used to detect SPA
    catch-all 200 responses where every path returns index.html.
    """

    __slots__ = ("captured", "hash", "size", "status", "title")

    def __init__(self):
        self.status = None
        self.size = None
        self.hash = None
        self.title = None
        self.captured = False


class http(connection):
    def __init__(self, args, db, host):
        # --ssl with the default port 80 almost always means the user wants 443.
        # Mutating args here is fine since args.ssl is sticky across targets.
        if args.ssl and args.port == 80:
            args.port = 443

        self.protocol = "HTTP"
        self.url = None
        self.final_url = None
        self.scheme = "http"
        self.is_ssl = False
        self.status_code = None
        self.server = None
        self.title = None
        self.technologies = []
        self.session = None
        self.response = None
        self.body_text = ""
        self.body_bytes = b""
        self.baseline = _Baseline()
        self.www_authenticate = None
        self.max_body_size = getattr(args, "max_body_size", 262144)

        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "HTTP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def _resolve_scheme(self):
        """Cache the scheme decision after __init__ port-mutation has settled."""
        self.is_ssl = bool(self.args.ssl) or self.port in SSL_PORTS
        self.scheme = "https" if self.is_ssl else "http"

    def build_url(self, path=None):
        """Construct a URL for the given path against this host. Public API
        used by modules that probe additional paths.
        """
        request_path = path if path is not None else self.args.path
        return _build_url(self.scheme, self.host, self.port,
                          request_path, getattr(self, "is_ipv6", False))

    # Kept for backwards compatibility / module code that grabbed the private name.
    _build_url = build_url

    def _build_session(self):
        session = requests.Session()
        session.verify = not self.args.no_verify
        session.headers["User-Agent"] = self.args.user_agent or DEFAULT_USER_AGENT
        if self.args.proxy:
            session.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        # Only suppress urllib3 SSL warnings when the user opted out of
        # verification, so other code in the process isn't silenced.
        if self.args.no_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return session

    def _request(self, url, **kwargs):
        """Streaming GET that caps body reads at max_body_size."""
        kwargs.setdefault("timeout", self.args.http_timeout)
        kwargs.setdefault("allow_redirects", False)
        kwargs["stream"] = True
        r = self.session.get(url, **kwargs)
        body_bytes = _read_capped(r, self.max_body_size)
        body_text = _decode(body_bytes, r)
        return r, body_bytes, body_text

    def _extract_title(self, text):
        if not text:
            return None
        try:
            soup = BeautifulSoup(text, "html.parser")
            tag = soup.title
            if tag is not None:
                # html.parser treats <title> content as a raw text node, so any
                # nested tags survive as literal "<...>" strings. Strip those,
                # collapse whitespace, drop non-printables.
                title = re.sub(r"<[^>]+>", "", tag.get_text())
                title = " ".join(title.split()).strip()
                title = "".join(c for c in title if c.isprintable() or c == " ")
                if len(title) > TITLE_MAX_LEN:
                    title = title[:TITLE_MAX_LEN] + "..."
                return title or None
        except Exception as e:
            self.logger.debug(f"Title parse error: {e}")
        return None

    def _fingerprint(self, response, body_text):
        tech = []

        server_header = response.headers.get("Server", "")
        if server_header:
            self.server = server_header
            for name, pattern in SERVER_FINGERPRINTS:
                if pattern.search(server_header) and name not in tech:
                    tech.append(name)

        for name, header_name, pattern in HEADER_FINGERPRINTS:
            value = response.headers.get(header_name)
            if value and pattern.search(value) and name not in tech:
                tech.append(name)

        set_cookie = response.headers.get("Set-Cookie", "")
        cookie_names = " ".join(c.name for c in response.cookies)
        cookie_blob = f"{set_cookie} {cookie_names}"
        for name, pattern in COOKIE_FINGERPRINTS:
            if pattern.search(cookie_blob) and name not in tech:
                tech.append(name)

        for name, pattern in BODY_FINGERPRINTS:
            if pattern.search(body_text) and name not in tech:
                tech.append(name)

        return tech

    def _baseline_probe(self):
        """Fingerprint how the server handles a known-nonexistent path so
        modules can distinguish a SPA catch-all 200 from a real hit.
        """
        rand_path = f"/nxc-baseline-{secrets.token_hex(8)}"
        try:
            r, body_bytes, body_text = self._request(self.build_url(rand_path))
            self.baseline.status = r.status_code
            self.baseline.size = len(body_bytes)
            self.baseline.hash = _content_hash(body_bytes)
            self.baseline.title = self._extract_title(body_text)
            self.baseline.captured = True
            self.logger.debug(
                f"Baseline {rand_path}: status={self.baseline.status} "
                f"size={self.baseline.size} hash={self.baseline.hash[:8]}"
            )
        except Exception as e:
            self.logger.debug(f"Baseline probe error: {e}")

    def looks_like_baseline(self, status, body_bytes):
        """Return True if a response is indistinguishable from the captured
        baseline (i.e. a catch-all).
        """
        if not self.baseline.captured:
            return False
        if status != self.baseline.status:
            return False
        if _content_hash(body_bytes) == self.baseline.hash:
            return True
        # For larger baselines, allow a small relative byte delta to account
        # for per-request nonces in SPA bundles. For small baselines, require
        # an exact hash match to avoid flagging unrelated short pages as the
        # same template.
        baseline_size = self.baseline.size or 0
        if baseline_size < BASELINE_MIN_SIZE_FOR_PCT:
            return False
        delta = abs(len(body_bytes) - baseline_size)
        return delta < baseline_size * 0.05

    def create_conn_obj(self):
        self._resolve_scheme()
        self.session = self._build_session()
        self.url = self.build_url()
        try:
            self.response, self.body_bytes, self.body_text = self._request(
                self.url,
                allow_redirects=self.args.follow_redirects,
            )
        except requests.exceptions.SSLError as e:
            self.logger.fail(f"SSL/TLS error connecting to {self.url}: {e} (try --no-verify if the cert is invalid)")
            return False
        except requests.exceptions.ConnectionError as e:
            self.logger.debug(f"Connection error to {self.url}: {e}")
            return False
        except requests.exceptions.Timeout as e:
            self.logger.debug(f"Timeout connecting to {self.url}: {e}")
            return False
        except Exception as e:
            self.logger.debug(f"Unexpected error connecting to {self.url}: {e}")
            return False

        self.final_url = self.response.url
        self.www_authenticate = self.response.headers.get("WWW-Authenticate")
        self._baseline_probe()
        return True

    def enum_host_info(self):
        if self.response is None:
            return
        self.status_code = self.response.status_code
        self.title = self._extract_title(self.body_text)
        self.technologies = self._fingerprint(self.response, self.body_text)

        with contextlib.suppress(Exception):
            self.db.add_host(
                host=self.host,
                port=self.port,
                scheme=self.scheme,
                url=self.final_url or self.url,
                status_code=self.status_code,
                server=self.server,
                title=self.title,
                technologies=",".join(self.technologies) if self.technologies else None,
            )

    def _auth_scheme_label(self):
        """Parse just the scheme name out of a WWW-Authenticate header value."""
        if not self.www_authenticate:
            return None
        # Header may contain multiple schemes: "Negotiate, Basic realm=..."
        first = re.split(r"[\s,]+", self.www_authenticate.strip(), maxsplit=1)[0]
        return first.rstrip(",").strip() or None

    def print_host_info(self):
        status = self.status_code if self.status_code is not None else "?"
        status_color = host_info_colors[0] if isinstance(status, int) and 200 <= status < 400 else host_info_colors[1]
        status_label = colored(f"status:{status}", status_color, attrs=["bold"])
        server = self.server.strip() if self.server else "unknown"
        title = self.title if self.title else ""
        tech = ",".join(self.technologies) if self.technologies else ""
        tech_part = f" (tech:{tech})" if tech else ""
        title_part = f" (title:{title})" if title else ""
        auth_scheme = self._auth_scheme_label()
        auth_part = f" (auth:{auth_scheme})" if auth_scheme else ""
        redirect_part = ""
        if self.final_url and self.final_url != self.url:
            redirect_part = f" (final:{self.final_url})"
        self.logger.display(f"{self.url} ({status_label}) (server:{server}){auth_part}{redirect_part}{title_part}{tech_part}")

    def disconnect(self):
        if self.session is not None:
            with contextlib.suppress(Exception):
                self.session.close()

    def _auth(self, username, password):
        """Pick an auth handler. The server's advertised scheme wins; failing
        that, fall back to the user's --auth-type.
        """
        advertised = (self._auth_scheme_label() or "").lower()
        choice = advertised or self.args.auth_type.lower()
        if choice == "digest":
            return HTTPDigestAuth(username, password)
        if choice in ("ntlm", "negotiate"):
            try:
                from requests_ntlm import HttpNtlmAuth
            except ImportError:
                self.logger.fail(
                    "NTLM authentication requested but 'requests-ntlm' is not installed; "
                    "falling back to Basic"
                )
                return HTTPBasicAuth(username, password)
            return HttpNtlmAuth(username, password)
        return HTTPBasicAuth(username, password)

    def plaintext_login(self, username, password):
        if self.session is None and not self.create_conn_obj():
            return False

        # Validate only HTTP Basic/Digest/NTLM. Cookie/form auth would need a
        # target-specific login flow we don't have, so refuse to guess.
        if self.response is None or self.response.status_code != 401 or not self.www_authenticate:
            self.logger.fail(
                f"{username}:{process_secret(password)} "
                f"(no HTTP auth challenge on {self.url}; "
                f"netexec cannot validate form-based auth)"
            )
            return False

        target_path = self.args.check_auth_path or self.args.path
        url = self.build_url(target_path)
        try:
            r = self.session.get(
                url,
                auth=self._auth(username, password),
                timeout=self.args.http_timeout,
                allow_redirects=False,
                stream=True,
            )
            # Drain a small amount so the connection can be reused
            _read_capped(r, 4096)
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} (Response: {e})")
            return False

        if r.status_code == 401:
            self.logger.fail(f"{username}:{process_secret(password)} (HTTP 401 - bad credentials)")
            return False
        if r.status_code >= 500:
            self.logger.fail(f"{username}:{process_secret(password)} (HTTP {r.status_code} - server error)")
            return False
        if 300 <= r.status_code < 400:
            location = r.headers.get("Location", "")
            self.logger.fail(
                f"{username}:{process_secret(password)} "
                f"(HTTP {r.status_code} -> {location}; ambiguous, refusing to claim success)"
            )
            return False

        self.username = username
        self.password = password
        self.admin_privs = False
        self.logger.success(f"{username}:{process_secret(password)} {highlight(f'(HTTP {r.status_code})')}")

        with contextlib.suppress(Exception):
            self.db.add_host(
                host=self.host,
                port=self.port,
                scheme=self.scheme,
                url=self.final_url or self.url,
                status_code=self.status_code,
                server=self.server,
                title=self.title,
                technologies=",".join(self.technologies) if self.technologies else None,
            )
            cred_id = self.db.add_credential(username, password)
            hosts = [h for h in self.db.get_hosts(self.host) if h.port == self.port]
            if hosts:
                self.db.add_loggedin_relation(cred_id, hosts[0].id)
        return True
