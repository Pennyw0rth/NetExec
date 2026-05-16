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

urllib3.disable_warnings()


DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) NetExec/HTTP"
SSL_PORTS = {443, 8443, 4443, 9443}
TITLE_MAX_LEN = 120


def _compile(patterns):
    return [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in patterns]


# Inspired by ProjectDiscovery httpx + Wappalyzer style fingerprints. Patterns
# are intentionally conservative — they trigger on strings that are unlikely to
# show up by coincidence on unrelated pages.
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

# Body patterns are anchored to strings specific enough to avoid matching the
# product name appearing in unrelated content (blog posts, status pages, etc.).
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


def _content_hash(text):
    return hashlib.md5((text or "").encode(errors="ignore")).hexdigest()


class http(connection):
    def __init__(self, args, db, host):
        # --ssl with the default port 80 almost always means the user wants 443.
        # Mutating args here is fine since args.ssl is sticky across targets;
        # on subsequent targets args.port is already 443.
        if args.ssl and args.port == 80:
            args.port = 443

        self.protocol = "HTTP"
        self.url = None
        self.scheme = "http"
        self.status_code = None
        self.server = None
        self.title = None
        self.technologies = []
        self.session = None
        self.response = None
        self.baseline_hash = None
        self.baseline_size = None
        self.baseline_status = None
        self.www_authenticate = None

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

    def _use_ssl(self):
        return bool(self.args.ssl) or self.port in SSL_PORTS

    def _build_url(self, path=None):
        scheme = "https" if self._use_ssl() else "http"
        default_port = 443 if scheme == "https" else 80
        host_part = self.host
        if getattr(self, "is_ipv6", False):
            host_part = f"[{self.host}]"
        port_part = "" if self.port == default_port else f":{self.port}"
        request_path = path if path is not None else self.args.path
        if not request_path.startswith("/"):
            request_path = "/" + request_path
        return f"{scheme}://{host_part}{port_part}{request_path}"

    def _build_session(self):
        session = requests.Session()
        session.verify = not self.args.no_verify
        session.headers["User-Agent"] = self.args.user_agent or DEFAULT_USER_AGENT
        if self.args.proxy:
            session.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        return session

    def _extract_title(self, text):
        if not text:
            return None
        try:
            soup = BeautifulSoup(text, "html.parser")
            tag = soup.title
            if tag is not None:
                # html.parser treats <title> content as a raw text node, so
                # any nested tags survive as literal "<...>" strings. Strip
                # them, then collapse whitespace and drop non-printables.
                title = re.sub(r"<[^>]+>", "", tag.get_text())
                title = " ".join(title.split()).strip()
                title = "".join(c for c in title if c.isprintable() or c == " ")
                if len(title) > TITLE_MAX_LEN:
                    title = title[:TITLE_MAX_LEN] + "..."
                return title or None
        except Exception as e:
            self.logger.debug(f"Title parse error: {e}")
        return None

    def _fingerprint(self, response):
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

        body_sample = response.text[:65536] if response.text else ""
        for name, pattern in BODY_FINGERPRINTS:
            if pattern.search(body_sample) and name not in tech:
                tech.append(name)

        return tech

    def _baseline_404(self):
        """Probe a guaranteed-nonexistent path so probing modules can tell
        a SPA's catch-all 200 (which would otherwise look like every path
        exists) apart from a real hit.
        """
        rand_path = f"/nxc-baseline-{secrets.token_hex(8)}"
        try:
            r = self.session.get(
                self._build_url(rand_path),
                timeout=self.args.http_timeout,
                allow_redirects=False,
            )
            self.baseline_status = r.status_code
            self.baseline_size = len(r.content)
            self.baseline_hash = _content_hash(r.text)
            self.logger.debug(
                f"Baseline {rand_path}: status={self.baseline_status} "
                f"size={self.baseline_size} hash={self.baseline_hash[:8]}"
            )
        except Exception as e:
            self.logger.debug(f"Baseline probe error: {e}")

    def create_conn_obj(self):
        self.scheme = "https" if self._use_ssl() else "http"
        self.session = self._build_session()
        self.url = self._build_url()
        try:
            self.response = self.session.get(
                self.url,
                timeout=self.args.http_timeout,
                allow_redirects=self.args.follow_redirects,
            )
        except requests.exceptions.SSLError as e:
            self.logger.debug(f"SSL error connecting to {self.url}: {e}")
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
        self.www_authenticate = self.response.headers.get("WWW-Authenticate")
        self._baseline_404()
        return True

    def enum_host_info(self):
        if self.response is None:
            return
        self.status_code = self.response.status_code
        self.title = self._extract_title(self.response.text)
        self.technologies = self._fingerprint(self.response)

        with contextlib.suppress(Exception):
            self.db.add_host(
                host=self.host,
                port=self.port,
                scheme=self.scheme,
                url=self.url,
                status_code=self.status_code,
                server=self.server,
                title=self.title,
                technologies=",".join(self.technologies) if self.technologies else None,
            )

    def print_host_info(self):
        status = self.status_code if self.status_code is not None else "?"
        status_color = host_info_colors[0] if isinstance(status, int) and 200 <= status < 400 else host_info_colors[1]
        status_label = colored(f"status:{status}", status_color, attrs=["bold"])
        server = self.server.strip() if self.server else "unknown"
        title = self.title if self.title else ""
        tech = ",".join(self.technologies) if self.technologies else ""
        tech_part = f" (tech:{tech})" if tech else ""
        title_part = f" (title:{title})" if title else ""
        auth_part = ""
        if self.www_authenticate:
            scheme = self.www_authenticate.split(" ", 1)[0]
            auth_part = f" (auth:{scheme})"
        self.logger.display(f"{self.url} ({status_label}) (server:{server}){auth_part}{title_part}{tech_part}")

    def disconnect(self):
        if self.session is not None:
            with contextlib.suppress(Exception):
                self.session.close()

    def _auth(self, username, password):
        # Prefer the scheme the server actually advertised
        if self.www_authenticate and "digest" in self.www_authenticate.lower():
            return HTTPDigestAuth(username, password)
        if self.args.auth_type == "digest":
            return HTTPDigestAuth(username, password)
        return HTTPBasicAuth(username, password)

    def plaintext_login(self, username, password):
        if self.session is None and not self.create_conn_obj():
            return False

        # We can only validate HTTP Basic/Digest credentials here. Cookie- or
        # form-based auth would need a target-specific login flow, which we
        # don't have. If the baseline path didn't issue a 401 challenge, we
        # have no way to tell whether creds worked, so refuse to guess.
        if self.response is None or self.response.status_code != 401 or not self.www_authenticate:
            self.logger.fail(
                f"{username}:{process_secret(password)} "
                f"(no HTTP Basic/Digest challenge on {self.url}; "
                f"netexec cannot validate form-based auth)"
            )
            return False

        target_path = self.args.check_auth_path or self.args.path
        url = self._build_url(target_path)
        try:
            r = self.session.get(
                url,
                auth=self._auth(username, password),
                timeout=self.args.http_timeout,
                allow_redirects=False,
            )
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} (Response: {e})")
            return False

        # A 401 still on the protected resource means creds were rejected.
        if r.status_code == 401:
            self.logger.fail(f"{username}:{process_secret(password)} (HTTP 401 - bad credentials)")
            return False
        if r.status_code >= 500:
            self.logger.fail(f"{username}:{process_secret(password)} (HTTP {r.status_code} - server error)")
            return False
        # Redirects from a previously-401 resource are ambiguous: could be a
        # post-auth redirect to a dashboard (success) or a redirect to a login
        # page (failure). Don't claim success without more evidence.
        if 300 <= r.status_code < 400:
            location = r.headers.get("Location", "")
            self.logger.fail(
                f"{username}:{process_secret(password)} "
                f"(HTTP {r.status_code} -> {location}; ambiguous, refusing to claim success)"
            )
            return False

        # 200/2xx (or 403 — authenticated but no access to this resource) on a
        # resource that previously returned 401 means the credentials are valid.
        self.username = username
        self.password = password
        self.admin_privs = False
        self.logger.success(f"{username}:{process_secret(password)} {highlight(f'(HTTP {r.status_code})')}")

        with contextlib.suppress(Exception):
            self.db.add_host(
                host=self.host,
                port=self.port,
                scheme=self.scheme,
                url=self.url,
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
