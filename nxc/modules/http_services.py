import re
import contextlib
import hashlib

import requests
from bs4 import BeautifulSoup

from nxc.helpers.misc import CATEGORY


# Each entry: (label, path, [content signature regexes])
# Signatures are intentionally tight: they look for HTML titles, JSON keys,
# header values, or other markers that don't occur in unrelated content. A
# probe is only counted as a "found" service when one of these signatures
# matches the response body or response headers AND the response doesn't
# look like the SPA catch-all baseline.
COMMON_SERVICES = [
    ("phpMyAdmin", "/phpmyadmin/", [r"<title>phpMyAdmin", r'name="pma_']),
    ("phpMyAdmin", "/phpMyAdmin/", [r"<title>phpMyAdmin", r'name="pma_']),
    ("Jenkins", "/", [r"X-Jenkins:", r"<title>Dashboard \[Jenkins\]", r"Jenkins ver\."]),
    ("Jenkins-Login", "/login", [r"Jenkins", r'class="login"']),
    ("Tomcat-Manager", "/manager/html", [r"Apache Tomcat", r"Tomcat Web Application Manager"]),
    ("Tomcat-HostManager", "/host-manager/html", [r"Tomcat Virtual Host Manager"]),
    ("Spring-Actuator", "/actuator", [r'"_links"\s*:\s*\{\s*"self"', r'"href"\s*:\s*"[^"]*/actuator']),
    ("Spring-Env", "/actuator/env", [r'"activeProfiles"\s*:', r'"propertySources"\s*:']),
    ("Spring-Health", "/actuator/health", [r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"']),
    ("GitLab", "/users/sign_in", [r"<title>Sign in.*GitLab", r"gitlab-workhorse"]),
    ("Gitea", "/user/login", [r"<title>.*Gitea", r'name="_csrf"[^>]+gitea']),
    ("Grafana", "/login", [r"<title>Grafana</title>", r'"grafanaBootData"']),
    ("Kibana", "/app/kibana", [r"<title>Kibana", r"kbn-injected-metadata"]),
    ("Kibana-Status", "/api/status", [r'"version"\s*:\s*\{[^}]*"number"', r'"name"\s*:\s*"kibana']),
    ("Elasticsearch", "/", [r'"tagline"\s*:\s*"You Know, for Search"', r'"cluster_name"\s*:']),
    ("Elasticsearch-Indices", "/_cat/indices", [r"^(yellow|green|red)\s", r"^[a-z]+\s+\S+\s+\S+"]),
    ("WordPress-Login", "/wp-login.php", [r'<title>.*WordPress|<input[^>]+name="wp-submit"']),
    ("WordPress-API", "/wp-json/", [r'"namespaces"\s*:\s*\[', r'"routes"\s*:\s*\{']),
    ("Drupal-Login", "/user/login", [r'<title>.*Drupal|<form[^>]+id="user-login']),
    ("Joomla-Admin", "/administrator/", [r"<title>.*Joomla", r'name="passwd"[^>]+id="mod-login-passwd"']),
    ("Confluence", "/login.action", [r"<title>.*Confluence", r"Atlassian Confluence"]),
    ("Jira", "/login.jsp", [r"<title>.*JIRA", r"jira-frontend|atlassian-token"]),
    ("Nextcloud", "/login", [r"<title>.*Nextcloud", r"data-requesttoken"]),
    ("ownCloud", "/login", [r"<title>.*ownCloud", r"/owncloud/core"]),
    ("Magento-Admin", "/admin", [r"<title>.*Magento", r"Magento_Backend"]),
    ("RabbitMQ", "/", [r"RabbitMQ Management", r"rabbitmq_management"]),
    ("Consul", "/v1/status/leader", [r'^"\d+\.\d+\.\d+\.\d+:\d+"\s*$']),
    ("Vault", "/v1/sys/health", [r'"initialized"\s*:\s*(true|false)', r'"sealed"\s*:\s*(true|false)']),
    ("Kubernetes-API", "/version", [r'"gitVersion"\s*:', r'"goVersion"\s*:']),
    ("Docker-API", "/version", [r'"ApiVersion"\s*:', r'"GoVersion"\s*:.*"Version"\s*:']),
    ("Etcd", "/version", [r'"etcdserver"\s*:', r'"etcdcluster"\s*:']),
    ("Prometheus", "/metrics", [r"^# HELP\s", r"^# TYPE\s"]),
    ("Prometheus-UI", "/graph", [r"<title>Prometheus", r"Prometheus Time Series"]),
    ("Solr", "/solr/", [r"<title>Solr Admin", r"solr-admin-app"]),
    ("Adminer", "/adminer.php", [r"<title>.*Adminer", r'class="adminer"']),
    ("Webmin", "/", [r"<title>.*Webmin", r"webmin_search"]),
    ("Cockpit", "/", [r"<title>Cockpit</title>", r"cockpit\.js"]),
    ("pfSense", "/", [r"<title>.*pfSense", r"pfSenseHelpers"]),
    ("OpenVPN-AS", "/", [r"OpenVPN Access Server", r"openvpn-as"]),
    ("Splunk", "/en-US/account/login", [r"<title>.*Splunk", r'name="splunkweb_csrf']),
    ("Hadoop-NameNode", "/dfshealth.html", [r"NameNode", r'"beans"\s*:\s*\[']),
    ("Airflow", "/login/", [r"<title>.*Airflow|<title>Sign In.*Airflow"]),
    ("ArgoCD", "/login", [r"<title>Argo CD", r"argocd-server"]),
    ("MinIO", "/minio/health/live", []),  # status-only: presence of this exact path is the signal
    ("Portainer", "/", [r"<title>Portainer", r"portainer-host"]),
    ("Traefik", "/dashboard/", [r"<title>Traefik|<div\s+id=\"traefik"]),
    ("HAProxy-Stats", "/haproxy?stats", [r"HAProxy Statistics Report", r"hap_stat"]),
    ("Couchbase", "/pools", [r'"implementationVersion"\s*:', r'"isAdminCreds"\s*:']),
    ("MongoDB-REST", "/", [r"It looks like you are trying to access MongoDB"]),
]


# Sensitive file probes. Each entry needs a content signature that won't match
# a generic 404 page that happens to be rendered with status 200.
SENSITIVE_FILES = [
    ("git", "/.git/HEAD", [r"^ref:\s*refs/", r"^[0-9a-f]{40}$"]),
    ("svn", "/.svn/entries", [r"^\d+\s*$", r"dir\s*$"]),
    ("env", "/.env", [r"^[A-Z][A-Z0-9_]+=", r"DB_PASSWORD\s*=", r"APP_KEY\s*="]),
    ("robots", "/robots.txt", [r"(?im)^user-agent\s*:", r"(?im)^disallow\s*:"]),
    ("sitemap", "/sitemap.xml", [r"<urlset[\s>]", r"<sitemapindex[\s>]"]),
    ("server-status", "/server-status", [r"<title>Apache Status", r"Server Version:"]),
    ("server-info", "/server-info", [r"<title>Server Information", r"Server Settings"]),
    ("htaccess", "/.htaccess", [r"(?im)^RewriteEngine\s+On", r"(?im)^Order\s+allow"]),
    ("wp-config-bak", "/wp-config.php.bak", [r"DB_PASSWORD", r"AUTH_KEY"]),
    ("phpinfo", "/phpinfo.php", [r"<title>phpinfo\(\)", r">PHP Version<"]),
    ("info", "/info.php", [r"<title>phpinfo\(\)", r">PHP Version<"]),
    ("composer", "/composer.json", [r'^\s*\{\s*"name"\s*:', r'"require"\s*:\s*\{']),
    ("package", "/package.json", [r'^\s*\{\s*"name"\s*:', r'"dependencies"\s*:\s*\{']),
    ("ds_store", "/.DS_Store", [r"^\x00\x00\x00\x01Bud1"]),
]


def _compile_sigs(entries):
    return [(label, path, [re.compile(p, re.IGNORECASE) for p in sigs]) for label, path, sigs in entries]


_COMMON_SERVICES = _compile_sigs(COMMON_SERVICES)
_SENSITIVE_FILES = _compile_sigs(SENSITIVE_FILES)


class NXCModule:
    """
    Probe common web service and admin panel paths on the target.

    For each path, fetches the resource and matches the response body or
    response headers to a tight signature. Skips responses that look
    identical to the SPA catch-all baseline (a random non-existent path
    is probed first to fingerprint how the server handles 404s). Reports
    confirmed matches with HTTP status and page title; reports 401/403
    responses as auth-protected hints, not confirmed services.

    Module by @claude
    """

    name = "common_services"
    description = "Probe common web services and admin panels (phpMyAdmin, Tomcat, Jenkins, Spring, ...) and identify them"
    supported_protocols = ["http"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.timeout = 5
        self.extra_paths = []
        self.show_files = True
        self.show_all = False

    def options(self, context, module_options):
        """
        TIMEOUT       Per-request timeout in seconds. Default: 5
        EXTRA         Comma-separated list of additional paths to probe
        FILES         Probe for sensitive files (.git, .env, robots.txt, ...). Default: true
        SHOW_ALL      Show every probed path including 404s and baseline matches. Default: false
        """
        self.timeout = int(module_options.get("TIMEOUT", 5))
        extra = module_options.get("EXTRA", "")
        self.extra_paths = [p.strip() for p in extra.split(",") if p.strip()]
        self.show_files = module_options.get("FILES", "true").lower() != "false"
        self.show_all = module_options.get("SHOW_ALL", "false").lower() == "true"

    @staticmethod
    def _content_hash(text):
        return hashlib.md5((text or "").encode(errors="ignore")).hexdigest()

    @staticmethod
    def _extract_title(text):
        if not text:
            return None
        with contextlib.suppress(Exception):
            soup = BeautifulSoup(text, "html.parser")
            tag = soup.title
            if tag is not None:
                title = re.sub(r"<[^>]+>", "", tag.get_text())
                title = " ".join(title.split()).strip()
                title = "".join(c for c in title if c.isprintable() or c == " ")
                return title[:80] or None
        return None

    def _looks_like_baseline(self, connection, response):
        """Return True if this response is indistinguishable from the
        previously-recorded non-existent-path baseline. That's the classic
        SPA-serves-index.html-for-everything trap.
        """
        if connection.baseline_hash is None:
            return False
        # Same status, near-identical body length, identical content hash:
        # near-certainly the catch-all response.
        if response.status_code != connection.baseline_status:
            return False
        body_hash = self._content_hash(response.text)
        if body_hash == connection.baseline_hash:
            return True
        # Hash differs but body length is within 5% — treat as the same
        # template (e.g. SPA bundle with a per-request nonce).
        size_delta = abs(len(response.content) - (connection.baseline_size or 0))
        return size_delta < max(64, (connection.baseline_size or 0) * 0.05)

    def _probe(self, connection, path, label, signatures):
        url = connection._build_url(path)
        try:
            r = connection.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"Probe error for {url}: {e}")
            return False

        # Auth-protected paths are reported as a hint but never as a confirmed
        # service — many sites have site-wide auth and every probe would 401.
        if r.status_code in (401, 403):
            self.context.log.display(f"[{label}] {url} -> HTTP {r.status_code} (auth-protected)")
            return False

        if self._looks_like_baseline(connection, r):
            if self.show_all:
                self.context.log.debug(f"[{label}] {url} -> HTTP {r.status_code} (matches baseline catch-all)")
            return False

        # Only HTTP 200 counts as a real positive. 3xx redirects, 404s, and
        # 5xx errors don't.
        if r.status_code != 200:
            if self.show_all:
                self.context.log.debug(f"[{label}] {url} -> HTTP {r.status_code}")
            return False

        body = r.text or ""
        headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())

        # If the entry has no signatures, the path itself is the signal (only
        # used for endpoints like /minio/health/live that don't return content).
        if not signatures:
            title = self._extract_title(body)
            title_part = f" (title:{title})" if title else ""
            self.context.log.highlight(f"[{label}] {url} -> HTTP {r.status_code}{title_part}")
            return True

        for sig in signatures:
            if sig.search(body) or sig.search(headers_blob):
                title = self._extract_title(body)
                title_part = f" (title:{title})" if title else ""
                self.context.log.highlight(f"[{label}] {url} -> HTTP {r.status_code}{title_part}")
                return True

        if self.show_all:
            self.context.log.debug(f"[{label}] {url} -> HTTP 200 (no signature match)")
        return False

    def _probe_extra(self, connection, path):
        """Extra paths are always reported when reachable — the user asked
        for them explicitly.
        """
        url = connection._build_url(path)
        try:
            r = connection.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"Probe error for {url}: {e}")
            return

        title = self._extract_title(r.text)
        title_part = f" (title:{title})" if title else ""
        baseline_part = " (matches baseline)" if self._looks_like_baseline(connection, r) else ""
        msg = f"[extra] {url} -> HTTP {r.status_code}{title_part}{baseline_part}"
        if r.status_code == 200 and not self._looks_like_baseline(connection, r):
            self.context.log.highlight(msg)
        else:
            self.context.log.display(msg)

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session was not initialized; cannot probe services")
            return

        if connection.baseline_hash is None:
            context.log.display(
                "Baseline 404 probe didn't return; SPA catch-all detection is disabled "
                "(matches may include false positives)"
            )
        else:
            context.log.display(
                f"Baseline 404 probe: HTTP {connection.baseline_status} "
                f"size={connection.baseline_size} hash={connection.baseline_hash[:8]}"
            )

        context.log.display(f"Probing common web services on {connection.url}")

        found = 0
        for label, path, signatures in _COMMON_SERVICES:
            if self._probe(connection, path, label, signatures):
                found += 1

        if self.show_files:
            for label, path, signatures in _SENSITIVE_FILES:
                if self._probe(connection, path, f"file:{label}", signatures):
                    found += 1

        for path in self.extra_paths:
            self._probe_extra(connection, path)

        if found == 0:
            context.log.display("No common web services matched")
        else:
            context.log.success(f"{found} match(es) confirmed")
