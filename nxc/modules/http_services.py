import re
import contextlib
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

from nxc.helpers.misc import CATEGORY


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


# Each entry: (label, path, [content signature regexes], extra_constraints)
# extra_constraints is an optional dict; supported keys:
#   - content_type_starts_with: substring the Content-Type must start with
#   - required_header: header name that must be present
#   - empty_body: True if a 200 with Content-Length 0 is the signal
COMMON_SERVICES = [
    ("phpMyAdmin", "/phpmyadmin/", [r"<title>phpMyAdmin", r'name="pma_'], {}),
    ("phpMyAdmin", "/phpMyAdmin/", [r"<title>phpMyAdmin", r'name="pma_'], {}),
    ("Jenkins", "/", [r"X-Jenkins:", r"<title>Dashboard \[Jenkins\]", r"Jenkins ver\."], {}),
    ("Jenkins-Login", "/login", [r"X-Jenkins:", r"<title>.*Sign in \[Jenkins\]", r"jenkins-instance-identity"], {}),
    ("Tomcat-Manager", "/manager/html", [r"<title>/manager</title>", r"Tomcat Web Application Manager"], {}),
    ("Tomcat-HostManager", "/host-manager/html", [r"Tomcat Virtual Host Manager"], {}),
    ("Spring-Actuator", "/actuator", [r'"_links"\s*:\s*\{\s*"self"', r'"href"\s*:\s*"[^"]*/actuator'], {"content_type_starts_with": "application/"}),
    ("Spring-Env", "/actuator/env", [r'"activeProfiles"\s*:', r'"propertySources"\s*:'], {"content_type_starts_with": "application/"}),
    ("Spring-Health", "/actuator/health", [r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)".*"groups"', r'"status"\s*:\s*"(UP|DOWN)".*"components"'], {"content_type_starts_with": "application/"}),
    ("GitLab", "/users/sign_in", [r"<title>Sign in.*GitLab", r"gitlab-workhorse"], {}),
    ("Gitea", "/user/login", [r"<title>.*Gitea", r'name="_csrf"[^>]+gitea'], {}),
    ("Grafana", "/login", [r"<title>Grafana</title>", r'"grafanaBootData"'], {}),
    ("Kibana", "/app/kibana", [r"<title>Kibana", r"kbn-injected-metadata"], {}),
    ("Kibana-Status", "/api/status", [r'"version"\s*:\s*\{[^}]*"number"', r'"name"\s*:\s*"kibana'], {"content_type_starts_with": "application/"}),
    ("Elasticsearch", "/", [r'"tagline"\s*:\s*"You Know, for Search"', r'"cluster_name"\s*:'], {"content_type_starts_with": "application/"}),
    ("Elasticsearch-Indices", "/_cat/indices", [r"^(yellow|green|red)\s", r"^[a-z]+\s+\S+\s+\S+"], {"content_type_starts_with": "text/plain"}),
    ("WordPress-Login", "/wp-login.php", [r'<title>.*WordPress|<input[^>]+name="wp-submit"'], {}),
    ("WordPress-API", "/wp-json/", [r'"namespaces"\s*:\s*\[', r'"routes"\s*:\s*\{'], {"content_type_starts_with": "application/"}),
    ("Drupal-Login", "/user/login", [r'<title>.*Drupal|<form[^>]+id="user-login'], {}),
    ("Joomla-Admin", "/administrator/", [r"<title>.*Joomla", r'name="passwd"[^>]+id="mod-login-passwd"'], {}),
    ("Confluence", "/login.action", [r"<title>.*Confluence", r"Atlassian Confluence"], {}),
    ("Jira", "/login.jsp", [r"<title>.*JIRA", r"jira-frontend|atlassian-token"], {}),
    ("Nextcloud", "/login", [r"<title>.*Nextcloud", r"data-requesttoken"], {}),
    ("ownCloud", "/login", [r"<title>.*ownCloud", r"/owncloud/core"], {}),
    ("Magento-Admin", "/admin", [r"<title>.*Magento", r"Magento_Backend"], {}),
    ("RabbitMQ", "/", [r"RabbitMQ Management", r"rabbitmq_management"], {}),
    ("Consul", "/v1/status/leader", [r'^"\d+\.\d+\.\d+\.\d+:\d+"\s*$'], {}),
    ("Vault", "/v1/sys/health", [r'"initialized"\s*:\s*(true|false)', r'"sealed"\s*:\s*(true|false)'], {"content_type_starts_with": "application/"}),
    ("Kubernetes-API", "/version", [r'"gitVersion"\s*:', r'"goVersion"\s*:'], {"content_type_starts_with": "application/"}),
    ("Docker-API", "/version", [r'"ApiVersion"\s*:', r'"GoVersion"\s*:.*"Version"\s*:'], {"content_type_starts_with": "application/"}),
    ("Etcd", "/version", [r'"etcdserver"\s*:', r'"etcdcluster"\s*:'], {"content_type_starts_with": "application/"}),
    ("Prometheus", "/metrics", [r"^# HELP\s", r"^# TYPE\s"], {"content_type_starts_with": "text/plain"}),
    ("Prometheus-UI", "/graph", [r"<title>Prometheus", r"Prometheus Time Series"], {}),
    ("Solr", "/solr/", [r"<title>Solr Admin", r"solr-admin-app"], {}),
    ("Adminer", "/adminer.php", [r"<title>.*Adminer", r'class="adminer"'], {}),
    ("Adminer", "/adminer/", [r"<title>.*Adminer", r'class="adminer"'], {}),
    ("Webmin", "/", [r"<title>.*Webmin", r"webmin_search"], {}),
    ("Cockpit", "/", [r"<title>Cockpit</title>", r"cockpit\.js"], {}),
    ("pfSense", "/", [r"<title>.*pfSense", r"pfSenseHelpers"], {}),
    ("OpenVPN-AS", "/", [r"OpenVPN Access Server", r"openvpn-as"], {}),
    ("Splunk", "/en-US/account/login", [r"<title>.*Splunk", r'name="splunkweb_csrf'], {}),
    ("Hadoop-NameNode", "/dfshealth.html", [r"NameNode", r'"beans"\s*:\s*\['], {}),
    ("Airflow", "/login/", [r"<title>.*Airflow|<title>Sign In.*Airflow"], {}),
    ("ArgoCD", "/login", [r"<title>Argo CD", r"argocd-server"], {}),
    ("MinIO", "/minio/health/live", [], {"empty_body": True}),
    ("Portainer", "/", [r"<title>Portainer", r"portainer-host"], {}),
    ("Traefik", "/dashboard/", [r"<title>Traefik|<div\s+id=\"traefik"], {}),
    ("HAProxy-Stats", "/haproxy?stats", [r"HAProxy Statistics Report", r"hap_stat"], {}),
    ("Couchbase", "/pools", [r'"implementationVersion"\s*:', r'"isAdminCreds"\s*:'], {"content_type_starts_with": "application/"}),
    ("MongoDB-REST", "/", [r"It looks like you are trying to access MongoDB"], {}),
]


SENSITIVE_FILES = [
    ("git", "/.git/HEAD", [r"^ref:\s*refs/", r"^[0-9a-f]{40}\s*$"], {"not_html": True}),
    ("svn", "/.svn/entries", [r"^\d+\s*$", r"^dir\s*$"], {"not_html": True}),
    ("env", "/.env", [r"(?m)^[A-Z][A-Z0-9_]+=.+$", r"DB_PASSWORD\s*=", r"APP_KEY\s*="], {"not_html": True}),
    ("robots", "/robots.txt", [r"(?im)^user-agent\s*:", r"(?im)^disallow\s*:"], {"not_html": True}),
    ("sitemap", "/sitemap.xml", [r"<urlset[\s>]", r"<sitemapindex[\s>]"], {}),
    ("server-status", "/server-status", [r"<title>Apache Status", r"Server Version:"], {}),
    ("server-info", "/server-info", [r"<title>Server Information", r"Server Settings"], {}),
    ("htaccess", "/.htaccess", [r"(?im)^RewriteEngine\s+On", r"(?im)^Order\s+allow"], {"not_html": True}),
    ("wp-config-bak", "/wp-config.php.bak", [r"DB_PASSWORD", r"AUTH_KEY"], {"not_html": True}),
    ("phpinfo", "/phpinfo.php", [r"<title>phpinfo\(\)", r">PHP Version<"], {}),
    ("info", "/info.php", [r"<title>phpinfo\(\)", r">PHP Version<"], {}),
    ("composer", "/composer.json", [r'^\s*\{\s*"name"\s*:', r'"require"\s*:\s*\{'], {"not_html": True}),
    ("package", "/package.json", [r'^\s*\{\s*"name"\s*:', r'"dependencies"\s*:\s*\{'], {"not_html": True}),
    ("ds_store", "/.DS_Store", [r"^\x00\x00\x00\x01Bud1"], {"not_html": True}),
]


def _compile_entries(entries):
    out = []
    for label, path, sigs, constraints in entries:
        compiled = [re.compile(p, re.IGNORECASE) for p in sigs]
        out.append((label, path, compiled, constraints or {}))
    return out


def _group_by_path(entries):
    """Bundle entries that share a path so we make one HTTP request per
    unique path and run every matching signature against the same response.
    """
    groups = defaultdict(list)
    for label, path, sigs, constraints in entries:
        groups[path].append((label, sigs, constraints))
    return groups


_COMMON_SERVICES = _compile_entries(COMMON_SERVICES)
_SENSITIVE_FILES = _compile_entries(SENSITIVE_FILES)
_COMMON_GROUPS = _group_by_path(_COMMON_SERVICES)
_FILE_GROUPS = _group_by_path(_SENSITIVE_FILES)


class NXCModule:
    """
    Probe common web service and admin panel paths on the target.

    Bundles entries that share a path so we make one request per unique URL,
    runs probes concurrently with a small thread pool, and skips responses
    that look like the captured SPA catch-all baseline. Reports confirmed
    matches with HTTP status and page title; auth-protected paths are
    surfaced once (deduped) as a hint rather than a confirmed service.

    Module by @claude
    """

    name = "http_services"
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
        self.concurrency = 5
        self.probe_delay = 0.0
        self._auth_protected_paths = set()
        self._lock = threading.Lock()
        self._found = 0
        self._host_id = None  # cached so we don't query the DB per match

    def options(self, context, module_options):
        """
        TIMEOUT       Per-request timeout in seconds. Default: 5
        EXTRA         Comma-separated list of additional paths to probe
        FILES         Probe for sensitive files (.git, .env, robots.txt, ...). Default: true
        SHOW_ALL      Show every probed path including 404s and baseline matches. Default: false
        CONCURRENCY   Number of concurrent probe workers. Default: 5
        DELAY         Optional seconds to sleep between probes (per worker). Default: 0
        """
        self.timeout = int(module_options.get("TIMEOUT", 5))
        extra = module_options.get("EXTRA", "")
        self.extra_paths = [p.strip() for p in extra.split(",") if p.strip()]
        self.show_files = module_options.get("FILES", "true").lower() != "false"
        self.show_all = module_options.get("SHOW_ALL", "false").lower() == "true"
        self.concurrency = max(1, int(module_options.get("CONCURRENCY", 5)))
        self.probe_delay = max(0.0, float(module_options.get("DELAY", 0)))

    @staticmethod
    def _extract_title(text):
        if not text:
            return None
        m = _TITLE_RE.search(text)
        raw = m.group(1) if m else None
        if not raw:
            with contextlib.suppress(Exception):
                soup = BeautifulSoup(text, "html.parser")
                tag = soup.title
                raw = tag.get_text() if tag is not None else None
        if not raw:
            return None
        title = _TAG_RE.sub("", raw)
        title = " ".join(title.split()).strip()
        title = "".join(c for c in title if c.isprintable() or c == " ")
        return title[:80] or None

    @staticmethod
    def _read_body(response, cap):
        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                response.close()
        return b"".join(chunks)[:cap]

    def _check_constraints(self, response, body_text, constraints):
        """Return True if the constraints (if any) are satisfied."""
        ct = response.headers.get("Content-Type", "").lower()
        starts_with = constraints.get("content_type_starts_with")
        if starts_with and not ct.startswith(starts_with.lower()):
            return False
        required_header = constraints.get("required_header")
        if required_header and required_header.lower() not in {k.lower() for k in response.headers}:
            return False
        if constraints.get("not_html") and "text/html" in ct:
            return False
        if constraints.get("empty_body"):
            cl = response.headers.get("Content-Length")
            if cl is not None:
                try:
                    if int(cl) != 0:
                        return False
                except ValueError:
                    return False
            elif body_text.strip():
                return False
        return True

    def _fetch(self, connection, path):
        """One streaming GET. Returns (response, body_bytes, body_text)
        or (None, b"", "") on error.
        """
        if self.probe_delay:
            time.sleep(self.probe_delay)
        url = connection.build_url(path)
        try:
            r = connection.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"Probe error for {url}: {e}")
            return None, b"", ""
        cap = getattr(connection, "max_body_size", 262144)
        body_bytes = self._read_body(r, cap)
        encoding = r.encoding or "utf-8"
        try:
            body_text = body_bytes.decode(encoding, errors="replace")
        except (LookupError, UnicodeDecodeError):
            body_text = body_bytes.decode("utf-8", errors="replace")
        return r, body_bytes, body_text

    def _probe_path_group(self, connection, path, entries):
        """Fetch `path` once, evaluate every (label, signatures, constraints)
        entry that targets that path against the same response.
        """
        url = connection.build_url(path)
        r, body_bytes, body_text = self._fetch(connection, path)
        if r is None:
            return

        # Auth-protected: report once per (path, status) regardless of how
        # many entries probe this path.
        if r.status_code in (401, 403):
            with self._lock:
                marker = (path, r.status_code)
                if marker in self._auth_protected_paths:
                    return
                self._auth_protected_paths.add(marker)
            self.context.log.display(f"{url} -> HTTP {r.status_code} (auth-protected)")
            return

        if connection.looks_like_baseline(r.status_code, body_bytes):
            if self.show_all:
                self.context.log.debug(f"{url} -> HTTP {r.status_code} (matches catch-all baseline)")
            return

        if r.status_code != 200:
            if self.show_all:
                self.context.log.debug(f"{url} -> HTTP {r.status_code}")
            return

        # Pre-build the headers blob once for this response.
        headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        title = self._extract_title(body_text)

        for label, signatures, constraints in entries:
            if not self._check_constraints(r, body_text, constraints):
                continue

            if not signatures and constraints.get("empty_body"):
                self._record_hit(connection, label, path, url, r.status_code, title)
                # Don't break: multiple labels may match the same path.
                continue

            matched = any(sig.search(body_text) or sig.search(headers_blob) for sig in signatures)
            if matched:
                self._record_hit(connection, label, path, url, r.status_code, title)

    def _record_hit(self, connection, label, path, url, status, title):
        title_part = f" (title:{title})" if title else ""
        self.context.log.highlight(f"[{label}] {url} -> HTTP {status}{title_part}")
        with self._lock:
            self._found += 1
        if self._host_id is None or not hasattr(connection.db, "add_probe"):
            return
        try:
            connection.db.add_probe(
                host_id=self._host_id, path=path, label=label,
                status_code=status, title=title,
            )
        except Exception as e:
            self.context.log.debug(f"add_probe failed for {label} {path}: {e}")

    def _probe_extra(self, connection, path):
        """Extra paths are always reported when reachable."""
        url = connection.build_url(path)
        r, body_bytes, body_text = self._fetch(connection, path)
        if r is None:
            return
        title = self._extract_title(body_text)
        title_part = f" (title:{title})" if title else ""
        is_baseline = connection.looks_like_baseline(r.status_code, body_bytes)
        baseline_part = " (matches baseline)" if is_baseline else ""
        msg = f"[extra] {url} -> HTTP {r.status_code}{title_part}{baseline_part}"
        if r.status_code == 200 and not is_baseline:
            self.context.log.highlight(msg)
        else:
            self.context.log.display(msg)

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session was not initialized; cannot probe services")
            return

        # Resolve the host_id once so _record_hit can write probes without
        # querying the DB on every match.
        self._host_id = None
        with contextlib.suppress(Exception):
            hosts = [h for h in connection.db.get_hosts(connection.host) if h.port == connection.port]
            if hosts:
                self._host_id = hosts[0].id

        baseline = getattr(connection, "baseline", None)
        if baseline is None or not baseline.captured:
            context.log.display(
                "Baseline 404 probe didn't return; SPA catch-all detection is disabled "
                "(matches may include false positives)"
            )
        else:
            context.log.display(
                f"Baseline 404 probe: HTTP {baseline.status} "
                f"size={baseline.size} hash={baseline.hash[:8]}"
            )

        context.log.display(f"Probing common web services on {connection.url}")

        path_groups = list(_COMMON_GROUPS.items())
        if self.show_files:
            path_groups += list(_FILE_GROUPS.items())

        # Concurrent probing with a small per-host pool.
        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futures = [ex.submit(self._probe_path_group, connection, path, entries)
                       for path, entries in path_groups]
            for f in as_completed(futures):
                with contextlib.suppress(Exception):
                    f.result()

        for path in self.extra_paths:
            self._probe_extra(connection, path)

        if self._found == 0:
            context.log.display("No common web services confirmed")
        else:
            context.log.success(f"{self._found} service match(es) confirmed")
