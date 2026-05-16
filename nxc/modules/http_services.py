import re
import contextlib

import requests
from bs4 import BeautifulSoup

from nxc.helpers.misc import CATEGORY


COMMON_SERVICES = [
    # (label, path, signature regex matched against body)
    ("phpMyAdmin", "/phpmyadmin/", r"phpMyAdmin"),
    ("phpMyAdmin", "/phpMyAdmin/", r"phpMyAdmin"),
    ("Jenkins", "/", r"X-Jenkins|Jenkins ver\."),
    ("Jenkins-Login", "/login", r"Jenkins"),
    ("Tomcat-Manager", "/manager/html", r"Tomcat|Application Manager"),
    ("Tomcat-HostManager", "/host-manager/html", r"Tomcat|Host Manager"),
    ("Spring-Actuator", "/actuator", r"_links|health|self"),
    ("Spring-Env", "/actuator/env", r"activeProfiles|systemProperties"),
    ("GitLab", "/users/sign_in", r"GitLab"),
    ("Gitea", "/user/login", r"Gitea"),
    ("Grafana", "/login", r"Grafana"),
    ("Kibana", "/app/kibana", r"Kibana"),
    ("Kibana", "/api/status", r"kibana"),
    ("Elasticsearch", "/", r'"cluster_name"|"tagline"\s*:\s*"You Know, for Search"'),
    ("Elasticsearch-CAT", "/_cat/indices", r"^[a-z]"),
    ("WordPress-Admin", "/wp-login.php", r"WordPress|wp-submit"),
    ("WordPress-API", "/wp-json/", r"namespaces|routes"),
    ("Drupal-Login", "/user/login", r"Drupal|drupal-"),
    ("Joomla-Admin", "/administrator/", r"Joomla"),
    ("Confluence", "/login.action", r"Confluence|Atlassian"),
    ("Jira", "/login.jsp", r"JIRA|Atlassian"),
    ("Nextcloud", "/login", r"Nextcloud"),
    ("ownCloud", "/login", r"ownCloud"),
    ("Magento-Admin", "/admin", r"Magento"),
    ("RabbitMQ", "/", r"RabbitMQ Management"),
    ("Consul", "/v1/status/leader", r"^\"\d+\.\d+\.\d+\.\d+:\d+\""),
    ("Vault", "/v1/sys/health", r"initialized|sealed"),
    ("Kubernetes-API", "/version", r"gitVersion|gitCommit"),
    ("Docker-API", "/version", r"ApiVersion|GoVersion"),
    ("Etcd", "/version", r"etcdserver"),
    ("Prometheus", "/metrics", r"# HELP"),
    ("Prometheus", "/graph", r"Prometheus Time Series"),
    ("Solr", "/solr/", r"Solr Admin|/solr/#/"),
    ("Adminer", "/adminer.php", r"Adminer"),
    ("Webmin", "/", r"Webmin"),
    ("Cockpit", "/", r"Cockpit"),
    ("pfSense", "/", r"pfSense"),
    ("OpenVPN-AS", "/", r"OpenVPN Access Server"),
    ("Splunk", "/en-US/account/login", r"Splunk"),
    ("Hadoop-NameNode", "/dfshealth.html", r"NameNode"),
    ("Spark-UI", "/", r"Spark Master|Spark Jobs"),
    ("Airflow", "/login/", r"Airflow"),
    ("ArgoCD", "/login", r"argocd|Argo CD"),
    ("MinIO", "/minio/health/live", r".*"),
    ("Portainer", "/", r"Portainer"),
    ("Traefik", "/dashboard/", r"Traefik"),
    ("HAProxy-Stats", "/haproxy?stats", r"HAProxy"),
    ("Couchbase", "/pools", r"couchbase|implementationVersion"),
    ("MongoDB-REST", "/", r"It looks like you are trying to access MongoDB"),
]


SENSITIVE_FILES = [
    ("git", "/.git/HEAD", r"^ref:"),
    ("svn", "/.svn/entries", r".+"),
    ("env", "/.env", r"(APP_|DB_|SECRET|TOKEN|PASSWORD)"),
    ("robots", "/robots.txt", r"User-agent"),
    ("sitemap", "/sitemap.xml", r"urlset|sitemapindex"),
    ("backup-sql", "/backup.sql", r".+"),
    ("server-status", "/server-status", r"Server Status"),
    ("server-info", "/server-info", r"Server Information"),
    ("ds_store", "/.DS_Store", r".+"),
    ("htaccess", "/.htaccess", r"RewriteEngine|Order allow"),
    ("config-php", "/config.php", r".+"),
    ("wp-config-bak", "/wp-config.php.bak", r"DB_PASSWORD|DB_USER"),
    ("phpinfo", "/phpinfo.php", r"phpinfo\(\)|PHP Version"),
    ("info", "/info.php", r"phpinfo\(\)|PHP Version"),
    ("composer", "/composer.json", r'"name"\s*:'),
    ("package", "/package.json", r'"name"\s*:'),
]


class NXCModule:
    """
    Probe common web service and admin panel paths on the target.

    Inspired by ProjectDiscovery's httpx/wappalyzer: for each path, fetches
    the resource and matches the response body or status code to a known
    fingerprint. Reports the service name, HTTP status, and the page title.

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
        self.show_only_found = True

    def options(self, context, module_options):
        """
        TIMEOUT       Per-request timeout in seconds. Default: 5
        EXTRA         Comma-separated list of additional paths to probe
        FILES         Probe for sensitive files (.git, .env, robots.txt, ...). Default: true
        SHOW_ALL      Show all attempted paths, including 404s. Default: false
        """
        self.timeout = int(module_options.get("TIMEOUT", 5))
        extra = module_options.get("EXTRA", "")
        self.extra_paths = [p.strip() for p in extra.split(",") if p.strip()]
        self.show_files = module_options.get("FILES", "true").lower() != "false"
        self.show_only_found = module_options.get("SHOW_ALL", "false").lower() != "true"

    def _extract_title(self, text):
        if not text:
            return None
        with contextlib.suppress(Exception):
            soup = BeautifulSoup(text, "html.parser")
            tag = soup.title
            if tag and tag.string:
                return " ".join(tag.string.split()).strip()[:80]
        return None

    def _probe(self, connection, path, label, signature):
        url = connection._build_url(path)
        try:
            r = connection.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=connection.args.follow_redirects,
            )
        except requests.exceptions.RequestException as e:
            self.context.log.debug(f"Probe error for {url}: {e}")
            return None

        body = r.text or ""
        matched = False
        if signature:
            matched = bool(re.search(signature, body, re.IGNORECASE)) or bool(re.search(signature, " ".join(r.headers.values()), re.IGNORECASE))

        # status-based hits even when body doesn't match the signature
        status_hit = r.status_code in (200, 401, 403) and not (r.status_code == 200 and not matched and signature)

        if matched or (r.status_code in (401, 403)):
            title = self._extract_title(body)
            title_part = f" (title:{title})" if title else ""
            level = self.context.log.highlight if matched else self.context.log.display
            level(f"[{label}] {url} -> HTTP {r.status_code}{title_part}")
            return True
        if not self.show_only_found and status_hit:
            self.context.log.display(f"[{label}] {url} -> HTTP {r.status_code}")
        return False

    def on_login(self, context, connection):
        self.context = context
        if getattr(connection, "session", None) is None:
            context.log.fail("HTTP session was not initialized; cannot probe services")
            return

        context.log.display(f"Probing common web services on {connection.url}")

        found = 0
        for label, path, signature in COMMON_SERVICES:
            if self._probe(connection, path, label, signature):
                found += 1

        if self.show_files:
            for label, path, signature in SENSITIVE_FILES:
                if self._probe(connection, path, f"file:{label}", signature):
                    found += 1

        for path in self.extra_paths:
            self._probe(connection, path, "extra", None)

        if found == 0:
            context.log.display("No common web services matched")
        else:
            context.log.success(f"{found} match(es) found")
