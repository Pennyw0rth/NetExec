import re
import warnings

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import SSLError
from urllib3.exceptions import InsecureRequestWarning

from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.logger import NXCAdapter
from nxc.config import process_secret


class http(connection):
    """
    NetExec HTTP protocol

    Basic Auth flow:
      - Probe (GET) unauthenticated
      - If 401 + WWW-Authenticate: Basic => try HTTP Basic credentials
      - 2xx/3xx => success, store host + credential in DB

    TLS:
      - verify=True by default
      - --insecure => verify=False (silence urllib3 warning)
      - --ca-file <path> => verify=<path>

    Important: when TLS verification fails (without --insecure),
    we print a visible TLS error so it's clear why --insecure/--ca-file is needed.
    """

    def __init__(self, args, db, host):
        self.protocol = "HTTP"

        self.session = None
        self.probe_resp = None

        self.remote_server = None
        self.remote_realm = None
        self.remote_status = None

        self._verify = True

        super().__init__(args, db, host)

    def proto_logger(self):
        # port may still be None here; set a safe placeholder and update later
        safe_port = self.port if self.port is not None else 0
        self.logger = NXCAdapter(
            extra={
                "protocol": "HTTP",
                "host": self.host,
                "port": safe_port,
                "hostname": self.hostname,
            }
        )

    def proto_flow(self):
        self.proto_logger()

        if self.create_conn_obj() and self.login():
            if hasattr(self.args, "module") and self.args.module:
                self.load_modules()
                self.logger.debug("Calling modules")
                self.call_modules()
            else:
                self.logger.debug("Calling command arguments")
                self.call_cmd_args()

    # ---------- Helpers ----------
    def _scheme(self):
        return "https" if getattr(self.args, "ssl", False) else "http"

    def _path(self):
        p = getattr(self.args, "path", "/") or "/"
        return p if p.startswith("/") else f"/{p}"

    def _host_for_url(self):
        # bracket IPv6 literals for URLs
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]"
        return self.host

    def _default_port(self):
        return 443 if getattr(self.args, "ssl", False) else 80

    def _url(self):
        return f"{self._scheme()}://{self._host_for_url()}:{self.port}{self._path()}"

    def _headers(self):
        vhost = getattr(self.args, "vhost", None)
        if vhost:
            return {"Host": vhost, "User-Agent": "NetExec-HTTP"}
        return {"User-Agent": "NetExec-HTTP"}

    @staticmethod
    def _parse_basic_realm(www_authenticate: str):
        if not www_authenticate:
            return None
        m = re.search(r'Basic\s+realm="([^"]+)"', www_authenticate, re.IGNORECASE)
        return m.group(1) if m else None

    def _timeout(self):
        t = getattr(self.args, "timeout", None)
        return t if t else 6

    def _tls_verify_value(self):
        ca_file = getattr(self.args, "ca_file", None)
        if ca_file:
            return ca_file
        if getattr(self.args, "insecure", False):
            return False
        return True

    def _request(self, auth=None):
        return self.session.get(
            self._url(),
            headers=self._headers(),
            auth=auth,
            timeout=self._timeout(),
            allow_redirects=getattr(self.args, "follow_redirects", False),
            verify=self._verify,
        )

    def _show_tls_error(self, e: Exception):
        """
        Make TLS verification failures visible in normal (non-debug) output.
        """
        # keep it short but useful; requests/ssl errors can be very long
        msg = str(e)
        if len(msg) > 220:
            msg = msg[:220] + "..."
        hint = ""
        if getattr(self.args, "ssl", False) and not getattr(self.args, "insecure", False) and not getattr(self.args, "ca_file", None):
            hint = " (try --insecure or --ca-file)"
        self.logger.fail(f"TLS verify failed{hint}: {msg}")

    # ---------- NetExec hooks ----------
    def create_conn_obj(self):
        self.session = requests.Session()

        # Default port selection
        if getattr(self.args, "port", None) is None:
            self.port = self._default_port()
        else:
            self.port = int(self.args.port)

        # Update logger extras now that port is known (prevents NoneType formatting crash)
        if hasattr(self, "logger") and hasattr(self.logger, "extra"):
            self.logger.extra["port"] = self.port

        # TLS verify handling
        self._verify = self._tls_verify_value()

        # Only silence urllib3 warnings when user explicitly asked for insecure
        if self._verify is False:
            warnings.simplefilter("ignore", InsecureRequestWarning)

        try:
            self.probe_resp = self._request(auth=None)
        except SSLError as e:
            # Visible signal that --insecure/--ca-file is needed
            self._show_tls_error(e)
            self.logger.debug(f"TLS error during probe: {e!r}")
            return False
        except Exception as e:
            self.logger.debug(f"Connection failed: {e}")
            return False

        return True

    def enum_host_info(self):
        if not self.probe_resp:
            return

        self.remote_status = self.probe_resp.status_code
        self.remote_server = self.probe_resp.headers.get("Server", "") or ""
        www = self.probe_resp.headers.get("WWW-Authenticate", "") or ""
        self.remote_realm = self._parse_basic_realm(www)

        self.logger.debug(
            f"HTTP probe status={self.remote_status} server='{self.remote_server}' realm='{self.remote_realm}'"
        )

    def print_host_info(self):
        parts = []
        if self.remote_status is not None:
            parts.append(str(self.remote_status))
        if self.remote_server:
            parts.append(self.remote_server)
        if self.remote_realm:
            parts.append(f"realm={self.remote_realm}")
        if parts:
            self.logger.display(" ".join(parts))

    def plaintext_login(self, username, password):
        if not self.session or not self.probe_resp:
            if not self.create_conn_obj():
                return False

        self.enum_host_info()

        www = self.probe_resp.headers.get("WWW-Authenticate", "") or ""
        is_basic = "basic" in www.lower()
        unauth_status = self.probe_resp.status_code

        if not (unauth_status == 401 and is_basic):
            self.logger.info(f"No HTTP Basic challenge on {self._path()} (status={unauth_status})")
            return False

        try:
            r = self._request(auth=HTTPBasicAuth(username, password))
        except SSLError as e:
            self._show_tls_error(e)
            self.logger.debug(f"TLS error during auth request: {e!r}")
            return False
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} (Error:{e})")
            return False

        auth_status = r.status_code
        server = r.headers.get("Server", "") or ""
        realm = self._parse_basic_realm(r.headers.get("WWW-Authenticate", "") or "") or self.remote_realm

        # Store host metadata
        try:
            self.db.add_host(
                ip=self.host,
                hostname=None,
                domain="",
                port=self.port,
                ssl=getattr(self.args, "ssl", False),
                vhost=getattr(self.args, "vhost", None),
                path=getattr(self.args, "path", "/"),
                realm=realm,
                server=server if server else self.remote_server,
                status=auth_status,
            )
        except Exception as e:
            self.logger.debug(f"DB add_host failed: {e}")

        if auth_status == 401:
            self.logger.fail(f"{username}:{process_secret(password)} (401 Unauthorized)")
            return False

        if 200 <= auth_status < 400:
            msg = f"{username}:{process_secret(password)}"
            if realm:
                msg += f" {highlight(f'(realm={realm})')}"
            self.logger.success(msg)

            try:
                self.db.add_credential("basic", "", username, password, pillaged_from=None)
            except Exception as e:
                self.logger.debug(f"DB add_credential failed: {e}")

            return True

        self.logger.info(f"{username}:{process_secret(password)} (status={auth_status})")
        return False
