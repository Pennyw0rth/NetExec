from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.backupkey import BackupkeyTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file


def get_domain_backup_key(context):
    pvkbytes = None
    try:
        results = context.db.get_domain_backupkey(context.domain)
    except Exception:
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
            dc_target = Target.create(
                domain=context.domain,
                username=context.username,
                password=context.password,
                target=context.domain,  # querying DNS server for domain will return DC
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

def collect_masterkeys_from_target(context, target, dploot_connection, user=True, system=True):
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
        if context.password != "":
            plaintexts[context.username] = context.password
        if context.nthash != "":
            nthashes[context.username] = context.nthash

    # Collect User and Machine masterkeys
    try:
        context.logger.display("Collecting DPAPI masterkeys, grab a coffee and be patient...")
        masterkeys_triage = MasterkeysTriage(
            target=target,
            conn=dploot_connection,
            pvkbytes=context.pvkbytes,
            passwords=plaintexts,
            nthashes=nthashes,
            dpapiSystem={},
        )
        context.logger.debug(f"Masterkeys Triage: {masterkeys_triage}")
        if user:
            context.logger.debug("Collecting user masterkeys")
            masterkeys += masterkeys_triage.triage_masterkeys()
        if system:
            context.logger.debug("Collecting machine masterkeys")
            masterkeys += masterkeys_triage.triage_system_masterkeys()
    except Exception as e:
        context.logger.debug(f"Could not get masterkeys: {e}")

    return masterkeys

def upgrade_to_dploot_connection(target, connection=None):
    conn = None
    try:
        conn = DPLootSMBConnection(target)
        if connection is not None:
            conn.smb_session = connection
            conn.connect()
    except Exception:
        return None
    return conn