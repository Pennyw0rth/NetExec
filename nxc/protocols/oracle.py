import re
import socket
import contextlib

import oracledb

from nxc.config import process_secret
from nxc.connection import connection
from nxc.logger import NXCAdapter


class oracle(connection):
    def __init__(self, args, db, host):
        self.protocol = "oracle"
        self.conn = None
        self.instance = None
        self.auth_mode = oracledb.AUTH_MODE_DEFAULT
        self.server_version = ""
        self.tns_version = ""

        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "ORACLE",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def create_conn_obj(self):
        """Confirm the TNS listener is reachable and that a target instance was specified.

        Oracle has no unauthenticated session we can hold open, so the actual connection
        happens per-credential in plaintext_login(). Here we only validate reachability and args.
        """
        if not self.args.service_name and not self.args.sid and not self.args.enum_sids:
            self.logger.fail("Specify the target instance with --service-name or --sid (or use --enum-sids)")
            return False

        self.instance = self.args.service_name if self.args.service_name else self.args.sid
        if self.args.sysdba:
            self.auth_mode = oracledb.AUTH_MODE_SYSDBA
        elif self.args.sysoper:
            self.auth_mode = oracledb.AUTH_MODE_SYSOPER

        try:
            self.tns_version = self.grab_tns_version()
        except Exception as e:
            self.logger.debug(f"Error connecting to Oracle TNS listener on {self.host}:{self.port}, reason: {e}")
            return False
        return True

    def grab_tns_version(self):
        """Send a TNS CONNECT with a probe service name; parse VSNNUM from the REFUSE response.

        The listener always includes VSNNUM in the REFUSE body even for unknown service names.
        VSNNUM is a 32-bit int where the top byte is the Oracle major version.
        Returns a dotted major.minor string, or empty string if parsing fails.
        """
        import struct as _struct
        cd = b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=NXC_PROBE)))"
        offset = 58
        total = offset + len(cd)
        hdr = bytes([(total >> 8) & 0xFF, total & 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
        fields = _struct.pack(">HHHHHHHHHH",
            0x0139, 0x012C, 0x0C41, 0x0800, 0x7FFF,
            0x860E, 0x0000, 0x0001, len(cd), offset,
        )
        fields += b"\x00" * (50 - len(fields))
        sock = socket.create_connection((self.host, self.port), timeout=self.args.oracle_timeout)
        try:
            sock.sendall(hdr + fields + cd)
            data = sock.recv(4096)
        finally:
            sock.close()
        if len(data) <= 8:
            return ""
        body = data[8:].decode("ascii", errors="replace")
        m = re.search(r"VSNNUM=(\d+)", body)
        if not m:
            return ""
        vsnnum = int(m.group(1))
        major = (vsnnum >> 24) & 0xFF
        if major:
            return str(major)
        return ""

    def enum_host_info(self):
        if not self.args.enum_sids:
            return
        common_sids = [
            "XE", "ORCL", "ORCLCDB", "DB11G", "DB12C", "ORACLE",
            "PLSExtProc", "CLRExtProc", "XEXDB",
        ]
        common_services = [
            "XEPDB1", "ORCLPDB1", "ORCL", "PDBORCL", "XE",
            "ORCLCDB", "DB12C", "orcl", "oracle",
        ]
        found = []
        for sid in common_sids:
            err = self.probe_tns_instance(sid, use_sid=True)
            if err not in (12505, 12514, None):
                found.append(f"SID:{sid}")
        for svc in common_services:
            err = self.probe_tns_instance(svc, use_sid=False)
            if err not in (12505, 12514, None):
                found.append(f"ServiceName:{svc}")
        if found:
            for name in found:
                self.logger.highlight(f"Found instance: {name}")
        else:
            self.logger.display("No common SIDs or service names found")

    def probe_tns_instance(self, name, use_sid):
        """Send a TNS CONNECT for the given SID or service name; return the ERR code from the REFUSE body.

        Returns None on network/parse failure, or the integer ERR value.
        ERR 12505/12514 means the instance doesn't exist; anything else means it does.
        """
        import struct as _struct
        key = "SID" if use_sid else "SERVICE_NAME"
        cd = f"(DESCRIPTION=(CONNECT_DATA=({key}={name})))".encode()
        offset = 58
        total = offset + len(cd)
        hdr = bytes([(total >> 8) & 0xFF, total & 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
        fields = _struct.pack(">HHHHHHHHHH",
            0x0139, 0x012C, 0x0C41, 0x0800, 0x7FFF,
            0x860E, 0x0000, 0x0001, len(cd), offset,
        )
        fields += b"\x00" * (50 - len(fields))
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.args.oracle_timeout)
            try:
                sock.sendall(hdr + fields + cd)
                data = sock.recv(4096)
            finally:
                sock.close()
            if len(data) < 5:
                return None
            # REDIRECT (0x0b) or ACCEPT (0x02) both mean the instance exists
            if data[4] in (0x02, 0x0b):
                return 0
            if len(data) <= 8:
                return None
            body = data[8:].decode("ascii", errors="replace")
            m = re.search(r"ERR=(\d+)", body)
            return int(m.group(1)) if m else 0
        except Exception as e:
            self.logger.debug(f"probe_tns_instance({name}): {e}")
            return None

    def print_host_info(self):
        role = ""
        if self.auth_mode == oracledb.AUTH_MODE_SYSDBA:
            role = " (role:SYSDBA)"
        elif self.auth_mode == oracledb.AUTH_MODE_SYSOPER:
            role = " (role:SYSOPER)"
        version_str = f" (version:{self.tns_version})" if self.tns_version else ""
        if self.instance:
            instance_type = "ServiceName" if self.args.service_name else "SID"
            self.logger.display(f"Oracle TNS Listener ({instance_type}:{self.instance}){role}{version_str}")
        else:
            self.logger.display(f"Oracle TNS Listener{role}{version_str}")

    def check_if_admin(self):
        """Determine whether the authenticated principal has DBA-level control.

        Oracle's equivalent of "pwned": a SYSDBA/SYSOPER session, or an account with the
        DBA role, which in practice leads to OS command execution.
        """
        self.admin_privs = False
        if self.auth_mode in (oracledb.AUTH_MODE_SYSDBA, oracledb.AUTH_MODE_SYSOPER):
            self.admin_privs = True
            return
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM session_roles WHERE role = 'DBA'")
            self.admin_privs = cursor.fetchone() is not None
            cursor.close()
        except oracledb.Error as e:
            self.logger.debug(f"Error checking for DBA role: {e}")

    def build_dsn(self):
        if self.args.service_name:
            return f"{self.host}:{self.port}/{self.args.service_name}"
        return oracledb.makedsn(self.host, self.port, sid=self.args.sid)

    def format_oracle_error(self, e):
        """Extract the most actionable error line from an oracledb exception."""
        message = str(e)
        if e.args and getattr(e.args[0], "message", None):
            message = e.args[0].message
        message = re.sub(r"\s*\(CONNECTION_ID=[^)]*\)", "", message)
        lines = [line.strip() for line in message.splitlines() if line.strip() and not line.strip().lower().startswith("help:")]
        return lines[-1] if lines else str(e)

    def plaintext_login(self, username, password):
        self.username = username
        self.password = password

        try:
            self.conn = oracledb.connect(
                user=username,
                password=password,
                dsn=self.build_dsn(),
                mode=self.auth_mode,
            )
        except oracledb.Error as e:
            self.logger.fail(f"{username}:{process_secret(password)} ({self.format_oracle_error(e)})")
            return False

        self.server_version = self.conn.version
        self.check_if_admin()

        role = ""
        if self.auth_mode == oracledb.AUTH_MODE_SYSDBA:
            role = " (SYSDBA)"
        elif self.auth_mode == oracledb.AUTH_MODE_SYSOPER:
            role = " (SYSOPER)"
        self.logger.success(f"{username}:{process_secret(password)} (version:{self.server_version}){role} {self.mark_pwned()}")

        self.db.add_host(self.host, self.port, self.instance, self.server_version)
        cred_id = self.db.add_credential(username, password)
        host_id = self.db.get_host_id(self.host, self.instance)
        self.db.add_loggedin_relation(cred_id, host_id)

        if not self.args.continue_on_success:
            return True

    def disconnect(self):
        if self.conn:
            with contextlib.suppress(Exception):
                self.conn.close()

    def query_execute(self, query):
        """Execute a SQL query and return (columns, rows), or (None, None) on error.

        Non-SELECT statements (DDL/DML) have no description/rows to fetch; they are
        executed and committed, returning ([], []) rather than being treated as an error.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(query)
            if cursor.description is None:
                self.conn.commit()
                cursor.close()
                return [], []
            columns = [col[0] for col in cursor.description]
            results = cursor.fetchall()
            cursor.close()
            return columns, results
        except oracledb.Error as e:
            self.logger.fail(f"Query error: {self.format_oracle_error(e)}")
            return None, None

    def list_databases(self):
        """List pluggable databases (PDBs) — Oracle's equivalent of MSSQL databases.

        Requires access to v$pdbs (typically DBA or SELECT_CATALOG_ROLE).
        Falls back to showing the current database name for unprivileged users.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT name, open_mode FROM v$pdbs ORDER BY name")
            rows = cursor.fetchall()
            cursor.close()
        except oracledb.Error:
            rows = None
        if rows:
            self.logger.success("Pluggable Databases (PDBs):")
            self.logger.highlight(f"  {'Name':<30} {'Open Mode':<15}")
            self.logger.highlight(f"  {'-' * 30} {'-' * 15}")
            for row in rows:
                self.logger.highlight(f"  {row[0]:<30} {row[1]:<15}")
            self.logger.highlight(f"  Total: {len(rows)} PDB(s)")
        else:
            # Unprivileged user — show what we can
            columns, fallback = self.query_execute("SELECT ora_database_name FROM dual")
            if fallback:
                self.logger.display(f"Connected to database: {fallback[0][0]}")
            self.logger.fail("Cannot list PDBs (insufficient privileges for v$pdbs)")

    def list_tables(self, owner):
        """List tables owned by a specific schema/user."""
        safe_owner = owner.replace("'", "''").upper()
        columns, rows = self.query_execute(f"SELECT table_name, num_rows FROM all_tables WHERE owner = '{safe_owner}' ORDER BY table_name")
        if rows is None:
            return
        if not rows:
            self.logger.display(f"No tables found for schema: {safe_owner}")
            return
        self.logger.success(f"Tables in schema {safe_owner}:")
        self.logger.highlight(f"  {'Table Name':<40} {'Row Count':<15}")
        self.logger.highlight(f"  {'-' * 40} {'-' * 15}")
        for row in rows:
            row_count = str(row[1]) if row[1] is not None else "N/A"
            self.logger.highlight(f"  {row[0]:<40} {row_count:<15}")
        self.logger.highlight(f"  Total: {len(rows)} table(s)")

    def dblinks(self):
        """Enumerate database links — a classic lateral movement vector.

        DBA_DB_LINKS exposes the remote username and target host/connect string, but Oracle
        never exposes the stored password via SQL (even to SYSDBA), so none is shown here.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT owner, db_link, username, host FROM dba_db_links ORDER BY owner, db_link")
            rows = cursor.fetchall()
            cursor.close()
        except oracledb.Error:
            rows = None

        if rows is None:
            columns, rows = self.query_execute("SELECT NULL, db_link, username, host FROM all_db_links ORDER BY db_link")
            if rows is None:
                return

        if not rows:
            self.logger.display("No database links found")
            return

        self.logger.success(f"Database links ({len(rows)}):")
        for owner, db_link, username, host in rows:
            owner_prefix = f"{owner}." if owner else ""
            self.logger.highlight(f"  {owner_prefix}{db_link}")
            self.logger.highlight(f"    Remote user: {username or '(none / CURRENT_USER)'}")
            self.logger.highlight(f"    Target:      {host}")

    def database(self):
        """Handle --database flag: no value lists PDBs, a value lists tables in that schema."""
        if self.args.database is True:
            self.list_databases()
        elif isinstance(self.args.database, str):
            self.list_tables(self.args.database)

    def users(self):
        """Enumerate database users. DBA sees account status; unprivileged sees usernames only."""
        # Try dba_users first (includes account_status), fall back to all_users
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT username, account_status, default_tablespace FROM dba_users ORDER BY username")
            rows = cursor.fetchall()
            cursor.close()
        except oracledb.Error:
            rows = None

        if rows:
            open_count = sum(1 for r in rows if r[1] == "OPEN")
            self.logger.success(f"Database users ({len(rows)} total, {open_count} OPEN):")
            self.logger.highlight(f"  {'Username':<30} {'Status':<20} {'Default Tablespace':<20}")
            self.logger.highlight(f"  {'-' * 30} {'-' * 20} {'-' * 20}")
            for row in rows:
                self.logger.highlight(f"  {row[0]:<30} {row[1]:<20} {row[2]:<20}")
        else:
            # Fallback: all_users is available to any authenticated user
            columns, rows = self.query_execute("SELECT username, created FROM all_users ORDER BY username")
            if rows is None:
                return
            self.logger.success(f"Database users ({len(rows)} visible via all_users):")
            self.logger.highlight(f"  {'Username':<30} {'Created':<25}")
            self.logger.highlight(f"  {'-' * 30} {'-' * 25}")
            for row in rows:
                created = row[1].strftime("%Y-%m-%d %H:%M:%S") if hasattr(row[1], "strftime") else str(row[1])
                self.logger.highlight(f"  {row[0]:<30} {created:<25}")
            self.logger.display("Note: use a DBA account to see account status (OPEN/LOCKED)")

    def roles(self):
        """Show the current session's roles and system privileges."""
        columns, role_rows = self.query_execute("SELECT role FROM session_roles ORDER BY role")
        if role_rows is not None:
            if role_rows:
                self.logger.success(f"Session roles ({len(role_rows)}):")
                for row in role_rows:
                    self.logger.highlight(f"  {row[0]}")
            else:
                self.logger.display("No roles enabled in current session")

        columns, priv_rows = self.query_execute("SELECT privilege FROM session_privs ORDER BY privilege")
        if priv_rows is not None:
            if priv_rows:
                self.logger.success(f"System privileges ({len(priv_rows)}):")
                for row in priv_rows:
                    self.logger.highlight(f"  {row[0]}")
            else:
                self.logger.display("No system privileges in current session")

    def tablespaces(self):
        """List tablespaces. DBA sees sizes; unprivileged sees names only."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT t.tablespace_name, t.status, "
                "ROUND(SUM(d.bytes) / 1024 / 1024) AS size_mb "
                "FROM dba_tablespaces t "
                "JOIN dba_data_files d ON t.tablespace_name = d.tablespace_name "
                "GROUP BY t.tablespace_name, t.status "
                "ORDER BY t.tablespace_name"
            )
            rows = cursor.fetchall()
            cursor.close()
        except oracledb.Error:
            rows = None

        if rows:
            self.logger.success(f"Tablespaces ({len(rows)}):")
            self.logger.highlight(f"  {'Tablespace':<30} {'Status':<12} {'Size (MB)':<12}")
            self.logger.highlight(f"  {'-' * 30} {'-' * 12} {'-' * 12}")
            for row in rows:
                size = str(row[2]) if row[2] is not None else "N/A"
                self.logger.highlight(f"  {row[0]:<30} {row[1]:<12} {size:<12}")
        else:
            # Fallback for unprivileged users
            columns, rows = self.query_execute("SELECT tablespace_name FROM user_tablespaces ORDER BY tablespace_name")
            if rows is None:
                return
            self.logger.success(f"Tablespaces ({len(rows)} visible):")
            for row in rows:
                self.logger.highlight(f"  {row[0]}")
            self.logger.display("Note: use a DBA account to see status and sizes")

    # Literal markers Oracle writes into sys.user$.password instead of a real hash, for
    # accounts that don't authenticate with a local verifier at all.
    NON_LOCAL_AUTH_MARKERS = {"EXTERNAL", "GLOBAL"}

    def hash_verifier_priority(self):
        """Order of verifier types to try, newest-first for the connected DB's major version.

        Oracle keeps older verifier types in SPARE4 alongside newer ones for backward
        compatibility with older clients, so a 12c+ database can still carry an 11g SHA-1
        verifier for the same account. We want exactly one hash per account — the one that
        actually matches the DB's auth generation — rather than dumping every type it kept
        around for compat.
        """
        try:
            major = int(self.server_version.split(".")[0])
        except (ValueError, AttributeError, IndexError):
            major = None

        sha512_12c = ("T", 12300, "SHA512/12c+")
        sha1_11g = ("S", 112, "SHA1/11g")
        legacy_des = ("legacy", 3100, "DES/legacy")

        if major is not None and major >= 12:
            return (sha512_12c, sha1_11g, legacy_des)
        if major == 11:
            return (sha1_11g, legacy_des, sha512_12c)
        return (legacy_des, sha1_11g, sha512_12c)

    def dump_hashes(self):
        """Dump one password verifier per account from sys.user$ for offline cracking. Requires SYSDBA.

        Oracle stores up to three verifier types depending on version/config: a legacy DES
        hash (PASSWORD column), an 11g SHA-1 verifier, and a 12c+ SHA-512/PBKDF2 verifier
        (both in SPARE4) — see hash_verifier_priority() for how the right one is picked.
        type# = 1 filters out roles (sys.user$ also stores role entries, e.g. CONNECT, DBA,
        which have no password of their own). Accounts that authenticate externally/globally
        carry a literal marker instead of a hash and are reported as such, not as crackable
        DES hashes. Values are extracted exactly as Oracle stores them — verify the exact
        input format your hashcat/john version expects for the reported mode.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT u.name, u.password, u.spare4, du.account_status "
                "FROM sys.user$ u LEFT JOIN dba_users du ON du.username = u.name "
                "WHERE u.type# = 1 ORDER BY u.name"
            )
            rows = cursor.fetchall()
            cursor.close()
        except oracledb.Error as e:
            hint = " — this typically requires --sysdba" if self.auth_mode != oracledb.AUTH_MODE_SYSDBA else ""
            self.logger.fail(f"Cannot read sys.user$: {self.format_oracle_error(e)}{hint}")
            return

        priority = self.hash_verifier_priority()
        accounts = []
        non_local = []
        for name, password, spare4, status in rows:
            if password and password.upper() in self.NON_LOCAL_AUTH_MARKERS:
                non_local.append((name, password, status))
                continue
            verifier = None
            for key, mode, label in priority:
                if key == "legacy":
                    if password:
                        verifier = (label, mode, password)
                        break
                else:
                    match = re.search(rf"{key}:([0-9A-Fa-f]+)", spare4 or "")
                    if match:
                        verifier = (label, mode, match.group(1))
                        break
            if verifier:
                accounts.append((name, status, verifier))

        if not accounts and not non_local:
            self.logger.fail("No extractable password verifiers found")
            return

        if accounts:
            self.logger.success(f"Password hashes for {len(accounts)} account(s):")
            hashcat_lines = {}
            for name, status, (label, mode, value) in accounts:
                status_tag = f" [{status}]" if status else ""
                self.logger.highlight(f"  {name}{status_tag} [{label}, hashcat -m {mode}] {value}")
                hashcat_lines.setdefault(mode, []).append(f"{name}:{value}")

            self.logger.display("Lines below are ready to save as hashcat input files, one per mode:")
            for mode, lines in sorted(hashcat_lines.items()):
                self.logger.highlight(f"  -- hashcat -m {mode} --")
                for line in lines:
                    self.logger.highlight(f"  {line}")

        if non_local:
            self.logger.display(f"{len(non_local)} account(s) use external/global authentication (no local hash):")
            for name, marker, status in non_local:
                status_tag = f" [{status}]" if status else ""
                self.logger.highlight(f"  {name}{status_tag} ({marker})")

    def query(self):
        """Execute an arbitrary SQL query supplied via -q/--query."""
        columns, rows = self.query_execute(self.args.query)
        if columns is None:
            return
        if not columns:
            self.logger.success("Statement executed successfully (no rows returned)")
            return
        if not rows:
            self.logger.display("Query returned no results")
            return

        # Compute column widths: max of header vs data, capped at 50
        widths = []
        for i, col in enumerate(columns):
            max_data = max((len(str(row[i])) for row in rows), default=0)
            widths.append(min(max(len(col), max_data), 50))

        header = "  ".join(f"{col:<{w}}" for col, w in zip(columns, widths, strict=False))
        separator = "  ".join("-" * w for w in widths)
        self.logger.success(f"Query result ({len(rows)} row(s)):")
        self.logger.highlight(f"  {header}")
        self.logger.highlight(f"  {separator}")
        for row in rows:
            line = "  ".join(f"{val!s:<{w}}" for val, w in zip(row, widths, strict=False))
            self.logger.highlight(f"  {line}")
