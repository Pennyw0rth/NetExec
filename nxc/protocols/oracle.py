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
        if not self.args.service_name and not self.args.sid:
            self.logger.fail("Specify the target instance with --service-name or --sid")
            return False

        self.instance = self.args.service_name if self.args.service_name else self.args.sid
        if self.args.sysdba:
            self.auth_mode = oracledb.AUTH_MODE_SYSDBA
        elif self.args.sysoper:
            self.auth_mode = oracledb.AUTH_MODE_SYSOPER

        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.args.oracle_timeout)
            sock.close()
        except Exception as e:
            self.logger.debug(f"Error connecting to Oracle TNS listener on {self.host}:{self.port}, reason: {e}")
            return False
        return True

    def enum_host_info(self):
        # Version is only known after a successful authentication; nothing to enumerate pre-auth.
        return

    def print_host_info(self):
        instance_type = "ServiceName" if self.args.service_name else "SID"
        role = ""
        if self.auth_mode == oracledb.AUTH_MODE_SYSDBA:
            role = " (role:SYSDBA)"
        elif self.auth_mode == oracledb.AUTH_MODE_SYSOPER:
            role = " (role:SYSOPER)"
        self.logger.display(f"Oracle TNS Listener ({instance_type}:{self.instance}){role}")

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
        """Execute a SQL query and return the results as a list of tuples, or None on error."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            columns = [col[0] for col in cursor.description] if cursor.description else []
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

    def query(self):
        """Execute an arbitrary SQL query supplied via -q/--query."""
        columns, rows = self.query_execute(self.args.query)
        if columns is None:
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
