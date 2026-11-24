import os
import socket
import ssl
import struct

import psycopg
from psycopg import OperationalError

from nxc.connection import connection, highlight
from nxc.logger import NXCAdapter
from nxc.config import process_secret

SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
PROTOCOL_VERSION_3_0 = (3 << 16) | 0
PROBE_MINOR_VERSION = 9999


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def startup_packet(user, database, protocol_version=PROTOCOL_VERSION_3_0):
    params = b"user\x00" + user.encode() + b"\x00" + b"database\x00" + database.encode() + b"\x00\x00"
    body = struct.pack("!I", protocol_version) + params
    return struct.pack("!I", len(body) + 4) + body


class psql(connection):
    def __init__(self, args, db, host):
        self.protocol = "PSQL"
        self.remote_version = "PostgreSQL"
        self.protocol_version = None
        self.admin_privs = False
        self.postgres = False
        self.ssl = False
        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(extra={
            "protocol": "PSQL",
            "host": self.host,
            "port": self.port,
            "hostname": self.hostname,
        })

    @staticmethod
    def protocol_version_to_range(protocol_version):
        if not protocol_version:
            return None
        try:
            _, minor_str = protocol_version.split(".", 1)
            minor = int(minor_str)
        except (ValueError, AttributeError):
            return None

        if minor >= 2:
            return "version >= 18"
        return "version < 18"

    def print_host_info(self):
        info = f"{self.remote_version}"
        version_range = self.protocol_version_to_range(self.protocol_version)
        if version_range:
            info += f" ({version_range})"
        self.logger.display(info)

    def enum_host_info(self):
        self.db.add_host(self.host, self.port, self.remote_version)

    def check_if_admin(self):
        try:
            with self.conn.cursor() as cur:
                cur.execute("SHOW server_version")
                self.remote_version = cur.fetchone()[0]
                cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                row = cur.fetchone()
                self.admin_privs = bool(row[0]) if row else False
        except Exception as e:
            self.logger.fail(f"Error: {e}")

    def probe_protocol_version(self):
        s = None
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.args.psql_timeout)

            if self.ssl:
                s.sendall(SSL_REQUEST)
                if read_exact(s, 1) != b"S":
                    return None
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=self.host)

            probe_version = (3 << 16) | PROBE_MINOR_VERSION
            s.sendall(startup_packet("postgres", self.args.database, protocol_version=probe_version))

            msg_type = read_exact(s, 1)
            length = struct.unpack("!I", read_exact(s, 4))[0]
            body = read_exact(s, length - 4)

            if msg_type == b"v":  # NegotiateProtocolVersion
                raw_version = struct.unpack("!I", body[:4])[0]
                major = raw_version >> 16
                minor = raw_version & 0xFFFF
                return f"{major}.{minor}"
            return None
        except (OSError, struct.error) as e:
            self.logger.debug(f"Protocol version probe failed: {e}")
            return None
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    def create_conn_obj(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.args.psql_timeout)
            s.sendall(SSL_REQUEST)
            response = s.recv(1)
            s.close()
            if response in (b"S", b"N"):
                self.ssl = response == b"S"
                self.postgres = True
                self.protocol_version = self.probe_protocol_version()
        except OSError:
            return False
        return self.postgres

    def plaintext_login(self, username, password):
        self.username = username
        self.password = password
        self.admin_privs = False

        try:
            self.conn = psycopg.connect(
                host=self.host, port=self.port,
                user=username, password=password,
                dbname=self.args.database,
                connect_timeout=self.args.psql_timeout, autocommit=True, passfile=os.path.join(os.devnull, "x")
            )
            self.check_if_admin()
        except OperationalError as e:
            self.logger.fail(f"{username}:{process_secret(password)} {e}")
            return False
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} Error: {e}")
            return False
        hosts = self.db.get_hosts(self.host)
        host_id = hosts[0].id if hosts else None
        cred_id = self.db.add_credential("plaintext", username, password)

        if host_id and cred_id:
            self.db.add_loggedin_relation(cred_id, host_id)
            if self.admin_privs:
                self.db.add_admin_user(cred_id, host_id)

        self.logger.success(
            f"{username}:{process_secret(password)} {self.mark_pwned()} "
            f"{highlight(f'PostgreSQL {self.remote_version}')}"
        )
        return True

    def get_file(self):
        for remote_path, local_path in self.args.get_file:
            try:
                data = self.conn.execute("SELECT pg_read_binary_file(%s)", (remote_path,)).fetchone()[0]
                with open(local_path, "wb") as f:
                    f.write(data)
                self.logger.success(f"Downloaded: {remote_path} -> {local_path}")
            except Exception as e:
                self.logger.fail(f"Error downloading {remote_path}: {e}")

    def put_file(self):
        for local_path, remote_path in self.args.put_file:
            try:
                with open(local_path, "rb") as f, self.conn.transaction():
                    oid = self.conn.execute("SELECT lo_from_bytea(0, %s)", (f.read(),)).fetchone()[0]
                    self.conn.execute("SELECT lo_export(%s, %s)", (oid, remote_path))
                    self.conn.execute("SELECT lo_unlink(%s)", (oid,))
                self.logger.success(f"Uploaded: {local_path} -> {remote_path}")
            except Exception as e:
                self.logger.fail(f"Error uploading {local_path}: {e}")
