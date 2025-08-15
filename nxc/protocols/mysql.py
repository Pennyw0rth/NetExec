import socket
import contextlib
from nxc.config import process_secret
from nxc.connection import connection
from nxc.logger import NXCAdapter
from pymysql.connections import Connection
from pymysql.err import OperationalError


class mysql(connection):
    def __init__(self, args, db, host):
        self.protocol = "MySQL"
        self.remote_version = None
        self.server_capabilities = {}
        self._pinged = False
        super().__init__(args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "MySQL",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def create_conn_obj(self):
        """Create the connection object, but defer the actual connection
        Because of how proto_flow works, we do an initial custom socket to ensure there is something on the port,
        then we can get server information with that same socket if there is something there
        """
        self.logger.debug(f"Creating connection object for {self.host}:{self.port}")

        # during the initial connection the username and password are actually blank
        self.conn = Connection(
            host=self.host,
            port=self.port,
            user=self.username,
            password=self.password,
            defer_connect=True,
        )
        self.logger.debug(f"Connection object created for {self.host}:{self.port}")

        # we don't want to do additional useless TCP handshake requests for connect(), etc, so we only "ping" it once
        if not self._pinged:
            self.logger.debug(f"Making initial socket connection to {self.host}:{self.port}")
            try:
                self.conn._sock = socket.create_connection((self.host, self.port))
                self._pinged = True
            except Exception as e:
                self.logger.debug(f"Error creating socket connection: {e}")
                return False
        return True

    def enum_host_info(self):
        """Use existing socket but only get the server information
        The way we do this actually sends less packets than nmap -sV, since they open a socket for ping then don't reuse it
        We also don't want to send a QUIT message, so we use _force_close()
        """
        self.logger.debug("Getting server information")

        try:
            # setup the socket for the server information request
            self.conn._rfile = self.conn._sock.makefile("rb")
            self.conn._next_seq_id = 0
            self.conn._get_server_information()
            if self.conn.server_version:
                self.remote_version = self.conn.server_version
                self.logger.debug(f"Server information: {self.remote_version}")
                try:
                    self.db.add_host(self.host, self.port, self.remote_version)
                except IndexError as e:
                    self.logger.debug(f"Error adding host to DB: {e}, trying one more time...")
                    self.db.add_host(self.host, self.port, self.remote_version)

            with contextlib.suppress(Exception):
                self.conn._force_close()  # close the socket without sending a QUIT message
        except OperationalError as e:
            if "is not allowed to connect to" in str(e):
                self.logger.fail("Host is not allowed to connect to server")
                exit(1)
            else:
                self.logger.fail(f"Error getting server information: {e}")

    def print_host_info(self):
        if self.remote_version:
            self.logger.display(f"MySQL Version: {self.remote_version}")

    def plaintext_login(self, username, password):
        """Authenticate with MySQL server using username/password via pymysql connect
        This is where we actually do the full connection as well
        """
        self.password = password
        self.username = username
        self.create_conn_obj()  # create connection object with username and password

        try:
            self.logger.debug(f"Attempting login with {username}:{process_secret(password)}")
            self.conn.connect()
            self.logger.debug(f"Authenticated to {self.host}:{self.port}")
            self.logger.success(f"{self.username}:{process_secret(self.password)} {self.mark_pwned()}")

            cred_id = self.db.add_credential(username, password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(cred_id, host_id)

            if self.args.query:
                self.execute_query(self.args.query)
            if self.args.databases:
                self.list_databases()
            if self.args.tables:
                self.list_tables(self.args.tables)
            if self.args.dump_database:
                self.dump_database(self.args.dump_database)
            if self.args.server_capabilities:
                self.get_server_capabilities()

            if not self.args.continue_on_success:
                with contextlib.suppress(Exception):
                    self.conn.close()
                return True
            return True
        except Exception as e:
            self.logger.fail(f"{username}:{process_secret(password)} (Response:{e})")
            with contextlib.suppress(Exception):
                if self.conn:
                    self.conn.close()
            return False

    def execute_query(self, query):
        """Execute a custom SQL query"""
        try:
            cursor = self.conn.cursor()
            self.logger.display(f"Executing query: {query}")
            cursor.execute(query)

            if cursor.description:
                results = cursor.fetchall()
                if results:
                    self.logger.display(f"Query Results ({len(results)} rows):")
                    for i, row in enumerate(results):
                        self.logger.highlight(f"Row {i + 1}: {row}")
                else:
                    self.logger.display("Query executed successfully (no results)")
            else:
                affected_rows = cursor.rowcount
                self.logger.display(f"Query executed successfully. {affected_rows} rows affected.")

            cursor.close()
        except Exception as e:
            self.logger.fail(f"Error executing query: {e}")

    def list_databases(self):
        """List all databases"""
        try:
            cursor = self.conn.cursor()
            try:
                cursor.execute("SHOW DATABASES")
            except Exception:
                cursor.execute("SHOW DATABASES LIKE '%'")
            databases = cursor.fetchall()

            if databases:
                self.logger.display(f"Available Databases ({len(databases)}):")
                for db in databases:
                    self.logger.highlight(db[0])
            else:
                self.logger.display("No databases found or access denied.")

            cursor.close()
        except Exception as e:
            self.logger.fail(f"Error listing databases: {e}")

    def list_tables(self, database):
        """List tables in specified database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(f"USE `{database}`")
            try:
                cursor.execute("SHOW TABLES")
            except Exception:
                cursor.execute(f"SHOW TABLES FROM `{database}`")
            tables = cursor.fetchall()

            if tables:
                self.logger.display(f"Tables in {database} ({len(tables)}):")
                for table in tables:
                    self.logger.highlight(table[0])
            else:
                self.logger.display(f"No tables found in database '{database}' or access denied.")

            cursor.close()
        except Exception as e:
            self.logger.fail(f"Error listing tables: {e}")

    def dump_database(self, database):
        """Dump database to stdout"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(f"USE `{database}`")
            try:
                cursor.execute("SHOW TABLES")
            except Exception:
                cursor.execute(f"SHOW TABLES FROM `{database}`")
            tables = cursor.fetchall()

            if not tables:
                self.logger.display(f"No tables found in database '{database}'")
                cursor.close()
                return

            self.logger.display(f"Database dump for {database} ({len(tables)} tables):")

            for table in tables:
                table_name = table[0]
                self.logger.highlight(f"Table: {table_name}")

                try:
                    cursor.execute(f"DESCRIBE `{table_name}`")
                    structure = cursor.fetchall()

                    if structure:
                        self.logger.display("  Schema:")
                        self.logger.display(f"    {'Field':<15} | {'Type':<15} | {'Null':<4} | {'Key':<15} | {'Default':<15} | {'Extra':<15}")
                        self.logger.display(f"    {'-' * 15} | {'-' * 15} | {'-' * 4} | {'-' * 15} | {'-' * 15} | {'-' * 15}")

                        for col in structure:
                            formatted_values = []
                            for idx, value in enumerate(col):
                                # third column is whether the column is nullable, so either YES or NO
                                if idx != 2:
                                    formatted_values.append(f"{value!s:<15}")
                                else:
                                    formatted_values.append(f"{value!s:<4}")
                            self.logger.display(f"    {' | '.join(formatted_values)}")

                    try:
                        cursor.execute(f"SELECT * FROM `{table_name}` LIMIT 5")
                        data = cursor.fetchall()

                        if data:
                            self.logger.display(f"  Data ({len(data)} rows):")
                            for i, row in enumerate(data):
                                self.logger.display(f"    Row {i + 1}: {row}")
                        else:
                            self.logger.display("  Data: No data in table")
                    except Exception as e:
                        self.logger.display(f"  Data: Error reading data - {e}")
                except Exception as e:
                    self.logger.display(f"  Error processing table: {e}")

                self.logger.display("")

            cursor.close()
        except Exception as e:
            self.logger.fail(f"Error dumping database: {e}")

    def get_server_capabilities(self):
        """Get MySQL server capabilities"""
        try:
            cursor = self.conn.cursor()
            capabilities = {}
            try:
                cursor.execute("SHOW VARIABLES LIKE 'have_ssl'")
                result = cursor.fetchone()
                capabilities["ssl"] = result[1] if result else "Unknown"
            except Exception:
                capabilities["ssl"] = "Not supported"
            try:
                cursor.execute("SHOW PLUGINS")
                plugins = cursor.fetchall()
                auth_plugins = [row[1] for row in plugins if "auth" in row[1].lower()]
                capabilities["auth_plugins"] = auth_plugins
            except Exception:
                capabilities["auth_plugins"] = ["Unknown"]
            try:
                cursor.execute("SELECT @@sql_mode")
                result = cursor.fetchone()
                capabilities["sql_mode"] = result[0] if result else "Unknown"
            except Exception:
                capabilities["sql_mode"] = "Unknown"
            cursor.close()

            self.server_capabilities = capabilities
            self.logger.display("Server capabilities:")
            self.logger.display(f"    SSL: {capabilities['ssl']}")
            self.logger.display(f"    Auth plugins: {capabilities['auth_plugins']}")
            self.logger.display(f"    SQL mode: {capabilities['sql_mode']}")
        except Exception as e:
            self.logger.debug(f"Error getting server capabilities: {e}")
            return {}
