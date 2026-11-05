import psycopg

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    List all databases on a PostgreSQL server, with size, owner and connection status
    Module by end0x1
    """

    name = "pg_databases"
    description = "Lists all databases present on the PostgreSQL server"
    supported_protocols = ["postgres"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """NO-TEMPLATES  Hide template databases (template0/template1) from the output (default: False)"""
        self.hide_templates = False
        if "NO-TEMPLATES" in module_options:
            self.hide_templates = module_options["NO-TEMPLATES"].lower() in ("true", "1", "yes")

    def on_login(self, context, connection):
        """Runs once credentials have been validated by postgres.plaintext_login()."""
        try:
            conn = psycopg.connect(
                host=connection.host,
                port=connection.port,
                user=connection.username,
                password=connection.password,
                dbname=connection.args.database,
                connect_timeout=connection.args.postgres_timeout,
            )
        except Exception as e:
            context.log.fail(f"Could not open a connection to enumerate databases: {e}")
            return

        query = """
            SELECT
                d.datname,
                pg_catalog.pg_get_userbyid(d.datdba) AS owner,
                pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname)) AS size,
                d.datistemplate,
                d.datallowconn
            FROM pg_catalog.pg_database d
            ORDER BY d.datname;
        """

        try:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as e:
            context.log.fail(f"Error while querying pg_database: {e}")
            return
        finally:
            conn.close()

        if not rows:
            context.log.fail("No databases returned")
            return

        context.log.success(f"Found {len(rows)} database(s)")
        context.log.highlight(f"{'DATABASE':<25}{'OWNER':<20}{'SIZE':<12}{'TEMPLATE':<10}{'ALLOW CONN'}")

        for datname, owner, size, is_template, allow_conn in rows:
            if self.hide_templates and is_template:
                continue
            context.log.highlight(
                f"{datname:<25}{owner:<20}{size:<12}{'Yes' if is_template else 'No':<10}"
                f"{'Yes' if allow_conn else 'No'}"
            )
