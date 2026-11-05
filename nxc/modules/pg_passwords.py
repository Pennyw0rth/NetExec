import psycopg

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Lists passwords present on the PostgreSQL server
    Module by end0x1
    """

    name = "pg_passwords"
    description = "Lists passwords present on the PostgreSQL server"
    supported_protocols = ["postgres"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

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

        query = """SELECT rolname, rolpassword
                    FROM pg_catalog.pg_authid
                    WHERE rolcanlogin = true
                    AND rolpassword IS NOT NULL;
"""

        try:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as e:
            context.log.fail(f"Error while querying passwords: {e}")
            return
        finally:
            conn.close()

        if not rows:
            context.log.fail("No passwords returned")
            return

        context.log.success(f"Found {len(rows)} password(s)")
        context.log.highlight(f"{'USERNAME':<25}{'PASS':<50}")

        for username, password in rows:
            context.log.highlight(f"{username:<25}{password:<50}")
