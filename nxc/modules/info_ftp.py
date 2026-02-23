# -*- coding: utf-8 -*-


from ftplib import FTP
import re

class NXCModule:
    """
    Module by: @m7arm4n
    info_ftp — Ultimate clean FTP fingerprint + real STATUS + stealth RCE detection
    """
    name = "info_ftp"
    description = "Ultimate FTP intel — banner, features, write test, real STATUS + stealth RCE check"
    supported_protocols = ["ftp"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        user = context.username[0] if isinstance(context.username, list) else context.username
        pwd  = context.password[0] if isinstance(context.password, list) else (context.password or "")
        host = connection.host
        port = connection.port or 21

        ftp = FTP()
        can_write = rce = False

        try:
            ftp.connect(host, port, timeout=12)
            banner = ftp.getwelcome().strip()
            connection.logger.highlight(f"[Banner] {banner}")

            ftp.login(user, pwd if pwd else "")

            # === OS Type ===
            try:
                connection.logger.highlight(f"[OS] {ftp.sendcmd('SYST').strip()}")
            except:
                connection.logger.highlight("[OS] Not supported")

            # === Features ===
            try:
                feat = ftp.sendcmd("FEAT")
                lines = [l.strip() for l in feat.splitlines() if l.strip() and not l.startswith("211")]
                connection.logger.highlight(f"[Features] {len(lines)} supported commands")
                for line in lines:
                    connection.logger.highlight(f"  → {line}")
            except:
                connection.logger.highlight("[Features] Not supported")

            # === Current Directory ===
            try:
                connection.logger.highlight(f"[CWD] {ftp.pwd()}")
            except:
                pass

            # === Write Test ===
            test_file = f".nxc_tmp_{id(object())}"
            try:
                with open(__file__, "rb") as f:
                    ftp.storbinary(f"STOR {test_file}", f)
                ftp.delete(test_file)
                can_write = True
                connection.logger.highlight("[Write] YES — You have write access!")
            except:
                connection.logger.highlight("[Write] NO — Read-only")

            # === UTF8 Support ===
            try:
                ftp.sendcmd("OPTS UTF8 ON")
                connection.logger.highlight("[UTF8] Supported")
            except:
                connection.logger.highlight("[UTF8] Not supported")

            # === MLSD Support ===
            try:
                ftp.sendcmd("MLSD")
                connection.logger.highlight("[MLSD] Supported (modern server)")
            except:
                connection.logger.highlight("[MLSD] Not supported")

            # === Real ftp> status output ===
            connection.logger.highlight("[STATUS] Client connection status:")
            try:
                status_lines = ftp.sendcmd("STAT").splitlines()
                for line in status_lines[1:]:
                    line = line.strip()
                    if line and not line.startswith("211"):
                        connection.logger.highlight(f"  → {line}")
            except:
                connection.logger.highlight("  → Not available")

            # === STEALTH RCE Detection ===
            connection.logger.highlight("[RCE] Checking command execution...")
            rce_cmds = [
                "id",
                "whoami",
                "uname -a",
                "id;id",
                "id|id",
                "id`id`",
            ]

            for cmd in rce_cmds:
                if rce:
                    break
                try:
                    resp = ftp.sendcmd(cmd)
                    if re.search(r"uid=\d+|gid=|www-data|root|linux|darwin|nobody|daemon", resp, re.I):
                        connection.logger.success(f"[RCE] YES → {cmd}")
                        connection.logger.highlight(f"     └─> {resp.strip()}")
                        rce = True
                except:
                    continue

            if not rce:
                connection.logger.highlight("[RCE] NO — Command execution not detected")

            # === FINAL PRIVILEGE SUMMARY ===
            if rce and can_write:
                connection.logger.highlight("[Privileges] GOD TIER — RCE + Write = Full compromise")
            elif rce:
                connection.logger.highlight("[Privileges] RCE ONLY — Blind/command injection possible")
            elif can_write:
                connection.logger.highlight("[Privileges] WRITE ACCESS — Upload webshell = win")
            else:
                connection.logger.highlight("[Privileges] Read-only — Enumeration only")

        except Exception as e:
            connection.logger.fail(f"Error: {e}")
        finally:
            try:
                ftp.quit()
            except:
                pass

        return True