from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Enables or disables xp_cmdshell in MSSQL Server.
    Module by crosscutsaw
    Modified by @azoxlpf to add a permission check so the module doesn’t show success when the user lacks rights.
    """

    name = "enable_cmdshell"
    description = "Enable or disable xp_cmdshell in MSSQL Server"
    supported_protocols = ["mssql"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self):
        self.mssql_conn = None
        self.context = None
        self.action = None
        self.advanced_options_backup = None  # Stores original value of 'show advanced options'

    def options(self, context, module_options):
        """
        ACTION      enable or disable xp_cmdshell

        Examples
        --------
        netexec mssql $TARGET -u $username -p $password -M enable_cmdshell -o ACTION=enable
        netexec mssql $TARGET -u $username -p $password -M enable_cmdshell -o ACTION=disable
        """
        if "ACTION" in module_options:
            self.action = module_options["ACTION"].lower()
        else:
            context.log.fail("Missing required option: ACTION (enable/disable)")
            exit(1)

    def on_login(self, context, connection):
        self.context = context
        self.mssql_conn = connection.conn

        if self.action == "enable":
            self.toggle_xp_cmdshell(enable=True)
        elif self.action == "disable":
            self.toggle_xp_cmdshell(enable=False)
        else:
            self.context.log.fail("Invalid ACTION. Use 'enable' or 'disable'.")

    def backup_show_advanced_options(self):
        """Backs up the current state of 'show advanced options'."""
        query = "SELECT CAST(value AS INT) AS value FROM sys.configurations WHERE name = 'show advanced options'"
        try:
            res = self.mssql_conn.sql_query(query)
            if res:
                row = res[0]
                if isinstance(row, dict) and "value" in row:
                    self.advanced_options_backup = int(row["value"])
                else:
                    self.advanced_options_backup = int(row[0])
        except Exception:
            self.advanced_options_backup = None

    def restore_show_advanced_options(self):
        """Restores the original state of 'show advanced options' if needed."""
        if self.advanced_options_backup is not None and self.advanced_options_backup == 0:
            try:
                self.mssql_conn.sql_query("EXEC sp_configure 'show advanced options', '0'; RECONFIGURE;")
            except Exception:
                pass

    def toggle_xp_cmdshell(self, enable: bool):
        """Enables or disables xp_cmdshell while preserving 'show advanced options' state.
        No xp_cmdshell execution: uses permission check + sys.configurations.value_in_use verification.
        """
        state = "1" if enable else "0"

        # Backup 'show advanced options' state
        self.backup_show_advanced_options()

        # Enable 'show advanced options' if it was disabled (best-effort)
        try:
            self.mssql_conn.sql_query("EXEC sp_configure 'show advanced options', '1'; RECONFIGURE;")
        except Exception:
            pass

        # 1) Silent permission check: ALTER SETTINGS or sysadmin
        res = None
        try:
            perm_q = (
                "SELECT "
                "HAS_PERMS_BY_NAME(NULL, 'SERVER', 'ALTER SETTINGS') AS can_alter_settings, "
                "IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;"
            )
            res = self.mssql_conn.sql_query(perm_q)
            has_perm = False
            if res and len(res) > 0:
                row = res[0]
                if isinstance(row, dict):
                    a = row.get("can_alter_settings") or row.get("CAN_ALTER_SETTINGS")
                    s = row.get("is_sysadmin") or row.get("IS_SYSADMIN")
                else:
                    try:
                        a = row[0] 
                        s = row[1]
                    except Exception:
                        a = s = None
                try:
                    if a is not None and int(a) == 1:
                        has_perm = True
                    elif s is not None and int(s) == 1:
                        has_perm = True
                    else:
                        sa = str(a).strip().lower() if a is not None else ""
                        ss = str(s).strip().lower() if s is not None else ""
                        if sa in ("1", "true", "ok") or ss in ("1", "true", "ok"):
                            has_perm = True
                except Exception:
                    if str(a).strip().lower() in ("1", "true", "ok") or str(s).strip().lower() in ("1", "true", "ok"):
                        has_perm = True
            else:
                has_perm = False
        except Exception:
            has_perm = False

        # If both checks explicitly say no, abort early
        if has_perm is False and res and len(res) > 0:
            self.context.log.fail("You do not have permission to enable xp_cmdshell.")
            self.restore_show_advanced_options()
            return

        # 2) Attempt to set xp_cmdshell
        try:
            self.mssql_conn.sql_query(f"EXEC sp_configure 'xp_cmdshell', '{state}'; RECONFIGURE;")
        except Exception as e:
            err = str(e).lower()
            if "permission" in err or "not exist" in err:
                self.context.log.fail("You do not have permission to enable xp_cmdshell.")
            else:
                self.context.log.fail(f"Failed to execute command: {e}")
            self.restore_show_advanced_options()
            return

        # 3) Verify via sys.configurations.value_in_use (no xp_cmdshell execution)
        verify_q = "SELECT CAST(value_in_use AS INT) AS value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
        verified = False
        try:
            for _ in range(2):  # read twice in case of propagation delay
                vres = self.mssql_conn.sql_query(verify_q)
                if vres and len(vres) > 0:
                    row = vres[0]
                    if isinstance(row, dict):
                        raw = row.get("value_in_use") if "value_in_use" in row else next(iter(row.values()), None)
                    else:
                        raw = row[0]
                    try:
                        verified = int(raw) == (1 if enable else 0)
                    except Exception:
                        verified = str(raw).strip() == ("1" if enable else "0")
                    if verified:
                        break
        except Exception:
            verified = False

        if verified:
            action_text = "enabled" if enable else "disabled"
            self.context.log.success(f"xp_cmdshell successfully {action_text}.")
        else:
            self.context.log.fail("Unable to confirm xp_cmdshell state, likely missing permissions or propagation delay.")

        # Restore 'show advanced options' to its original state if needed
        self.restore_show_advanced_options()
