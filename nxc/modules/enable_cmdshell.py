from nxc.helpers.misc import CATEGORY
import contextlib


class NXCModule:
    """
    Enables or disables xp_cmdshell in MSSQL Server.
    Module by crosscutsaw
    Modified by @azoxlpf to add a permission check so the module does not show success when the user lacks rights.
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
            query_result = self.mssql_conn.sql_query(query)
            if query_result:
                result_row = query_result[0]
                if isinstance(result_row, dict) and "value" in result_row:
                    self.advanced_options_backup = int(result_row["value"])
                else:
                    self.advanced_options_backup = int(result_row[0])
        except Exception:
            self.advanced_options_backup = None

    def restore_show_advanced_options(self):
        """Restores the original state of 'show advanced options' if needed."""
        if self.advanced_options_backup is not None and self.advanced_options_backup == 0:
            with contextlib.suppress(Exception):
                self.mssql_conn.sql_query("EXEC sp_configure 'show advanced options', '0'; RECONFIGURE;")

    def toggle_xp_cmdshell(self, enable: bool):
        """Enables or disables xp_cmdshell while preserving 'show advanced options' state.
        Uses IS_SRVROLEMEMBER('sysadmin') OR fn_my_permissions(NULL,'SERVER') to decide.
        """
        desired_state = "1" if enable else "0"

        # Backup 'show advanced options' state
        self.backup_show_advanced_options()

        # Enable 'show advanced options' if it was disabled (best-effort)
        with contextlib.suppress(Exception):
            self.mssql_conn.sql_query("EXEC sp_configure 'show advanced options', '1'; RECONFIGURE;")

        # 1) Permission checks: prefer sysadmin check, fallback to fn_my_permissions (ALTER SETTINGS)
        has_permission = False
        is_sysadmin = None

        # Check sysadmin first
        try:
            sysadmin_result = self.mssql_conn.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;")
            if sysadmin_result and len(sysadmin_result) > 0:
                row = sysadmin_result[0]
                if isinstance(row, dict):
                    is_sysadmin = row.get("is_sysadmin") or row.get("IS_SYSADMIN")
                else:
                    try:
                        is_sysadmin = row[0]
                    except Exception:
                        is_sysadmin = None

                try:
                    if is_sysadmin is not None and int(is_sysadmin) == 1:
                        has_permission = True
                        self.context.log.info("Permission check: user is sysadmin.")
                except Exception:
                    if str(is_sysadmin).strip().lower() in ("1", "true", "ok"):
                        has_permission = True
                        self.context.log.info("Permission check: user is sysadmin.")
        except Exception:
            is_sysadmin = None

        # If not sysadmin, check fn_my_permissions for ALTER SETTINGS
        if not has_permission:
            try:
                perms = self.mssql_conn.sql_query("SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER');")
                if perms:
                    for prow in perms:
                        perm_name = ""
                        if isinstance(prow, dict):
                            # some drivers return column lowercase/uppercase
                            perm_name = (prow.get("permission_name") or prow.get("PERMISSION_NAME") or "")
                        else:
                            try:
                                perm_name = str(prow[0])
                            except Exception:
                                perm_name = ""
                        if "ALTER SETTINGS" in perm_name.upper():
                            has_permission = True
                            self.context.log.info("Permission check: ALTER SETTINGS found via fn_my_permissions.")
                            break
            except Exception:
                # If fn_my_permissions fails, we cannot confirm ALTER SETTINGS via this method
                pass

        # If neither check succeeded, abort early
        if not has_permission:
            self.context.log.fail("You do not have permission to enable xp_cmdshell.")
            self.restore_show_advanced_options()
            return

        # 2) Attempt to set xp_cmdshell
        try:
            self.mssql_conn.sql_query(f"EXEC sp_configure 'xp_cmdshell', '{desired_state}'; RECONFIGURE;")
        except Exception as exception_obj:
            error_message = str(exception_obj).lower()
            if "permission" in error_message or "not exist" in error_message:
                self.context.log.fail("You do not have permission to enable xp_cmdshell.")
            else:
                self.context.log.fail(f"Failed to execute command: {exception_obj}")
            self.restore_show_advanced_options()
            return

        # 3) Verify via sys.configurations.value_in_use (no xp_cmdshell execution)
        verify_query = "SELECT CAST(value_in_use AS INT) AS value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
        is_verified = False

        try:
            for _ in range(2):  # read twice in case of propagation delay
                xp_cmdshell_state_result = self.mssql_conn.sql_query(verify_query)
                if xp_cmdshell_state_result and len(xp_cmdshell_state_result) > 0:
                    result_row = xp_cmdshell_state_result[0]
                    value_in_use = result_row.get("value_in_use") or next(iter(result_row.values()), None) if isinstance(result_row, dict) else result_row[0]

                    try:
                        is_verified = int(value_in_use) == (1 if enable else 0)
                    except Exception:
                        is_verified = str(value_in_use).strip() == desired_state

                    if is_verified:
                        break
        except Exception:
            is_verified = False

        if is_verified:
            action_text = "enabled" if enable else "disabled"
            self.context.log.success(f"xp_cmdshell successfully {action_text}.")
        else:
            self.context.log.fail("Unable to confirm xp_cmdshell state, likely missing permissions or propagation delay.")

        # Restore 'show advanced options' to its original state if needed
        self.restore_show_advanced_options()
