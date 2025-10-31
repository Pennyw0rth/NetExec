from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    MSSQL security audit module.
    Module by: Matt Millen
    """

    name = "mssql_audit"
    description = "Audit MSSQL for exploitable configurations"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        self.context = context
        self.conn = connection.conn

        # Run all checks
        findings = {
            "service_account": self.get_service_account(),
            "is_sysadmin": self.check_sysadmin(),
            "xp_dirtree": self.check_xp_procedure("xp_dirtree"),
            "xp_fileexist": self.check_xp_procedure("xp_fileexist"),
            "extended_protection": self.check_extended_protection(),
            "impersonation": self.get_impersonation(),
            "linked_servers": self.get_linked_servers()
        }

        self.print_report(findings)

    def get_service_account(self):
        """Get SQL Server service account"""
        # Try sys.dm_server_services first (SQL 2008 R2+)
        query = "SELECT service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%'"
        try:
            result = self.conn.sql_query(query)
            if result and result[0].get("service_account"):
                return self.parse_service_account(result[0]["service_account"])
        except Exception:
            pass

        # Fallback to registry
        query = """DECLARE @acct NVARCHAR(256)
        EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER', N'ObjectName', @acct OUTPUT
        SELECT @acct AS service_account"""
        try:
            result = self.conn.sql_query(query)
            if result and result[0].get("service_account"):
                return self.parse_service_account(result[0]["service_account"])
        except Exception:
            pass

        return {"name": "UNKNOWN", "type": "Unknown"}

    def parse_service_account(self, account):
        """Parse service account type"""
        if not account:
            return {"name": "UNKNOWN", "type": "Unknown"}

        account_upper = account.upper()

        if account_upper.startswith(("NT SERVICE\\", "NT AUTHORITY\\")):
            return {"name": account, "type": "Local Service"}
        elif account_upper in ("LOCALSYSTEM", "LOCAL SYSTEM"):
            return {"name": account, "type": "Local System"}
        elif "\\" in account:
            return {"name": account, "type": "Domain Account"}

        return {"name": account, "type": "Unknown"}

    def check_sysadmin(self):
        """Check if current user has sysadmin"""
        try:
            result = self.conn.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin') AS r")
            return result and result[0].get("r") == 1
        except Exception:
            return False

    def check_xp_procedure(self, proc_name):
        """Check if extended stored procedure is exploitable"""
        query = f"SELECT COUNT(*) AS c FROM sys.all_objects WHERE name = '{proc_name}' AND type = 'X'"
        try:
            result = self.conn.sql_query(query)
            if not result or result[0].get("c") == 0:
                return "NOT_AVAILABLE"

            # Try executing it
            try:
                self.conn.sql_query(f"EXEC master..{proc_name}")
                return "EXPLOITABLE"
            except Exception as e:
                if any(x in str(e).lower() for x in ["parameter", "argument"]):
                    return "EXPLOITABLE"
                return "EXISTS_NOT_CALLABLE"
        except Exception:
            return "NOT_AVAILABLE"

    def check_extended_protection(self):
        """Check Extended Protection status"""
        query = """DECLARE @ep INT
        EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SYSTEM\\CurrentControlSet\\Services\\MSSQLSERVER', N'ExtendedProtection', @ep OUTPUT
        SELECT @ep AS ep"""

        try:
            result = self.conn.sql_query(query)
            if result:
                value = result[0].get("ep")
                if value in (None, 0):
                    return "OFF"
                elif value == 1:
                    return "ALLOWED"
                elif value == 2:
                    return "REQUIRED"
        except Exception:
            pass

        return "OFF"

    def get_impersonation(self):
        """Get impersonation privileges"""
        query = """SELECT pr.name AS grantee, pr2.name AS grantor
        FROM sys.server_permissions pe
        JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
        LEFT JOIN sys.server_principals pr2 ON pe.grantor_principal_id = pr2.principal_id
        WHERE pe.permission_name = 'IMPERSONATE'"""

        try:
            return self.conn.sql_query(query) or []
        except Exception:
            return []

    def get_linked_servers(self):
        """Get linked servers with SA/RPC status"""
        query = "SELECT name, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1"
        try:
            results = self.conn.sql_query(query) or []
            for srv in results:
                srv["has_sa"] = self.check_linked_sa(srv["name"])
                srv["remote_login"] = self.get_linked_login(srv["name"])
            return results
        except Exception:
            return []

    def check_linked_sa(self, link_name):
        """Check if we have SA on linked server"""
        try:
            result = self.conn.sql_query(f"EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [{link_name}]")
            return result and next(iter(result[0].values())) == 1
        except Exception:
            return False

    def get_linked_login(self, link_name):
        """Get remote login for linked server"""
        query = f"""SELECT uses_self_credential, remote_name, local_principal_id
        FROM sys.linked_logins ll
        JOIN sys.servers s ON ll.server_id = s.server_id
        WHERE s.name = '{link_name}'
        ORDER BY local_principal_id"""

        try:
            results = self.conn.sql_query(query)
            if not results:
                return None

            # Find default mapping (local_principal_id = 0) or use first
            mapping = next((r for r in results if r.get("local_principal_id") == 0), results[0])

            if mapping.get("uses_self_credential") in (1, True):
                return "uses self credentials"
            elif mapping.get("remote_name"):
                return mapping["remote_name"]
            return None
        except Exception:
            return None

    def print_report(self, findings):
        """Print formatted report"""
        # Service Account
        svc = findings["service_account"]
        svc_str = f"{svc['name']} \033[91m({svc['type']})\033[0m" if svc["type"] == "Domain Account" else f"{svc['name']} ({svc['type']})"
        self.context.log.highlight(f"Service Account:          {svc_str}")

        # Sysadmin
        if findings["is_sysadmin"]:
            self.context.log.display("Sysadmin Access:          \033[91mYES\033[0m")
        else:
            self.context.log.display("Sysadmin Access:          NO")

        # xp_dirtree
        if findings["xp_dirtree"] == "EXPLOITABLE":
            self.context.log.display("xp_dirtree:               \033[91mEXPLOITABLE\033[0m")
        else:
            self.context.log.display(f"xp_dirtree:               {findings['xp_dirtree']}")

        # xp_fileexist
        if findings["xp_fileexist"] == "EXPLOITABLE":
            self.context.log.display("xp_fileexist:             \033[91mEXPLOITABLE\033[0m")
        else:
            self.context.log.display(f"xp_fileexist:             {findings['xp_fileexist']}")

        # MSSQL Relay
        if findings["extended_protection"] in ("OFF", "ALLOWED"):
            self.context.log.display(f"MSSQL Relay:              \033[91mEXPLOITABLE\033[0m (Extended Protection: {findings['extended_protection']})")
        elif findings["extended_protection"] == "REQUIRED":
            self.context.log.display(f"MSSQL Relay:              MITIGATED (Extended Protection: {findings['extended_protection']})")
        else:
            self.context.log.display(f"MSSQL Relay:              UNKNOWN (Extended Protection: {findings['extended_protection']})")

        # Impersonation
        if findings["impersonation"]:
            self.context.log.display(f"Impersonation:            \033[91m{len(findings['impersonation'])} user(s) can impersonate\033[0m")
            for imp in findings["impersonation"]:
                self.context.log.highlight(f"  → {imp['grantee']} can impersonate {imp['grantor']}")
        elif not findings["is_sysadmin"]:
            self.context.log.display("Impersonation:            Cannot check (requires sysadmin)")
        else:
            self.context.log.display("Impersonation:            No privileges found")

        # Linked Servers
        if findings["linked_servers"]:
            has_exploit = any(s["has_sa"] or s["is_rpc_out_enabled"] for s in findings["linked_servers"])

            if has_exploit:
                self.context.log.display("\033[91mLinked servers found:\033[0m")
            else:
                self.context.log.display("Linked servers found:")

            for link in findings["linked_servers"]:
                flags = []
                if link["has_sa"]:
                    flags.append("SA")
                if link["is_rpc_out_enabled"]:
                    flags.append("RPC")

                remote = link["remote_login"]
                if remote == "uses self credentials":
                    login_str = "(Remote Login: Current User)"
                elif remote:
                    login_str = f"(Remote Login: {remote})"
                else:
                    login_str = "(Remote Login: NULL)"

                link_info = f"{link['name']} {login_str}"
                if flags:
                    link_info += f" [\033[91m{', '.join(flags)}\033[0m]"
                    self.context.log.highlight(f"  → {link_info}")
                else:
                    self.context.log.display(f"  → {link_info}")
        else:
            self.context.log.display("Linked Servers:           None found")
