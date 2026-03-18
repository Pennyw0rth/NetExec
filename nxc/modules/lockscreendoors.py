from io import BytesIO
import pefile
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    Module for detecting Windows lock screen backdoors
    Module by @E1A
    """

    name = "lockscreendoors"
    description = "Detect Windows lock screen backdoors by checking FileDescriptions of accessibility binaries."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        # List of exe names with expected descriptions
        self.expected_descriptions = {
            "utilman.exe": ["Utility Manager"],
            "narrator.exe": ["Screen Reader", "Narrator"],
            "sethc.exe": ["Accessibility shortcut keys"],
            "osk.exe": ["Accessibility On-Screen Keyboard"],
            "magnify.exe": ["Microsoft Screen Magnifier"],
            "EaseOfAccessDialog.exe": ["Ease of Access Dialog Host"],
            "voiceaccess.exe": ["Voice access"],  # Only on Windows 11 / Server 2025+
            "displayswitch.exe": ["Display Switch"],
            "atbroker.exe": ["Windows Assistive Technology Manager", "Transitions Accessible technologies between desktops"],
        }

        # If description matches one of these it's almost certainly backdoored
        self.backdoor_descriptions = [
            "Windows Command Processor",
            "Windows PowerShell"
        ]

    def options(self, context, module_options):
        """No options available"""

    def get_description(self, binary_data):
        # Extract the file description from version info
        try:
            pe = pefile.PE(data=binary_data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for fileinfo in pe.FileInfo:
                for entry in fileinfo:
                    if entry.Key.decode() == "StringFileInfo":
                        for st in entry.StringTable:
                            desc = st.entries.get(b"FileDescription")
                            if desc:
                                return desc.decode().strip()
        except Exception as e:
            self.context.log.debug(f"Failed to extract PE info: {e}")
        return None

    def on_admin_login(self, context, connection):
        target_path = "\\Windows\\System32"
        tampered = False

        for exe, expected_descs in self.expected_descriptions.items():
            try:
                # Grab the binary from the share
                buf = BytesIO()
                connection.conn.getFile("C$", f"{target_path}\\{exe}", buf.write)
                binary = buf.getvalue()

                # Extract and normalize the file description
                file_desc = self.get_description(binary)
                if not file_desc:
                    context.log.fail(f"{exe}: could not extract FileDescription")
                    continue

                # Check if the description is as expected
                if file_desc not in expected_descs:
                    tampered = True
                    if file_desc in self.backdoor_descriptions:
                        context.log.highlight(f"BACKDOOR DETECTED: {exe} has FileDescription '{file_desc}'")
                    else:
                        if len(expected_descs) == 1:
                            expected_str = f"'{expected_descs[0]}'"
                        else:
                            expected_str = ", ".join(f"'{d}'" for d in expected_descs)
                            expected_str = f"one of: {expected_str}"
                        context.log.highlight(f"SUSPICIOUS: {exe} has unexpected FileDescription '{file_desc}' (expected {expected_str})")
            except Exception as e:
                context.log.debug(f"Failed to process {exe}: {e}")

        if not tampered:
            context.log.display("All lock screen executable descriptions are consistent with the expected values")
