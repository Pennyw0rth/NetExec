import struct
from io import BytesIO
import pefile

class NXCModule:
    """
    Module by @E1A
    """

    name = "lockscreendoors"
    description = "Detect Windows lock screen backdoors by checking FileDescriptions of accessibility binaries."
    supported_protocols = ["smb"]

    def __init__(self):
        # list of exe names with expected descriptions
        self.expected_descriptions = {
            "utilman.exe": "Utility Manager",
            "narrator.exe": "Screen Reader",
            "sethc.exe": "Accessibility shortcut keys",
            "osk.exe": "Accessibility On-Screen Keyboard",
            "xwizard.exe": "Extensible Wizards Host Process",
            "sndvol.exe": "Volume Mixer",
            "ctfmon.exe": "CTF Loader",
            "displayswitch.exe": "Display Switch",
            "magnify.exe": "Microsoft Screen Magnifier",
            "atbroker.exe": "Windows Assistive Technology Manager",
            "EaseOfAccessDialog.exe": "Ease of Access Dialog Host"
        }

        # if description matches one of these it's almost certainly backdoored
        self.backdoor_descriptions = [
            "Windows Command Processor",
            "Windows PowerShell"
        ]

    def options(self, context, module_options):
        pass

    def get_description(self, binary_data):
        # extract the file description from version info
        try:
            pe = pefile.PE(data=binary_data, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
            )
            for fileinfo in pe.FileInfo:
                for entry in fileinfo:
                    if entry.Key.decode() == 'StringFileInfo':
                        for st in entry.StringTable:
                            desc = st.entries.get(b"FileDescription")
                            if desc:
                                return desc.decode(errors="ignore")
        except Exception:
            return None
        return None

    def on_admin_login(self, context, connection):
        target_path = "Windows/System32"
        tampered = False
        readable_file_found = False

        for exe, expected_desc in self.expected_descriptions.items():
            try:
                # grab the binary from the share
                buf = BytesIO()
                connection.conn.getFile("C$", f"{target_path}/{exe}", buf.write)
                binary = buf.getvalue()
                readable_file_found = True

                # extract and normalize the file description
                file_desc = self.get_description(binary)
                if not file_desc:
                    context.log.fail(f"{exe}: could not extract FileDescription")
                    continue

                file_desc = file_desc.strip()

                # check if the description is what we expect
                if file_desc != expected_desc:
                    tampered = True
                    if file_desc in self.backdoor_descriptions:
                        context.log.fail(f"BACKDOOR DETECTED: {exe} has FileDescription '{file_desc}'")
                    else:
                        context.log.fail(f"SUSPICIOUS: {exe} has unexpected FileDescription '{file_desc}' (expected '{expected_desc}')")

            except Exception:
                # silently skip if we can't access the file
                continue

        if not readable_file_found:
            return

        if not tampered:
            context.log.display("All lock screen executable descriptions are consistent with the expected values")