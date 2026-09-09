import base64
import contextlib
import threading
import xml.etree.ElementTree as ET

from pypsrp.client import Client
from pypsrp.exceptions import WinRMTransportError, WSManFaultError
from pypsrp.wsman import SelectorSet

from nxc.helpers.misc import gen_random_string

PS_MODULE_FILE_URI = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/Microsoft/Windows/Powershellv3/PS_ModuleFile"
CIM_DATAFILE_URI = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/CIM_DataFile"
CONFIG_URI = "http://schemas.microsoft.com/wbem/wsman/1/config"
CONFIG_NS = "http://schemas.microsoft.com/wbem/wsman/1/config"
DEFAULT_ENVELOPE_KB = 500

# files above this cannot answer a PS_ModuleFile GET with the stock
# envelope: the base64 in the response would not fit the 500KB limit, and
# the service envelope is raised for the read instead
ENVELOPE_FILE_MAX = 375 * 1024
# reads are sized first: up to SINGLE_READ_MAX one invoke carries the whole
# file, bigger ones are split in CHUNK_SIZE reads across STREAMS parallel
# connections (four measured as the sweet spot on both 2008 R2 and 2019)
SINGLE_READ_MAX = 4 * 1024 * 1024
CHUNK_SIZE = 4 * 1024 * 1024
STREAMS = 4


class FileTransfer:
    """File reads over WS-Management.

    The routing of get_file, the entry point the winrm protocol hands
    out:

        get_file --> _file_size --> FileTransfer_WMI --served--> done
                                       |
                                       | fault: no PowerShell v3
                                       | (2008 R2 stock), a stalled
                                       | GET, or a missing file
                                       v
                            FileTransfer_Compatible

    _file_size                 CIM_DataFile GET (no process involved),
                               PowerShell probe for the kernel paths
                               the provider cannot see.  None = a
                               missing file, or a kernel path under
                               PowerShell 2.0

    FileTransfer_WMI           one PS_ModuleFile GET, zero process on
                               the target, not even a runspace
                                 <= 375KB   within the stock envelope
                                 >  375KB   MaxEnvelopeSizeKb raised
                                            for the read and restored
                                            after: a crash in between
                                            leaves the bigger value
                                            behind

    FileTransfer_Compatible    the PowerShell machinery, every system
                                 GLOBALROOT chunked slices directly,
                                            the .NET of PS 3+ reads
                                            kernel paths; under PS 2.0
                                            the size answers None and
                                            a native cmd copy bridges
                                            to a normal path
                                 DOS path   <= 4MB one ReadAllBytes
                                            invoke, > 4MB chunked
                                            slices over STREAMS
                                            parallel connections,
                                            server memory flat
                                            whatever the file size
    """

    def __init__(self, connection):
        self.connection = connection
        self.logger = connection.logger

    def get_file(self, remote_path, download_path):
        # sized once here, both transfers below work from it
        file_size = self._file_size(remote_path)
        try:
            if FileTransfer_WMI(self.connection).get_file(remote_path, download_path, file_size):
                return True
        except (WSManFaultError, WinRMTransportError) as e:
            # no Powershellv3 namespace (a system predating PowerShell v3)
            # or a stalled GET: the machinery decides what still works - a
            # missing file faults the same way and fails there too
            self.logger.debug(f"{remote_path}: no PS_ModuleFile read: {e}")
        return FileTransfer_Compatible(self.connection).get_file(remote_path, download_path, file_size)

    def _file_size(self, remote_path):
        """File size, through a CIM_DataFile GET first (no process
        involved) and a PowerShell probe for the kernel paths the provider
        cannot see. None when neither sees the file: missing, or a kernel
        path under PowerShell 2.0.
        """
        selector = SelectorSet()
        selector.add_option("Name", remote_path)
        try:
            res = self.connection.conn.wsman.get(CIM_DATAFILE_URI, selector_set=selector)
            for element in res.iter():
                if element.tag.endswith("}FileSize") and element.text:
                    return int(element.text)
        except WSManFaultError as e:
            self.logger.debug(f"No CIM_DataFile size for {remote_path}: {e}")
        try:
            output = self.connection.ps_execute(f"[IO.File]::OpenRead('{remote_path}').Length", True) or ""
            return int(output.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None


class FileTransfer_WMI(FileTransfer):
    """The PS_ModuleFile route: one GET per file, no process involved on
    the target, not even a runspace.
    """

    def get_file(self, remote_path, download_path, file_size=None):
        if file_size is None:
            file_size = self._file_size(remote_path)
        if file_size is not None and file_size > ENVELOPE_FILE_MAX:
            # the response would not fit the stock envelope: raise it for
            # the read and restore the original value right after, a crash
            # in between leaves the raised value behind
            original_kb = self._get_envelope_size()
            envelope_kb = max(original_kb, int(file_size * 4 / 3 / 1024) + 128)
            self._set_envelope_size(envelope_kb)
            try:
                return self._get_module_file(remote_path, download_path)
            finally:
                try:
                    self._set_envelope_size(original_kb)
                except Exception as e:
                    self.logger.fail(f"Could not restore MaxEnvelopeSizeKb to {original_kb}KB, the service keeps the raised {envelope_kb}KB: {e}")
        return self._get_module_file(remote_path, download_path)

    def _get_module_file(self, remote_path, download_path):
        selector = SelectorSet()
        selector.add_option("InstanceID", remote_path)
        res = self.connection.conn.wsman.get(PS_MODULE_FILE_URI, selector_set=selector)
        for element in res.iter():
            if element.tag.endswith("}FileData") and element.text:
                with open(download_path, "wb") as file:
                    file.write(base64.b64decode(element.text.strip()))
                return True
        return False

    def _get_envelope_size(self):
        """The current service MaxEnvelopeSizeKb, DEFAULT_ENVELOPE_KB when
        the config does not answer.
        """
        res = self.connection.conn.wsman.get(CONFIG_URI)
        for element in res.iter():
            if element.tag.endswith("}MaxEnvelopeSizekb") and element.text:
                return int(element.text)
        return DEFAULT_ENVELOPE_KB

    def _set_envelope_size(self, size_kb):
        """Set the service MaxEnvelopeSizeKb, and the client side limit
        with it: pypsrp refuses responses above its own default.
        """
        config = ET.Element(f"{{{CONFIG_NS}}}Config")
        ET.SubElement(config, f"{{{CONFIG_NS}}}MaxEnvelopeSizeKb").text = str(size_kb)
        self.connection.conn.wsman.put(CONFIG_URI, config)
        self.connection.conn.wsman.max_envelope_size = size_kb * 1024


class FileTransfer_Compatible(FileTransfer):
    """The PowerShell machinery, the option that serves every system: one
    ReadAllBytes invoke for small files (every pypsrp invoke costs a
    fresh session, the parallel setup does not pay off), parallel chunks
    for big ones, and a native cmd copy bridge for the kernel paths the
    managed layer of PowerShell 2.0 rejects whatever their form.
    """

    def get_file(self, remote_path, download_path, file_size=None):
        if "GLOBALROOT" in remote_path.upper():
            return self._get_file_chunked(remote_path, download_path, file_size)
        if file_size is None:
            file_size = self._file_size(remote_path)
        if file_size is not None and file_size <= SINGLE_READ_MAX:
            return self._read_whole(remote_path, download_path)
        return self._get_file_chunked(remote_path, download_path, file_size)

    def _read_whole(self, remote_path, download_path):
        """The whole file in a single ReadAllBytes invoke."""
        output = self.connection.ps_execute(f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_path}'))", True)
        if output is None:
            return False
        with open(download_path, "wb") as file:
            file.write(base64.b64decode(output.strip()))
        return True

    def _get_file_chunked(self, remote_path, download_path, file_size=None):
        """STREAMS slices of the file in parallel, one runspace connection
        each: the round trips overlap and the throughput multiplies.
        """
        if file_size is None:
            file_size = self._file_size(remote_path)
        if file_size is None:
            # kernel path under PowerShell 2.0: the managed layer rejects
            # the open, only native cmd copy reads it
            if "GLOBALROOT" in remote_path.upper():
                return self._get_file_through_copy(remote_path, download_path)
            return False
        with open(download_path, "wb") as file:
            file.truncate(file_size)
            if file_size == 0:
                return True

        self.logger.debug(f"Fetching {remote_path} ({file_size} bytes) in {STREAMS} parallel slices")
        slices = [None] * STREAMS

        def reader(index):
            start = file_size * index // STREAMS
            end = file_size * (index + 1) // STREAMS
            try:
                slices[index] = self._read_range(self._new_client(), remote_path, start, end)
            except Exception as e:
                self.logger.debug(f"Slice {index} of {remote_path} failed: {e}")

        threads = [threading.Thread(target=reader, args=(i,)) for i in range(STREAMS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        if any(part is None for part in slices):
            return False
        with open(download_path, "r+b") as file:
            for index, data in enumerate(slices):
                file.seek(file_size * index // STREAMS)
                file.write(data)
        return True

    def _read_range(self, conn, remote_path, start, end):
        """One slice of the file as bytes, in CHUNK_SIZE .NET reads."""
        data = b""
        offset = start
        while offset < end:
            read_size = min(CHUNK_SIZE, end - offset)
            command = (
                f"$fs=[IO.File]::OpenRead('{remote_path}'); $fs.Seek({offset}, 0) | Out-Null; "
                f"$b=New-Object byte[] {read_size}; $fs.Read($b, 0, {read_size}) | Out-Null; "
                f"[Convert]::ToBase64String($b); $fs.Close()"
            )
            output, _, _ = conn.execute_ps(command)
            data += base64.b64decode((output or "").strip())
            offset += read_size
        return data

    def _get_file_through_copy(self, remote_path, download_path):
        """Copy to a random normal path with native cmd, read the copy,
        then clean it up.
        """
        temp_path = f"C:\\Windows\\Temp\\{gen_random_string(8)}"
        try:
            copy_command = f'copy /Y "{remote_path}" {temp_path}'
            self.connection.ps_execute(f"cmd /c '{copy_command}'", True)
            temp_size = self._file_size(temp_path)
            if temp_size is not None and temp_size <= SINGLE_READ_MAX:
                return self._read_whole(temp_path, download_path)
            return self._get_file_chunked(temp_path, download_path, temp_size)
        except Exception as e:
            self.logger.debug(f"Cannot copy {remote_path} to a readable path: {e}")
            return False
        finally:
            with contextlib.suppress(Exception):
                self.connection.ps_execute(f"cmd /c 'del {temp_path}'", True)

    def _new_client(self):
        """A dedicated connection per stream: the NTLM authentication is
        bound to the connection, streams cannot share one. Chunk invokes
        carry a few MB of base64, the read timeout is raised for the slow
        or inspected hosts the default 30s does not cover.
        """
        conn = self.connection
        # the base protocol leaves password empty on hash logins
        password = conn.password or f"{conn.lmhash}:{conn.nthash}"
        return Client(
            conn.host,
            port=conn.port,
            auth="ntlm",
            username=f"{conn.domain}\\{conn.username}",
            password=password,
            ssl=conn.ssl,
            cert_validation=False,
            read_timeout=120,
        )
