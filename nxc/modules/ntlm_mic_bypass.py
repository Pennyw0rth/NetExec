from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from impacket.nmb import NetBIOSError


class NXCModule:
    # https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/
    name = "ntlm_mic_bypass"
    description = "Attempt to check if the OS is vulnerable to CVE-2025–54918"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    # Reference table from MSRC report
    # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54918
    MSRC_PATCHES = {    # key = (major, minor, build), value = minimum patched UBR
        (6, 0, 6003): 23529,      # Windows Server 2008 SP2
        (6, 1, 7601): 27929,      # Windows Server 2008 R2 SP1
        (6, 2, 9200): 25675,      # Windows Server 2012
        (6, 3, 9600): 22774,      # Windows Server 2012 R2
		(10, 0, 10240): 21128,      # Windows 10 1507
        (10, 0, 14393): 8422,     # Windows Server 2016
        (10, 0, 17763): 7792,     # Windows Server 2019 / Win10 1809
        (10, 0, 19044): 6332,     # Windows 10 21H2
		(10, 0, 20348): 4171,     # Windows Server 2022
        (10, 0, 22621): 5909,     # Windows 11 22H2
		(10, 0, 22631): 5909,     # Windows 11 23H2
		(10, 0, 26100): 6584,     # Windows Server 2025
    }

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """No options available"""

    def is_vulnerable(self, major, minor, build, ubr):
        key = (major, minor, build)
        min_patched_ubr = self.MSRC_PATCHES.get(key)
        if min_patched_ubr is None:
            return None  # Unknown product
        if ubr is None:
            return None
        return ubr < min_patched_ubr

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection
        connection.trigger_winreg()
        rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
        rpc.set_smb_connection(connection.conn)
        if connection.kerberos:
            rpc.set_kerberos(connection.kerberos, kdcHost=connection.kdcHost)
        dce = rpc.get_dce_rpc()
        if connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        try:
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            # Reading UBR from registry
            hRootKey = rrp.hOpenLocalMachine(dce)["phKey"]
            hKey = rrp.hBaseRegOpenKey(dce, hRootKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]
            ubr = rrp.hBaseRegQueryValue(dce, hKey, "UBR")[1]
            version_str = f"{connection.server_os_major}.{connection.server_os_minor}.{connection.server_os_build}.{ubr}" if ubr else None
            dce.disconnect()
            if not version_str:
                self.context.log.info("Could not determine OS version from registry")
                return
            vuln = self.is_vulnerable(connection.server_os_major, connection.server_os_minor, connection.server_os_build, ubr)
            if vuln:
                    context.log.highlight(f"VULNERABLE (can relay SMB to other protocols except SMB on {self.context.log.extra['host']})")
        except SessionError as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                self.context.log.info(f"RemoteRegistry is probably deactivated: {e}")
            else:
                self.context.log.debug(f"Unexpected error: {e}")
        except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
            context.log.debug(f"ntlm_mic_bypass: DCERPC transport error: {e.__class__.__name__}: {e}")
