from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from impacket.nmb import NetBIOSError


class NXCModule:
    # https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
    # Modified by azoxlpf to handle BrokenPipe/transport errors gracefully
    # Modified by Defte following the discovery of ctjf (https://github.com/Pennyw0rth/NetExec/issues/928) and the research done along side with @NeffIsBack and I
    name = "ntlm_reflection"
    description = "Attempt to check if the OS is vulnerable to CVE-2025-33073 (NTLM Reflection attack)"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    # Reference table from MSRC report
    # https://msrc.microsoft.com/update-guide/fr-FRS/vulnerability/CVE-2025-33073
    MSRC_PATCHES = {    # key = (major, minor, build), value = minimum patched UBR
        (6, 0, 6003): 23351,      # Windows Server 2008 SP2
        (6, 1, 7601): 27769,      # Windows Server 2008 R2 SP1
        (6, 2, 9200): 25522,      # Windows Server 2012
        (6, 3, 9600): 22620,      # Windows Server 2012 R2
        (10, 0, 14393): 8148,     # Windows Server 2016
        (10, 0, 17763): 7434,     # Windows Server 2019 / Win10 1809
        (10, 0, 20348): 3807,     # Windows Server 2022
        (10, 0, 19044): 5965,     # Windows 10 21H2
        (10, 0, 22621): 5472,     # Windows 11 22H2
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
                if not connection.conn.isSigningRequired():  # Not vulnerable if SMB signing is enabled
                    context.log.highlight(f"VULNERABLE (can relay SMB to any protocol on {self.context.log.extra['host']})")
                else:
                    context.log.highlight(f"VULNERABLE (can relay SMB to other protocols except SMB on {self.context.log.extra['host']})")
        except SessionError as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                self.context.log.info(f"RemoteRegistry is probably deactivated: {e}")
            else:
                self.context.log.debug(f"Unexpected error: {e}")
        except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
            context.log.debug(f"ntlm_reflection: DCERPC transport error: {e.__class__.__name__}: {e}")
