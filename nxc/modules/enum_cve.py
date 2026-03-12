from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from impacket.nmb import NetBIOSError


class NXCModule:
    """
    Initial module by: Mauriceter
    Additional authors: azoxlpf, Defte, YOLOP0wn, pol4ir, NeffIsBack
    """
    name = "enum_cve"
    description = "Enumerate common (useful) CVEs by querying the registry for the OS version and UBR."
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        context = context
        self.module_options = module_options
        self.cve = "all"

    def options(self, context, module_options):
        """
        Be aware that these checks solely rely on the OS version and UBR reported in the registry,
        and do not check for the actual presence of the vulnerable components or mitigations.
        Test the attack yourself to verify the host is actually vulnerable.

        Currently supported CVEs:
        - CVE-2025-33073 (NTLM Reflection)
        - CVE-2025-58726 (Ghost SPN)
        - CVE-2025-54918 (NTLM MIC Bypass)

        CVE       Filter for specific CVE number (default: All)
        """
        self.listener = None
        if "CVE" in module_options:
            self.cve = module_options["CVE"].lower()

    def is_vulnerable(self, major, minor, build, ubr, msrc):
        key = (major, minor, build)
        min_patched_ubr = msrc.get(key)
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

        except SessionError as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                self.context.log.info(f"RemoteRegistry is probably deactivated: {e}")
            else:
                self.context.log.debug(f"Unexpected error: {e}")
            return
        except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
            context.log.debug(f"ntlm_reflection: DCERPC transport error: {e.__class__.__name__}: {e}")
            return

        if self.cve == "all" or self.cve == "ntlm_reflection":  # CVE-2025-33073
            """NTLM REFLECTION START"""

            vuln = self.is_vulnerable(connection.server_os_major, connection.server_os_minor, connection.server_os_build, ubr, self.MSRC_PATCHES_ntlm_reflection)
            if vuln:
                context.log.highlight("VULNERABLE, NTLM REFLECTION")
                if not connection.conn.isSigningRequired():  # Not vulnerable if SMB signing is enabled
                    context.log.highlight(f"(can relay SMB to any protocol on {self.context.log.extra['host']})")
                else:
                    context.log.highlight(f"(can relay SMB to other protocols except SMB on {self.context.log.extra['host']})")

            """NTLM REFLECTION END"""

        if self.cve == "all" or self.cve == "ghostspn":  # CVE‑2025‑54918
            """GHOSTSPN START"""

            vuln = self.is_vulnerable(connection.server_os_major, connection.server_os_minor, connection.server_os_build, ubr, self.MSRC_PATCHES_ghostspn)
            if vuln:
                context.log.highlight("VULNERABLE, GhostSPN")
                if not connection.conn.isSigningRequired():  # Not vulnerable if SMB signing is enabled
                    context.log.highlight(f"(can relay SMB using Ghost SPN for Kerberos reflection on {self.context.log.extra['host']})")
                else:
                    context.log.highlight(f"(can relay SMB using Ghost SPN (non HOST/CIFS) for Kerberos reflection to other protocols except SMB on {self.context.log.extra['host']})")

            """GHOSTSPN END"""

        if self.cve == "all" or self.cve == "ntlm_mic_bypass":  # CVE-2025-58726
            """ NTLM MIC BYPASS START"""

            vuln_ntlm_reflection = self.is_vulnerable(connection.server_os_major, connection.server_os_minor, connection.server_os_build, ubr, self.MSRC_PATCHES_ntlm_reflection)
            vuln = self.is_vulnerable(connection.server_os_major, connection.server_os_minor, connection.server_os_build, ubr, self.MSRC_PATCHES_ntlm_mic_bypass)
            if vuln_ntlm_reflection and vuln:
                context.log.highlight(f"VULNERABLE, NTLM MIC BYPASS \n(can relay SMB to other protocols except SMB on {self.context.log.extra['host']})")
            elif vuln and connection.server_os_build >= 22621:  # Windows 11 22H2+ and Windows Server 2025
                context.log.highlight(f"VULNERABLE, NTLM MIC BYPASS \n(can relay SMB to any protocol on {self.context.log.extra['host']}) — coercion works only via DCE/RPC over TCP (no named pipes)")

            """ NTLM MIC BYPASS END"""

