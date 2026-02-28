from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.smbconnection import SessionError
from nxc.helpers.misc import CATEGORY
from impacket.nmb import NetBIOSError


class NXCModule:
    """
    Module by polair: @p0l4ir
    Initial module:
        https://github.com/Pennyw0rth/NetExec/pull/1086
    """
     
    name = "ntlm_reflection"
    description = "Module to check whether the target is vulnerable to any CVE that relies on NTLM reflection."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION

    # https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
    # Modified by azoxlpf to handle BrokenPipe/transport errors gracefully
    # Modified by Defte following the discovery of ctjf (https://github.com/Pennyw0rth/NetExec/issues/928) and the research done along side with @NeffIsBack and I
    # Thanks to @YOLOP0wn for ghostspn https://github.com/Pennyw0rth/NetExec/pull/978 

    # Reference table from MSRC report
    # https://msrc.microsoft.com/update-guide/fr-FRS/vulnerability/CVE-2025-33073
    MSRC_PATCHES_ntlm_reflection = {    # key = (major, minor, build), value = minimum patched UBR
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

    # Reference table from MSRC report
    # https://msrc.microsoft.com/update-guide/fr-FRS/vulnerability/CVE-2025-58726
    # Thanks to @YOLOP0wn https://github.com/Pennyw0rth/NetExec/pull/978
    MSRC_PATCHES_ghostspn = {    # key = (major, minor, build), value = minimum patched UBR
        (6, 1, 7601): 23571,      # Windows Server 2008 SP2
        (6, 1, 7601): 27974,      # Windows Server 2008 R2 SP1
        (6, 2, 9200): 25722,      # Windows Server 2012
        (6, 3, 9600): 22824,      # Windows Server 2012 R2
        (10, 0, 14393): 8519,     # Windows Server 2016
        (10, 0, 17763): 7919,     # Windows Server 2019 / Win10 1809
        (10, 0, 20348): 4294,     # Windows Server 2022
        (10, 0, 19044): 6456,     # Windows 10 21H2
        (10, 0, 22621): 6060,     # Windows 11 22H2
    }

     # Reference table from MSRC report
     # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54918
    MSRC_PATCHES_ntlm_mic_bypass = {    # key = (major, minor, build), value = minimum patched UBR
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
        self.cve = "all"

    def options(self, context, module_options):
        """
        CVE         CVE recon (CVE-2025-33073, CVE‑2025‑54918, CVE-2025-58726, All   default: All)
        """
        self.listener = None
        if "CVE" in module_options:
            self.cve = module_options["CVE"].lower()


    def is_vulnerable(self, major, minor, build, ubr,msrc):
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
            elif vuln and connection.server_os_build >= 22621: # Windows 11 22H2+ and Windows Server 2025
                    context.log.highlight(f"VULNERABLE, NTLM MIC BYPASS \n(can relay SMB to any protocol on {self.context.log.extra['host']}) — coercion works only via DCE/RPC over TCP (no named pipes)")

            """ NTLM MIC BYPASS END"""

