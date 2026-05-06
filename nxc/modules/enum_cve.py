from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, DCERPCException
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
        self.exploitation_details = False

    def options(self, context, module_options):
        """
        Be aware that these checks solely rely on the OS version and UBR reported in the registry,
        and do not check for the actual presence of the vulnerable components or mitigations.
        Test the attack yourself to verify the host is actually vulnerable.

        Currently supported CVEs:
        - CVE-2025-33073 (NTLM Reflection)
        - CVE-2025-58726 (Ghost SPN)
        - CVE-2025-54918 (NTLM MIC Bypass)
        - CVE-2025-53779 (BadSuccessor)
        - CVE-2024-49019 (EKUwu / ESC15)

        CVE             Filter for specific CVE number (default: All)
        EXPLOITATION    Also provide sources for exploitation details (default: False)
        """
        self.listener = None
        if "CVE" in module_options:
            self.cve = module_options["CVE"].lower()
        if "EXPLOITATION" in module_options:
            self.exploitation_details = module_options["EXPLOITATION"].lower() in ["true", "1", "yes"]

    def is_vulnerable(self, major, minor, build, ubr, msrc):
        key = (major, minor, build)
        min_patched_ubr = msrc.get(key)
        if min_patched_ubr is None:
            return None  # Unknown product
        if ubr is None:
            return None
        return ubr < min_patched_ubr

    def on_login(self, context, connection):
        connection.trigger_winreg()

        # Connect to RemoteRegistry to read UBR from registry
        rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
        rpc.set_smb_connection(connection.conn)
        if connection.kerberos:
            rpc.set_kerberos(connection.kerberos, kdcHost=connection.kdcHost)
        dce = rpc.get_dce_rpc()
        if connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        # Query the UBR
        try:
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            # Reading UBR from registry
            hRootKey = rrp.hOpenLocalMachine(dce)["phKey"]
            hKey = rrp.hBaseRegOpenKey(dce, hRootKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")["phkResult"]
            ubr = rrp.hBaseRegQueryValue(dce, hKey, "UBR")[1]
            dce.disconnect()
            if not ubr:
                context.log.info("Could not determine OS version from registry")
                return
            else:
                context.log.debug(f"OS version from registry: {connection.server_os_major}.{connection.server_os_minor}.{connection.server_os_build}.{ubr}")
        except DCERPCException as e:
            context.log.fail(f"DCERPC error: {e}")
            return
        except SessionError as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                context.log.info(f"RemoteRegistry is probably deactivated: {e}")
            else:
                context.log.fail(f"Unexpected error: {e}")
            return
        except (BrokenPipeError, ConnectionResetError, NetBIOSError, OSError) as e:
            context.log.fail(f"DCERPC transport error: {e.__class__.__name__}: {e}")
            return

        # Check each CVE
        for cve in self.CVE_PATCHES:
            if self.cve == "all" or self.cve.lower() == cve.lower():
                if self.CVE_PATCHES[cve].get("dc_only") and not connection.is_host_dc():
                    context.log.info(f"Skipping {self.CVE_PATCHES[cve]['alias']} - only applicable to Domain Controllers")
                    continue
                if self.is_vulnerable(connection.server_os_major, connection.server_os_minor, connection.server_os_build, ubr, self.CVE_PATCHES[cve]["patches"]):
                    if connection.conn.isSigningRequired() and "signing_message" in self.CVE_PATCHES[cve]:  # Special conditional message for some CVEs
                        context.log.highlight(f"{cve.upper()} - {self.CVE_PATCHES[cve]['alias']} - {self.CVE_PATCHES[cve]['signing_message']}")
                    else:
                        context.log.highlight(f"{cve.upper()} - {self.CVE_PATCHES[cve]['alias']} - {self.CVE_PATCHES[cve]['message']}")
                    if self.exploitation_details:
                        context.log.highlight(f"Exploitation details: {self.CVE_PATCHES[cve]['exploitation']}")
                else:
                    context.log.info(f"Not vulnerable to {self.CVE_PATCHES[cve]['alias']} (UBR {ubr} >= {self.CVE_PATCHES[cve]['patches'].get((connection.server_os_major, connection.server_os_minor, connection.server_os_build), 'unknown')})")

    # patches: key = (major, minor, build), value = minimum patched UBR
    CVE_PATCHES = {
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073
        "CVE-2025-33073": {
            "alias": "NTLM reflection",
            "patches": {
                (6, 0, 6003): 23351,      # Windows Server 2008 SP2
                (6, 1, 7601): 27769,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25522,      # Windows Server 2012
                (6, 3, 9600): 22620,      # Windows Server 2012 R2
                (10, 0, 10240): 21034,    # Windows 10 1507
                (10, 0, 14393): 8148,     # Windows Server 2016 / Win10 1607
                (10, 0, 17763): 7434,     # Windows Server 2019 / Win10 1809
                (10, 0, 19044): 5965,     # Windows 10 21H2
                (10, 0, 20348): 3807,     # Windows Server 2022
                (10, 0, 22621): 5472,     # Windows 11 22H2
                (10, 0, 25398): 1665,     # Windows Server 2022 23H2
                (10, 0, 26100): 4270,     # Windows Server 2025 / Win11 24H2
            },
            "message": "Relay possible from SMB to any protocol",
            "signing_message": "can relay SMB to other protocols except SMB",
            "exploitation": "https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-58726
        "CVE-2025-58726": {
            "alias": "Ghost SPN",
            "patches": {
                (6, 0, 6003): 23571,      # Windows Server 2008 SP2
                (6, 1, 7601): 27974,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25722,      # Windows Server 2012
                (6, 3, 9600): 22824,      # Windows Server 2012 R2
                (10, 0, 10240): 21161,    # Windows 10 1507
                (10, 0, 14393): 8519,     # Windows Server 2016 / Win10 1607
                (10, 0, 17763): 7919,     # Windows Server 2019 / Win10 1809
                (10, 0, 19044): 6456,     # Windows 10 21H2
                (10, 0, 20348): 4294,     # Windows Server 2022
                (10, 0, 22621): 6060,     # Windows 11 22H2
                (10, 0, 25398): 1913,     # Windows Server 2022 23H2
                (10, 0, 26100): 6899,     # Windows Server 2025 / Win11 24H2
                (10, 0, 26200): 6899,     # Windows 11 25H2
            },
            "message": "Relay possible from SMB using Ghost SPN for Kerberos reflection",
            "signing_message": "Relay possible from SMB using Ghost SPN (non HOST/CIFS) for Kerberos reflection to other protocols except SMB",
            "exploitation": "https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/",
        },

        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54918
        # https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/
        "CVE-2025-54918": {
            "alias": "NTLM MIC Bypass",
            "dc_only": True,
            "patches": {
                (6, 0, 6003): 23529,      # Windows Server 2008 SP2
                (6, 1, 7601): 27929,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25675,      # Windows Server 2012
                (6, 3, 9600): 22774,      # Windows Server 2012 R2
                (10, 0, 10240): 21128,    # Windows 10 1507
                (10, 0, 14393): 8422,     # Windows Server 2016
                (10, 0, 17763): 7792,     # Windows Server 2019 / Win10 1809
                (10, 0, 19044): 6332,     # Windows 10 21H2
                (10, 0, 20348): 4171,     # Windows Server 2022
                (10, 0, 22621): 5909,     # Windows 11 22H2
                (10, 0, 22631): 5909,     # Windows 11 23H2
                (10, 0, 26100): 6508,     # Windows Server 2025 / Win11 24H2
            },
            "message": "Note that without CVE-2025-33073 only Windows Server 2025 is exploitable",
            "exploitation": "https://yousofnahya.medium.com/hands-on-exploitation-of-cve-2025-54918-cf376ebb40e1",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779
        "CVE-2025-53779": {
            "alias": "BadSuccessor",
            "dc_only": True,
            "patches": {
                (10, 0, 26100): 4851,     # Windows Server 2025 / Win11 24H2
            },
            "message": "Escalation to Domain Admin possible via dMSA Kerberos abuse",
            "exploitation": "https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory",
        },
        # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019
        "CVE-2024-49019": {
            "alias": "ESC15 / EKUwu",
            "patches": {
                (6, 0, 6003): 22966,      # Windows Server 2008 SP2
                (6, 1, 7601): 27415,      # Windows Server 2008 R2 SP1
                (6, 2, 9200): 25165,      # Windows Server 2012
                (6, 3, 9600): 22267,      # Windows Server 2012 R2
                (10, 0, 14393): 7515,     # Windows Server 2016
                (10, 0, 17763): 6532,     # Windows Server 2019 / Win10 1809
                (10, 0, 20348): 2849,     # Windows Server 2022
                (10, 0, 25398): 1251,     # Windows Server 2022 23H2
                (10, 0, 26100): 2314,     # Windows Server 2025 / Win11 24H2
            },
            "message": "If host is an AD CS / CA server, it may be vulnerable to ESC15",
            "exploitation": "https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc",
        },
    }
