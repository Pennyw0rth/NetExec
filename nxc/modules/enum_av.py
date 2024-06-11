# All credit to @an0n_r0
# https://github.com/tothi/serviceDetector
# Module by @mpgn_x64
# https://twitter.com/mpgn_x64

from impacket.dcerpc.v5 import lsat, lsad, transport
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
import pathlib


class NXCModule:
    """
    Uses LsarLookupNames and NamedPipes to gather information on all endpoint protection solutions installed on the the remote host(s)
    Module by @mpgn_x64
    """

    name = "enum_av"
    description = "Gathers information on all endpoint protection solutions installed on the the remote host(s) via LsarLookupNames (no privilege needed)"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """
        """

    def on_login(self, context, connection):
        target = self._get_target(connection)
        context.log.debug(f"Detecting installed services on {target} using LsarLookupNames()...")

        results = self._detect_installed_services(context, connection, target)
        self.detect_running_processes(context, connection, results)

        self.dump_results(results, context)

    def _get_target(self, connection):
        return connection.host if not connection.kerberos else f"{connection.hostname}.{connection.domain}"

    def _detect_installed_services(self, context, connection, target):
        results = {}

        try:
            lsa = LsaLookupNames(
                domain=connection.domain,
                username=connection.username,
                password=connection.password,
                remote_name=target,
                do_kerberos=connection.kerberos,
                remoteHost=connection.host,
                kdcHost=connection.kdcHost,
                lmhash=connection.lmhash,
                nthash=connection.nthash,
                aesKey=connection.aesKey
            )

            dce, _ = lsa.connect()
            policyHandle = lsa.open_policy(dce)
            for product in conf["products"]:
                for service in product["services"]:
                    try:
                        lsa.LsarLookupNames(dce, policyHandle, service["name"])
                        context.log.info(f"Detected installed service on {connection.host}: {product['name']} {service['description']}")
                        results.setdefault(product["name"], {"services": []})["services"].append(service)
                    except Exception:
                        pass
        except Exception as e:
            context.log.fail(str(e))
        return results

    def detect_running_processes(self, context, connection, results):
        context.log.info(f"Detecting running processes on {connection.host} by enumerating pipes...")
        try:
            for f in connection.conn.listPath("IPC$", "\\*"):
                fl = f.get_longname()
                for product in conf["products"]:
                    for pipe in product["pipes"]:
                        if pathlib.PurePath(fl).match(pipe["name"]):
                            context.log.info(f"{product['name']} running claim found on {connection.host} by existing pipe {fl} (likely processes: {pipe['processes']})")
                            prod_results = results.setdefault(product["name"], {})
                            prod_results.setdefault("pipes", []).append(pipe)
        except Exception as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                context.log.fail("Error STATUS_ACCESS_DENIED while enumerating pipes, probably due to using SMBv1")
            else:
                context.log.fail(str(e))

    def dump_results(self, results, context):
        if not results:
            context.log.highlight("Found NOTHING!")
            return

        for item, data in results.items():
            message = f"Found {item}"
            if "services" in data:
                message += " INSTALLED"
                if "pipes" in data:
                    message += " and RUNNING"
            elif "pipes" in data:
                message += " RUNNING"
            context.log.highlight(message)


class LsaLookupNames:
    timeout = None
    authn_level = None
    protocol = None
    transfer_syntax = None
    machine_account = False

    iface_uuid = lsat.MSRPC_UUID_LSAT
    authn = True

    def __init__(
        self,
        domain="",
        username="",
        password="",
        remote_name="",
        do_kerberos=False,
        remoteHost="",
        kdcHost="",
        lmhash="",
        nthash="",
        aesKey="",
    ):
        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remote_name
        self.string_binding = rf"ncacn_np:{remote_name}[\PIPE\lsarpc]"
        self.doKerberos = do_kerberos
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.kdcHost = kdcHost
        self.remoteHost = remoteHost

    def connect(self, string_binding=None, iface_uuid=None):
        """Obtains a RPC Transport and a DCE interface according to the bindings and
        transfer syntax specified.
        :return: tuple of DCE/RPC and RPC Transport objects
        :rtype: (DCERPC_v5, DCERPCTransport)
        """
        string_binding = string_binding or self.string_binding
        if not string_binding:
            raise NotImplementedError("String binding must be defined")

        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.setRemoteHost(self.remoteHost)

        # Set timeout if defined
        if self.timeout:
            rpc_transport.set_connect_timeout(self.timeout)

        # Authenticate if specified
        if self.authn and hasattr(rpc_transport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)

        if self.doKerberos:
            rpc_transport.set_kerberos(self.doKerberos, kdcHost=self.kdcHost)

        # Gets the DCE RPC object
        dce = rpc_transport.get_dce_rpc()

        if self.doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        # Connect
        dce.connect()

        # Bind if specified
        iface_uuid = iface_uuid or self.iface_uuid
        if iface_uuid and self.transfer_syntax:
            dce.bind(iface_uuid, transfer_syntax=self.transfer_syntax)
        elif iface_uuid:
            dce.bind(iface_uuid)

        return dce, rpc_transport

    def open_policy(self, dce):
        request = lsad.LsarOpenPolicy2()
        request["SystemName"] = NULL
        request["ObjectAttributes"]["RootDirectory"] = NULL
        request["ObjectAttributes"]["ObjectName"] = NULL
        request["ObjectAttributes"]["SecurityDescriptor"] = NULL
        request["ObjectAttributes"]["SecurityQualityOfService"] = NULL
        request["DesiredAccess"] = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
        resp = dce.request(request)
        return resp["PolicyHandle"]

    def LsarLookupNames(self, dce, policyHandle, service):
        request = lsat.LsarLookupNames()
        request["PolicyHandle"] = policyHandle
        request["Count"] = 1
        name1 = RPC_UNICODE_STRING()
        name1["Data"] = f"NT Service\\{service}"
        request["Names"].append(name1)
        request["TranslatedSids"]["Sids"] = NULL
        request["LookupLevel"] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        return dce.request(request)


conf = {
    "products": [
        {
            "name": "Acronis Cyber Protect Active Protection",
            "services": [{"name": "AcronisActiveProtectionService", "description": "Acronis Active Protection Service"}],
            "pipes": []
        },
        {
            "name": "Bitdefender",
            "services": [
                {"name": "bdredline_agent", "description": "Bitdefender Agent RedLine Service"},
                {"name": "BDAuxSrv", "description": "Bitdefender Auxiliary Service"},
                {"name": "UPDATESRV", "description": "Bitdefender Desktop Update Service"},
                {"name": "VSSERV", "description": "Bitdefender Virus Shield"},
                {"name": "bdredline", "description": "Bitdefender RedLine Service"},
                {"name": "EPRedline", "description": "Bitdefender Endpoint Redline Service"},
                {"name": "EPUpdateService", "description": "Bitdefender Endpoint Update Service"},
                {"name": "EPSecurityService", "description": "Bitdefender Endpoint Security Service"},
                {"name": "EPProtectedService", "description": "Bitdefender Endpoint Protected Service"},
                {"name": "EPIntegrationService", "description": "Bitdefender Endpoint Integration Service"}
            ],
            "pipes": [
                {"name": "\\bdConnector\\ServiceControl\\EPSecurityService.exe", "processes": ["EPConsole.exe"]},
                {"name": "etw_sensor_pipe_ppl", "processes": ["EPProtectedService.exe"]},
                {"name": "local\\msgbus\\antitracker.low\\*", "processes": ["bdagent.exe"]},
                {"name": "local\\msgbus\\aspam.actions.low\\*", "processes": ["bdagent.exe"]},
                {"name": "local\\msgbus\\bd.process.broker.pipe", "processes": ["bdagent.exe", "bdservicehost.exe", "updatesrv.exe"]},
                {"name": "local\\msgbus\\bdagent*", "processes": ["bdagent.exe"]},
                {"name": "local\\msgbus\\bdauxsrv", "processes": ["bdagent.exe", "bdntwrk.exe"]}
            ]
        },
        {
            "name": "Carbon Black App Control",
            "services": [{"name": "Parity", "description": "Carbon Black App Control Agent"}],
            "pipes": []
        },
        {
            "name": "CrowdStrike",
            "services": [{"name": "CSFalconService", "description": "CrowdStrike Falcon Sensor Service"}],
            "pipes": [{"name": "CrowdStrike\\{*", "processes": ["CSFalconContainer.exe", "CSFalconService.exe"]}]
        },
        {
            "name": "Cortex",
            "services": [
                {"name": "xdrhealth", "description": "Cortex XDR Health Helper"},
                {"name": "cyserver", "description": " Cortex XDR"}
            ],
            "pipes": []
        },
        {
            "name": "Cybereason",
            "services": [
                {"name": "CybereasonActiveProbe", "description": "Cybereason Active Probe"},
                {"name": "CybereasonCRS", "description": "Cybereason Anti-Ransomware"},
                {"name": "CybereasonBlocki", "description": "Cybereason Execution Prevention"}
            ],
            "pipes": [
                {"name": "CybereasonAPConsoleMinionHostIpc_*", "processes": ["minionhost.exe"]},
                {"name": "CybereasonAPServerProxyIpc_*", "processes": ["minionhost.exe"]}
            ]
        },
        {
            "name": "ESET",
            "services": [
                {"name": "ekm", "description": "ESET"},
                {"name": "epfw", "description": "ESET"},
                {"name": "epfwlwf", "description": "ESET"},
                {"name": "epfwwfp", "description": "ESET"},
                {"name": "EraAgentSvc", "description": "ESET Management Agent service"},
                {"name": "ERAAgent", "description": "ESET Management Agent service"},
                {"name": "efwd", "description": "ESET Communication Forwarding Service"},
                {"name": "ehttpsrv", "description": "ESET HTTP Server"},
            ],
            "pipes": [{"name": "nod_scriptmon_pipe", "processes": [""]}],
        },
        {
            "name": "G DATA Security Client",
            "services": [
                {"name": "AVKWCtl", "description": "Anti-virus Kit Window Control"},
                {"name": "AVKProxy", "description": "G Data AntiVirus Proxy Service"},
                {"name": "GDScan", "description": "GDSG Data AntiVirus Scan Service"}
            ],
            "pipes": [
                {"name": "exploitProtectionIPC", "processes": ["AVKWCtlx64.exe"]}
            ]
        },
        {
            "name": "Kaspersky Security for Windows Server",
            "services": [
                {"name": "kavfsslp", "description": "Kaspersky Security Exploit Prevention Service"},
                {"name": "KAVFS", "description": "Kaspersky Security Service"},
                {"name": "KAVFSGT", "description": "Kaspersky Security Management Service"},
                {"name": "klnagent", "description": "Kaspersky Security Center"}
            ],
            "pipes": [
                {"name": "Exploit_Blocker", "processes": ["kavfswh.exe"]}
            ]
        },
        {
            "name": "Panda Adaptive Defense 360",
            "services": [
                {"name": "PandaAetherAgent", "description": "Panda Endpoint Agent"},
                {"name": "PSUAService", "description": "Panda Product Service"},
                {"name": "NanoServiceMain", "description": "Panda Cloud Antivirus Service"}
            ],
            "pipes": [
                {"name": "NNS_API_IPC_SRV_ENDPOINT", "processes": ["PSANHost.exe"]},
                {"name": "PSANMSrvcPpal", "processes": ["PSUAService.exe"]}
            ]
        },
        {
            "name": "SentinelOne",
            "services": [
                {"name": "SentinelAgent", "description": "SentinelOne Endpoint Protection Agent"},
                {"name": "SentinelStaticEngine", "description": "Manage static engines for SentinelOne Endpoint Protection"},
                {"name": "LogProcessorService", "description": "Manage logs for SentinelOne Endpoint Protection"}
            ],
            "pipes": [
                {"name": "SentinelAgentWorkerCert.*", "processes": [""]},
                {"name": "DFIScanner.Etw.*", "processes": ["SentinelStaticEngine.exe"]},
                {"name": "DFIScanner.Inline.*", "processes": ["SentinelAgent.exe"]}
            ]
        },
        {
            "name": "Symantec Endpoint Protection",
            "services": [
                {"name": "SepMasterService", "description": "Symantec Endpoint Protection"},
                {"name": "SepScanService", "description": "Symantec Endpoint Protection Scan Services"},
                {"name": "SNAC", "description": "Symantec Network Access Control"}
            ],
            "pipes": []
        },
        {
            "name": "Sophos Intercept X",
            "services": [
                {"name": "SntpService", "description": "Sophos Network Threat Protection"},
                {"name": "Sophos Endpoint Defense Service", "description": "Sophos Endpoint Defense Service"},
                {"name": "Sophos File Scanner Service", "description": "Sophos File Scanner Service"},
                {"name": "Sophos Health Service", "description": "Sophos Health Service"},
                {"name": "Sophos Live Query", "description": "Sophos Live Query"},
                {"name": "Sophos Managed Threat Response", "description": "Sophos Managed Threat Response"},
                {"name": "Sophos MCS Agent", "description": "Sophos MCS Agent"},
                {"name": "Sophos MCS Client", "description": "Sophos MCS Client"},
                {"name": "Sophos System Protection Service", "description": "Sophos System Protection Service"}
            ],
            "pipes": [
                {"name": "SophosUI", "processes": [""]},
                {"name": "SophosEventStore", "processes": [""]},
                {"name": "sophos_deviceencryption", "processes": [""]},
                {"name": "sophoslivequery_*", "processes": [""]}
            ]
        },
        {
            "name": "Trend Micro Endpoint Security",
            "services": [
                {"name": "Trend Micro Endpoint Basecamp", "description": "Trend Micro Endpoint Basecamp"},
                {"name": "TMBMServer", "description": "Trend Micro Unauthorized Change Prevention Service"},
                {"name": "Trend Micro Web Service Communicator", "description": "Trend Micro Web Service Communicator"},
                {"name": "TMiACAgentSvc", "description": "Trend Micro Application Control Service (Agent)"},
                {"name": "CETASvc", "description": "Trend Micro Cloud Endpoint Telemetry Service"},
                {"name": "iVPAgent", "description": "Trend Micro Vulnerability Protection Service (Agent)"}
            ],
            "pipes": [
                {"name": "IPC_XBC_XBC_AGENT_PIPE_*", "processes": ["EndpointBasecamp.exe"]},
                {"name": "iacagent_*", "processes": ["TMiACAgentSvc.exe"]},
                {"name": "OIPC_LWCS_PIPE_*", "processes": ["TmListen.exe"]},
                {"name": "Log_ServerNamePipe", "processes": ["LogServer.exe"]},
                {"name": "OIPC_NTRTSCAN_PIPE_*", "processes": ["Ntrtscan.exe"]}
            ]
        },
        {
            "name": "Windows Defender",
            "services": [
                {"name": "WinDefend", "description": "Windows Defender Antivirus Service"},
                {"name": "Sense", "description": "Windows Defender Advanced Threat Protection Service"},
                {"name": "WdNisSvc", "description": "Windows Defender Antivirus Network Inspection Service"}
            ],
            "pipes": []
        }
    ]
}
