import winrm
import json
import os

class NXCModule:
    name = "winrmjump"
    description = "Relay commands from one WinRM host to another (New-PsSession)"
    supported_protocols = ["winrm"]
    opsec_safe = False
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Parse REMOTE options:
        - REMOTE_HOST=host1,host2
        - REMOTE_USER=user1,user2
        - REMOTE_PASSWORD=pass1,pass2
        - REMOTE_DOMAIN=domain1,domain2
        - REMOTE_COMMAND=cmd1,cmd2
        Fill-forward applied if lists are shorter than hosts.
        """
        hosts = [h.strip() for h in module_options.get("REMOTE_HOST", "").split(",") if h.strip()]
        users = [u.strip() for u in module_options.get("REMOTE_USER", "").split(",") if u.strip()]
        passwords = [p.strip() for p in module_options.get("REMOTE_PASSWORD", "").split(",") if p.strip()]
        domains = [d.strip() for d in module_options.get("REMOTE_DOMAIN", "").split(",") if d.strip()]
        commands = [c.strip() for c in module_options.get("REMOTE_COMMAND", "").split(",") if c.strip()]

        if not hosts:
            context.log.error("[winrm_relay] REMOTE_HOST not provided")
            raise ValueError("Remote host not provided")

        # Default command if nothing provided
        if not commands:
            commands = ["whoami"]

        def fill_forward(lst, default=None):
            result = []
            last = default
            for i in range(len(hosts)):
                if i < len(lst) and lst[i]:
                    last = lst[i]
                result.append(last)
            return result

        filled_users = fill_forward(users)
        filled_passwords = fill_forward(passwords)
        filled_domains = fill_forward(domains)
        filled_commands = fill_forward(commands, default="whoami")

        self.targets = []
        for i, host in enumerate(hosts):
            self.targets.append({
                "host": host,
                "user": filled_users[i],
                "password": filled_passwords[i],
                "domain": filled_domains[i],
                "command": filled_commands[i]
            })

        context.log.info(f"[winrm_relay] Targets: {self.targets}")

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
                cmd = tgt["command"] or "whoami"

                # Resolve host to hostname if needed
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

        # JSON output if requested
        if getattr(self, "output_json", False):
            print(json.dumps(results, indent=2))

        if getattr(self, "save_json", False):
            filename = "winrm_relay_results.json"
            try:
                with open(filename, "w") as f:
                    json.dump(results, f, indent=2)
                context.log.success(f"[winrm_relay] JSON results saved to {os.path.abspath(filename)}")
            except Exception as e:
                context.log.error(f"[winrm_relay] Failed to save JSON -> {e}")
