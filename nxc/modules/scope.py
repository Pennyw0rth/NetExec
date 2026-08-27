import csv
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import ClassVar

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    name = "scope"
    description = "Export a first-pass SMB scope inventory without additional network traffic"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    output_lock: ClassVar = Lock()
    default_output_dir: ClassVar[Path | None] = None
    initialized_output_dirs: ClassVar[set[Path]] = set()
    recorded_hosts: ClassVar[dict[Path, set[str]]] = {}

    def __init__(self):
        self.output_dir = None
        self.hosts_file = None
        self.relay_file = None
        self.null_auth_file = None
        self.scope_file = None

    def options(self, context, module_options):
        """
        OUTPUT      Directory for results (default: NXC_PATH/logs/scope-<timestamp>)
        OVERWRITE   Overwrite existing scope files in OUTPUT (default: false)

        Run without credentials so every live SMB host is recorded:
        netexec smb scope.txt -M scope

        The module reuses SMB negotiation results already collected by NetExec
        and does not send additional requests to targets.

        Output files:
        hosts.txt       All hosts that completed SMB negotiation
        relay.txt       Hosts with NTLM enabled where SMB signing is not required
        null-auth.txt   Hosts that accepted blank SMB authentication
        scope.csv       Detailed inventory of all recorded hosts

        relay.txt contains candidates for further validation; it does not prove
        that relaying to a host will succeed.
        """
        credential_values = []
        for argument in ["username", "password", "hash", "cred_id", "aesKey", "use_kcache"]:
            value = getattr(context.args, argument, None)
            credential_values.extend(value if isinstance(value, list) else [value])
        if any(credential_values):
            context.log.fail("Run the scope module without credentials so authentication failures cannot exclude live SMB hosts")
            return False

        overwrite = module_options.get("OVERWRITE", "false").lower() in ["true", "1", "yes"]
        with self.output_lock:
            if "OUTPUT" in module_options:
                self.output_dir = Path(module_options["OUTPUT"]).expanduser()
            else:
                if self.default_output_dir is None:
                    type(self).default_output_dir = Path(NXC_PATH) / "logs" / f"scope-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                self.output_dir = self.default_output_dir

            self.hosts_file = self.output_dir / "hosts.txt"
            self.relay_file = self.output_dir / "relay.txt"
            self.null_auth_file = self.output_dir / "null-auth.txt"
            self.scope_file = self.output_dir / "scope.csv"

            if self.output_dir not in self.initialized_output_dirs:
                scope_files = [self.hosts_file, self.relay_file, self.null_auth_file, self.scope_file]
                if not overwrite and any(output_file.exists() for output_file in scope_files):
                    context.log.fail(f"Scope results already exist in {self.output_dir}; choose another OUTPUT directory or set OVERWRITE=true")
                    return False
                try:
                    self.output_dir.mkdir(parents=True, exist_ok=True)
                    self.hosts_file.write_text("", encoding="utf-8")
                    self.relay_file.write_text("", encoding="utf-8")
                    self.null_auth_file.write_text("", encoding="utf-8")
                    with self.scope_file.open("w", newline="", encoding="utf-8") as output_file:
                        csv.writer(output_file).writerow(["host", "hostname", "domain", "os", "smbv1", "signing_required", "ntlm_enabled", "null_auth", "guest_auth", "dc_detected"])
                except OSError as e:
                    context.log.fail(f"Unable to initialize scope output directory {self.output_dir}: {e}")
                    return False
                self.initialized_output_dirs.add(self.output_dir)
                self.recorded_hosts[self.output_dir] = set()
                context.log.display(f"Scope results will be written to {self.output_dir}")

    def on_login(self, context, connection):
        relay_candidate = connection.signing is False and not connection.no_ntlm
        try:
            with self.output_lock:
                if connection.host in self.recorded_hosts[self.output_dir]:
                    context.log.debug("Host already recorded in scope results")
                    return

                with self.hosts_file.open("a", encoding="utf-8") as output_file:
                    output_file.write(f"{connection.host}\n")

                if relay_candidate:
                    with self.relay_file.open("a", encoding="utf-8") as output_file:
                        output_file.write(f"{connection.host}\n")

                if connection.null_auth:
                    with self.null_auth_file.open("a", encoding="utf-8") as output_file:
                        output_file.write(f"{connection.host}\n")

                with self.scope_file.open("a", newline="", encoding="utf-8") as output_file:
                    csv.writer(output_file).writerow([
                        connection.host,
                        connection.hostname,
                        connection.targetDomain,
                        connection.server_os,
                        connection.smbv1,
                        connection.signing,
                        not connection.no_ntlm,
                        connection.null_auth,
                        connection.is_guest,
                        connection.isdc,
                    ])
                self.recorded_hosts[self.output_dir].add(connection.host)
        except OSError as e:
            context.log.fail(f"Unable to write scope results for {connection.host}: {e}")
            return

        findings = []
        if relay_candidate:
            findings.append("relay candidate")
        if connection.null_auth:
            findings.append("null authentication")
        finding_text = f" ({', '.join(findings)})" if findings else ""
        context.log.success(f"Recorded live SMB host{finding_text}")
