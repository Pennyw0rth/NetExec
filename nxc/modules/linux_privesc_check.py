import requests
import re

RED = "\033[91m"
RESET = "\033[0m"

class NXCModule:
    name = "linux_privesc_check"
    description = "Check sudo -l, SUID binaries, capabilities, and kernel version for potential Linux privesc paths"
    supported_protocols = ["ssh"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.no_sudo = False
        self.gtfobins_online = True
        self.show_all_suid = False
        self.show_all_caps = False
        self.logger = None
        self.conn = None
        self.password = None

    def options(self, context, module_options):
        self.logger = context.log

        self.no_sudo = module_options.get("NO_SUDO", "false").lower() in ("true","1","yes")
        if self.no_sudo:
            self.logger.display("[linux_privesc_check] Skipping sudo -l enumeration (NO_SUDO)")
        else:
            self.logger.display("[linux_privesc_check] Sudo -l enumeration enabled")

        self.gtfobins_online = module_options.get("NO_GTF","false").lower() not in ("true","1","yes")
        if not self.gtfobins_online:
            self.logger.display("[linux_privesc_check] Skipping GTFOBins lookups (NO_GTF)")

        self.show_all_suid = module_options.get("SHOW_ALL_SUID","false").lower() in ("true","1","yes")
        if self.show_all_suid:
            self.logger.display("[linux_privesc_check] Showing all SUID binaries (SHOW_ALL_SUID)")

        self.show_all_caps = module_options.get("SHOW_ALL_CAPS","false").lower() in ("true","1","yes")
        if self.show_all_caps:
            self.logger.display("[linux_privesc_check] Showing all capabilities (SHOW_ALL_CAPS)")

    def on_login(self, context, connection):
        self.conn = connection.conn
        self.password = connection.password
        self.logger.display("[linux_privesc_check] Running Linux privilege escalation checks...")

        # Kernel info
        kernel = self._run_cmd("uname -a")
        if kernel:
            self.logger.display(f"[Kernel] {kernel}")

        # UID info
        uidinfo = self._run_cmd("id")
        if uidinfo:
            self.logger.display(f"[User Info] {uidinfo}")

        # Sudo -l
        if not self.no_sudo:
            self.logger.display("[Sudo] Checking sudo -l...")
            sudo_out = self._sudo_list()
            if sudo_out:
                self.logger.display(sudo_out)
            else:
                self.logger.display("[Sudo] No sudo rights or password required")

        # SUID binaries
        self.logger.display("[SUID] Checking for exploitable SUID binaries...")
        suid_bins = self._run_cmd("find / -perm -4000 -type f 2>/dev/null").splitlines()
        for b in suid_bins:
            gtfobin = self._check_gtfobins(b, type_filter="suid")
            if gtfobin or self.show_all_suid:
                line = f"Exploit SUID: {b}"
                if gtfobin:
                    line += f" -> {RED}{gtfobin}{RESET}"
                self.logger.display(line)

        # Capabilities
        self.logger.display("[Capabilities] Checking for binaries with capabilities...")
        caps = self._run_cmd("getcap -r / 2>/dev/null").splitlines()
        for c in caps:
            binpath = c.split("=")[0]
            gtfobin = self._check_gtfobins(binpath, type_filter="capabilities")
            if gtfobin:
                self.logger.display(f"Capability: {c} -> {RED}{gtfobin}{RESET}")
            elif self.show_all_caps:
                self.logger.display(f"Capability: {c}")

        if not self.gtfobins_online:
            self.logger.display("[!] GTFOBins lookup skipped — no internet connection or NO_GTF set")

    # ---------- Internal helpers ----------

    def _run_cmd(self, cmd, getpass=False):
        try:
            _, stdout, stderr = self.conn.exec_command(cmd, get_pty=getpass, timeout=20)
            return stdout.read().decode(errors="ignore").strip()
        except Exception as e:
            self.logger.error(f"Command failed: {cmd} -> {e}")
            return ""

    def _sudo_list(self):
        """Run sudo -l using provided password if needed"""
        try:
            cmd = "sudo -l -S"
            stdin, stdout, stderr = self.conn.exec_command(cmd, get_pty=True, timeout=20)
            if self.password:
                stdin.write(self.password + "\n")
                stdin.flush()
            out = stdout.read().decode(errors="ignore")
            err = stderr.read().decode(errors="ignore")
            combined = out + err
            if combined.strip() == "":
                return None
            highlighted = []
            for line in combined.splitlines():
                if "ALL" in line:
                    # Try to append GTFOBins URL for sudo commands
                    cmd_match = re.search(r'NOPASSWD:\s*(.*)', line)
                    url = None
                    if cmd_match:
                        path = cmd_match.group(1).strip()
                        url = self._check_gtfobins(path, type_filter="sudo")
                    if url:
                        highlighted.append(f"{line} -> {RED}{url}{RESET}")
                    else:
                        highlighted.append(f"{RED}{line}{RESET}" if "ALL" in line else line)
                else:
                    highlighted.append(line)
            return "\n".join(highlighted)
        except Exception as e:
            self.logger.error(f"sudo command failed: -l -> {e}")
            return None

    def _check_gtfobins(self, binary_path, type_filter=None):
        """Return GTFOBins URL if online and matching type (suid, sudo, capabilities)"""
        if not self.gtfobins_online:
            return None
    
        # Extract the binary name
        bin_name = binary_path.strip().split("/")[-1]
        bin_name = bin_name.split()[0]
    
        # Only clean for capabilities
        if type_filter and type_filter.lower() == "capabilities":
            # Strip trailing digits (python3 -> python)
            bin_name = re.sub(r'\d+$', '', bin_name)
            # Remove anything after a space (like cap_setuid,cap_net=ep)
            bin_name = re.sub(r'[^a-zA-Z0-9_\-]+$', '', bin_name)
    
        url = f"https://gtfobins.github.io/gtfobins/{bin_name}/"
        if type_filter:
            url += f"#{type_filter.lower()}"
    
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                # Only validate if the page contains the correct type keyword
                if type_filter and type_filter.lower() in ("suid", "sudo"):
                    if type_filter.lower() not in resp.text.lower():
                        return None
                return url
        except Exception:
            self.gtfobins_online = False
    
        return None

    
    
    