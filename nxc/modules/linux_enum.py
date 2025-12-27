from nxc.helpers.misc import CATEGORY

class NXCModule:
    """
    Enumerate Linux system information including Sudo privileges, SUID binaries, 
    Scheduled tasks, and Context info.
    Module by Liyander Rishwanth( @CyberGhost05 )
    """
    name = "linux_enum"
    description = "Enumerate (Read-Only) Sudo, SUID, Cron, and Context info on Linux"
    supported_protocols = ["ssh"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None

    def options(self, context, module_options):
        """
        No options required for this module.
        """
        pass

    def on_login(self, context, connection):
        """
        Enumerates system information after successful login.
        """
        # Ensure we are running on Linux
        # The connection object usually determines OS, but let's be safe.
        # connection.server_os_platform is set in check_shell
        if hasattr(connection, 'server_os_platform') and connection.server_os_platform != "Linux":
            context.log.debug("Skipping linux_enum on non-Linux host")
            return

        context.log.info("Starting Linux Enumeration Module")

        self.check_context(context, connection)
        self.check_sudo(context, connection)
        self.check_suid(context, connection)
        self.check_cron(context, connection)

    def execute_silent(self, connection, command):
        try:
            _, stdout, _ = connection.conn.exec_command(f"{command} 2>&1")
            # Decode using the same codec as connection, default usually utf-8 but better safe
            codec = getattr(connection.args, "codec", "utf-8")
            return stdout.read().decode(codec, errors="ignore")
        except Exception:
            return ""

    def check_sudo(self, context, connection):
        context.log.display("[*] Checking Sudo Privileges")
        
        # 1. Try non-interactive (no password)
        # We manually append 2>&1 as executed_silent does it or we do it here. 
        # execute_silent defined above does append 2>&1.
        command = "sudo -n -l" 
        output = self.execute_silent(connection, command)

        password_required = False
        if output and ("a password is required" in output or "incorrect password attempt" in output):
             password_required = True
        
        # 2. If password required and we have one, try using it
        if password_required and hasattr(connection, "password") and connection.password:
            context.log.display(f"Sudo requires password, attempting with provided password...")
            safe_pass = connection.password.replace("'", "'\\''")
            command = f"echo '{safe_pass}' | sudo -S -l"
            output = self.execute_silent(connection, command)

        if output:
            if "a password is required" in output or "incorrect password attempt" in output:
                context.log.fail("Sudo requires password (and provided password failed or didn't work)")
            elif "not allow" in output and "to execute" in output:
                 context.log.fail("User is not allowed to run sudo")
            else:
                lines = output.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    if line.startswith("[sudo] password"): continue
                    
                    if "NOPASSWD" in line:
                         context.log.highlight(f"Sudo NOPASSWD Entry: {line}")
                    elif "User" in line and "may run the following commands" in line:
                         context.log.display(f"Sudo Header: {line}")
                    elif "(" in line and ")" in line:
                         context.log.display(f"Sudo Rule: {line}")

    def check_suid(self, context, connection):
        context.log.display("[*] Checking SUID Binaries")
        
        # Check sh -c logic
        command = "sh -c 'find / -perm -4000 -type f 2>/dev/null'"
        output = self.execute_silent(connection, command)
        
        gtfobins = [
            "aria2c", "arp", "ash", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown", "chroot", "cp", "csh", "curl",
            "cut", "dash", "date", "dd", "diff", "dmsetup", "docker", "emacs", "env", "eqn", "expand", "expect", "file", "find",
            "flock", "fmt", "fold", "gdb", "gimp", "git", "grep", "gtester", "hd", "head", "hexdump", "highlight", "iconv",
            "ionice", "ip", "jjs", "jq", "jrunscript", "ksh", "ksshell", "ld.so", "less", "logsave", "look", "lwp-download",
            "lwp-request", "make", "man", "mawk", "more", "mosquitto", "msgfilter", "mv", "nawk", "nc", "nice", "nl", "node",
            "nohup", "nmap", "od", "openssl", "perl", "pg", "php", "pic", "pico", "python", "readelf", "restic", "rlwrap", "rpm",
            "rpmquery", "rsync", "ruby", "run-parts", "rvim", "scp", "sed", "setarch", "shuf", "soelim", "sort", "start-stop-daemon",
            "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tclsh", "tee", "tftp", "time", "timeout",
            "ul", "unexpand", "uniq", "unshare", "uudecode", "uuencode", "vim", "watch", "wget", "xargs", "xxd", "xz", "zsh", "zsoelim"
        ]

        if output:
            lines = output.split('\n')
            for line in lines:
                path = line.strip()
                if not path: continue
                if "find:" in path and "Permission denied" in path: continue

                binary = path.split('/')[-1]
                if binary in gtfobins:
                    context.log.highlight(f"GTFOBin SUID Found: {path}")
                
                is_standard = (
                    path.startswith("/bin/") or 
                    path.startswith("/sbin/") or 
                    path.startswith("/usr/bin/") or 
                    path.startswith("/usr/sbin/") or
                    path.startswith("/usr/local/bin/") or
                    path.startswith("/usr/local/sbin/") or
                    path.startswith("/snap/") or
                    path.startswith("/usr/lib/")
                )
                
                if not is_standard:
                     context.log.display(f"Non-Standard SUID Binary: {path}")

    def check_cron(self, context, connection):
        context.log.display("[*] Checking Scheduled Tasks")
        
        user_cron = self.execute_silent(connection, "crontab -l 2>/dev/null")
        if user_cron and "no crontab for" not in user_cron:
            context.log.success(f"User Crontab:\n{user_cron.strip()}")

        sys_cron = self.execute_silent(connection, "cat /etc/crontab 2>/dev/null")
        if sys_cron and len(sys_cron.strip()) > 0:
             context.log.display(f"/etc/crontab content:\n{sys_cron.strip()}")
        
        cron_dirs = self.execute_silent(connection, "ls -R /etc/cron.* 2>/dev/null")
        if cron_dirs:
            context.log.display(f"Contents of /etc/cron.*:\n{cron_dirs.strip()}")

        timers = self.execute_silent(connection, "systemctl list-timers --all --no-pager 2>/dev/null")
        if timers and "0 timers listed" not in timers:
            context.log.display(f"Systemd Timers:\n{timers.strip()}")

    def check_context(self, context, connection):
        context.log.display("[*] Checking Context Info")
        
        user = self.execute_silent(connection, "whoami")
        if user:
            context.log.highlight(f"Current User: {user.strip()}")
            
        uid_info = self.execute_silent(connection, "id")
        if uid_info:
            context.log.highlight(f"UID/Groups: {uid_info.strip()}")
            
        hostname_info = self.execute_silent(connection, "hostnamectl")
        if hostname_info and "Static hostname" in hostname_info:
             context.log.display(f"Hostnamectl Info:\n{hostname_info.strip()}")
        else:
             uname = self.execute_silent(connection, "uname -a")
             if uname: context.log.display(f"Kernel: {uname.strip()}")
             
             issue = self.execute_silent(connection, "cat /etc/issue")
             if issue: context.log.display(f"Distro (issue): {issue.strip()}")
