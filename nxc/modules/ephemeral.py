# ~/.nxc/modules/ephemeral.py
import threading
import time
import os

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

    def options(self, context, module_options):
        self.script_path = module_options.get("SCRIPT")
        self.raw_command = module_options.get("COMMAND")

        context.log.display("[ephemeral] Ready to run script in memory.")

        if self.script_path and not os.path.isfile(self.script_path):
            context.log.error(f"[ephemeral] Script file not found: {self.script_path}")
            self.script_path = None
            return

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
            with open(self.script_path, "r") as f:
                script_content = f.read()
        elif self.raw_command:
            script_content = self.raw_command
        elif getattr(connection.args, "execute", None):
            # fallback to NetExec -x command
            script_content = connection.args.execute
        else:
            context.log.error("[ephemeral] No commands to execute.")
            return

        # Run command in a separate thread
        self.thread = threading.Thread(target=self._run_command, args=(context, script_content), daemon=True)
        self.thread.start()

        # Keep alive until execution completes
        while self.thread.is_alive():
            time.sleep(0.1)

    def _run_command(self, context, script_content):
        try:
            chan = self.transport.open_session()
            # Fully non-interactive
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
            # Close SSH transport after execution
            self.conn.close()
            context.log.display("[ephemeral] SSH connection closed.")

        except Exception as e:
            context.log.error(f"[ephemeral] Execution error: {e}")
            if self.conn:
                self.conn.close()
                context.log.display("[ephemeral] SSH connection closed due to error.")
