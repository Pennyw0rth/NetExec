# ~/.nxc/modules/ssh_socks.py
import socket
import struct
import select
import threading
import time

class NXCModule:
    name = "ssh_socks"
    description = "SOCKS5 dynamic forwarder defaults to port 1080"
    supported_protocols = ["ssh"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self):
        self.local_port = 1080
        self.bind_host = "127.0.0.1"
        self.conn = None
        self.transport = None
        self.listener = None
        self.stop_evt = threading.Event()

    # nxc passes a dict in module_options; PORT is optional
    def options(self, context, module_options):
        # Existing port option
        try:
            self.local_port = int(module_options.get("PORT", 1080))
        except Exception:
            self.local_port = 1080
        context.log.display(f"[ssh_socks] Listening on {self.bind_host}:{self.local_port} (SOCKS5)")

        # Options for kex and hostkey for legacy systems
        kex = module_options.get("KEX")
        hostkey = module_options.get("HOSTKEY")

        if kex:
            algos = [x.strip() for x in kex.split(",") if x.strip()]
            context.log.display(f"[ssh_socks] Forcing KEX algos: {algos}")
            # Patch paramiko defaults
            from paramiko.transport import Transport
            Transport._preferred_kex = algos

        if hostkey:
            algos = [x.strip() for x in hostkey.split(",") if x.strip()]
            context.log.display(f"[ssh_socks] Forcing hostkey algos: {algos}")
            from paramiko.transport import Transport
            Transport._preferred_pubkeys = algos

    def on_login(self, context, connection):
        """
        Called after SSH auth succeeds. We reuse NetExec's Paramiko transport.
        Keep this function alive so NetExec doesn't close the SSH session.
        """
        if not hasattr(connection, "conn") or connection.conn is None:
            context.log.error("[ssh_socks] SSH client not found on connection.")
            return

        self.conn = connection.conn
        self.transport = self.conn.get_transport()
        if self.transport is None or not self.transport.is_active():
            context.log.error("[ssh_socks] SSH transport not available or inactive.")
            return

        # Start SOCKS5 listener
        try:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((self.bind_host, self.local_port))
            self.listener.listen(128)
        except Exception as e:
            context.log.error(f"[ssh_socks] Failed to bind {self.bind_host}:{self.local_port} - {e}")
            return

        context.log.success(f"[ssh_socks] SOCKS5 forwarder running on {self.bind_host}:{self.local_port}")

        t = threading.Thread(target=self._accept_loop, args=(context,), daemon=True)
        t.start()

        # Block so NetExec keeps the SSH session open (Ctrl+C to stop)
        try:
            while t.is_alive() and not self.stop_evt.is_set():
                time.sleep(0.5)
        finally:
            self.stop_evt.set()
            try:
                if self.listener:
                    self.listener.close()
            except Exception:
                pass
            context.log.display("[ssh_socks] Stopped.")

    # ---------- Internals ----------

    def _accept_loop(self, context):
        while not self.stop_evt.is_set():
            try:
                client, _ = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(context, client), daemon=True).start()

    def _handle_client(self, context, client):
        remote = None
        try:
            # ===== SOCKS5 handshake =====
            # greeting
            data = self._recv_exact(client, 2)
            if not data or data[0] != 0x05:
                raise ValueError("Not SOCKS5")
            n_methods = data[1]
            _ = self._recv_exact(client, n_methods)  # ignore offered methods
            client.sendall(b"\x05\x00")  # version 5, NO AUTH

            # request
            hdr = self._recv_exact(client, 4)
            if not hdr or hdr[0] != 0x05 or hdr[1] != 0x01:  # CONNECT only
                # reply: command not supported
                try:
                    client.sendall(b"\x05\x07\x00\x01\0\0\0\0\x00\x00")
                except Exception:
                    pass
                return

            atyp = hdr[3]
            if atyp == 0x01:  # IPv4
                dst_addr = socket.inet_ntoa(self._recv_exact(client, 4))
            elif atyp == 0x03:  # DOMAIN
                ln = self._recv_exact(client, 1)[0]
                dst_addr = self._recv_exact(client, ln).decode(errors="ignore")
            elif atyp == 0x04:  # IPv6 (optional)
                raw = self._recv_exact(client, 16)
                dst_addr = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                try:
                    client.sendall(b"\x05\x08\x00\x01\0\0\0\0\x00\x00")
                except Exception:
                    pass
                return

            dst_port = struct.unpack(">H", self._recv_exact(client, 2))[0]

            # ===== Open SSH direct-tcpip channel =====
            if self.transport is None or not self.transport.is_active():
                raise RuntimeError("SSH transport inactive")

            # originator tuple can be anything local-ish; it's metadata for the server
            originator = ("127.0.0.1", 0)
            remote = self.transport.open_channel(
                "direct-tcpip",
                (dst_addr, dst_port),
                originator
            )

            # reply success
            # BND.ADDR & BND.PORT are the proxy’s bind; we just return 0.0.0.0:0
            reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0)
            client.sendall(reply)

            # ===== Pump data =====
            self._pump(client, remote)

        except Exception as e:
            context.log.error(f"[ssh_socks] SOCKS5 handler error: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass
            if remote:
                try:
                    remote.close()
                except Exception:
                    pass

    def _pump(self, c, r):
        bufsz = 65536
        sockets = [c, r]
        while True:
            rd, _, _ = select.select(sockets, [], [])
            if c in rd:
                data = c.recv(bufsz)
                if not data:
                    break
                r.sendall(data)
            if r in rd:
                data = r.recv(bufsz)
                if not data:
                    break
                c.sendall(data)

    def _recv_exact(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
