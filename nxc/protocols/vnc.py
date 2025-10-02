import asyncio
import os
from datetime import datetime
from termcolor import colored
import socket
import struct
from nxc.config import host_info_colors
from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.logger import NXCAdapter
from nxc.paths import NXC_PATH
from aardwolf.commons.target import RDPTarget
from aardwolf.vncconnection import VNCConnection
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol
import contextlib


class vnc(connection):
    def __init__(self, args, db, host):
        self.iosettings = RDPIOSettings()
        self.iosettings.channels = []
        self.iosettings.video_out_format = VIDEO_FORMAT.RAW
        self.iosettings.clipboard_use_pyperclip = False
        self.url = None
        self.target = None
        self.credential = None
        self.RBFversion = "3.8"
        self.noauth = False  # True when security type is 1
        connection.__init__(self, args, db, host)

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.print_host_info()
            if self.login():
                if hasattr(self.args, "module") and self.args.module:
                    self.load_modules()
                    self.logger.debug("Calling modules")
                    self.call_modules()
                else:
                    self.logger.debug("Calling command arguments")
                    self.call_cmd_args()

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "VNC",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        noauth = colored(f" (No Auth:{self.noauth})", host_info_colors[2], attrs=["bold"]) if self.noauth else ""
        self.logger.display(f"RBF {self.RBFversion} {'' if self.RBFversion == '3.8' else '(Not supported)'} {noauth}")

    def probe_rfb33(self):
        # Attempt an RFB 3.3 handshake
        with contextlib.suppress(Exception), socket.create_connection((self.host, self.port), timeout=1.0) as s:

            # Read the server banner (usually "RFB 003.003\n" or similar)
            banner = s.recv(12)
            if not banner.startswith(b"RFB"):
                return None
            self.logger.debug(f"RFB 3.3 probe: server banner={banner!r}")

            # Always send 3.3 client banner
            s.sendall(b"RFB 003.003\n")

            # Expect a 4-byte uint32 security type
            sec = s.recv(4)
            if len(sec) != 4:
                return None

            return struct.unpack("!I", sec)[0]

        return None

    def create_conn_obj(self):
        try:
            self.target = RDPTarget(ip=self.host, port=self.port)
            credential = UniCredential(protocol=asyauthProtocol.PLAIN, stype=asyauthSecret.NONE, secret="")
            self.conn = VNCConnection(target=self.target, credentials=credential, iosettings=self.iosettings)
            asyncio.run(self.connect_vnc(True))
            # If no errors, secure type 1 is supported by the service
            self.noauth = True
        except Exception as e:
            self.logger.debug(str(e))
            if "Server supports:" not in str(e):
                self.logger.debug("Exception message was empty; probing server with RFB 3.3 handshake...")
                sec = self.probe_rfb33()
                if sec is None:
                    self.logger.debug("RFB 3.3 probe: no response or malformed response. The server likely closed the connection or sent a non-standard handshake.")
                    return False
                else:
                    self.logger.debug(f"RFB 3.3 probe: server returned security-type={sec!r}")
                    self.RBFversion = "3.3"
                    if (sec == 1):
                        self.noauth = True
                    return True
        return True

    async def connect_vnc(self, discover=False):
        _, err = await self.conn.connect()
        if err is not None:
            if not discover:
                await asyncio.sleep(self.args.vnc_sleep)
            raise err
        return True

    def plaintext_login(self, username, password):
        try:
            stype = asyauthSecret.PASS
            if password == "":
                stype = asyauthSecret.NONE
            self.credential = UniCredential(secret=password, protocol=asyauthProtocol.PLAIN, stype=stype)
            self.conn = VNCConnection(
                target=self.target,
                credentials=self.credential,
                iosettings=self.iosettings,
            )
            asyncio.run(self.connect_vnc())

            self.admin_privs = True
            self.logger.success(
                "{} {}".format(
                    password,
                    highlight(f"({self.config.get('nxc', 'pwn3d_label')})" if self.admin_privs else ""),
                )
            )
            return True

        except Exception as e:
            self.logger.debug(str(e))
            if "Server supports: 1" in str(e):
                self.logger.success(
                    "{} {}".format(
                        "No password seems to be accepted by the server",
                        highlight(f"({self.config.get('nxc', 'pwn3d_label')})" if self.admin_privs else ""),
                    )
                )
            else:
                self.logger.fail(f"{password} {'Authentication failed'}")
            return False

    async def screen(self):
        self.conn = VNCConnection(target=self.target, credentials=self.credential, iosettings=self.iosettings)
        await self.connect_vnc()
        await asyncio.sleep(int(self.args.screentime))
        if self.conn is not None and self.conn.desktop_buffer_has_data is True:
            buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
            filename = os.path.expanduser(f"{NXC_PATH}/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
            buffer.save(filename, "png")
            self.logger.highlight(f"Screenshot saved {filename}")

    def screenshot(self):
        asyncio.run(self.screen())
