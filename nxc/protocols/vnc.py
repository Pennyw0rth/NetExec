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
        self.RFBversion = None
        self.noauth = False  # True when security type is 1
        self.stype = None
        connection.__init__(self, args, db, host)

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
        self.logger.display(f"RFB {self.RFBversion}{noauth}")

    def probe_rfb(self):
        # Attempt an RFB handshake
        with contextlib.suppress(Exception), socket.create_connection((self.host, self.port), timeout=1.0) as s:

            # Read the server banner (usually "RFB 003.003\n" or similar)
            banner = s.recv(12)
            if not banner.startswith(b"RFB"):
                return None
            self.logger.debug(f"RFB probe: server banner={banner}")
            self.RFBversion = float(f"{int(banner[4:7])}.{int(banner[8:11])}")
            s.sendall(banner)

            if self.RFBversion <= 3.6:
                # Expect a 4-byte uint32 security type
                raw_stype = s.recv(4)
                if len(raw_stype) != 4:
                    return None
                stypes = struct.unpack("!I", raw_stype)[0]
                self.logger.debug(f"Security types: {stypes}")
                return [stypes]

            # 3.7/8 return a list of supported security types
            else:
                nbytes = s.recv(1)  # Number of security types
                if not nbytes:
                    return None
                n = nbytes[0]
                if n == 0:
                    # Server reports failure; read reason
                    ln = struct.unpack("!I", s.recv(4))[0]
                    reason = s.recv(ln)
                    self.logger.debug(f"RFB failure: {reason}")
                    return None

                # Read n one-byte security type IDs (e.g. 1=None, 2=VNCAuth)
                stypes = list(s.recv(n))
                self.logger.debug(f"Security types: {stypes}")
                return stypes

    def enum_host_info(self):
        self.stype = self.probe_rfb()
        if self.stype is None:
            self.logger.debug("RFB probe: no response or malformed response. The server likely closed the connection or sent a non-standard handshake.")
        else:
            self.logger.info(f"RFB probe: server returned security-type={self.stype}")
            if (1 in self.stype):
                self.noauth = True

    def create_conn_obj(self):
        try:
            self.target = RDPTarget(ip=self.host, port=self.port)
            credential = UniCredential(protocol=asyauthProtocol.PLAIN, stype=asyauthSecret.PASS)
            self.conn = VNCConnection(target=self.target, credentials=credential, iosettings=self.iosettings)
            asyncio.run(self.connect_vnc(True))
        except Exception as e:
            self.logger.debug(str(e))
            if "Connect call failed" in str(e):
                return False
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
            self.logger.fail(f"{password} - Authentication failed")
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
