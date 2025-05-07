import asyncio
import os
from datetime import datetime
from os import getenv
from termcolor import colored

from impacket.krb5.ccache import CCache

from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter
from nxc.config import host_info_colors
from nxc.config import process_secret

from aardwolf.connection import RDPConnection
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from aardwolf.commons.queuedata.keyboard import RDP_KEYBOARD_UNICODE
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.target import RDPTarget
from aardwolf.keyboard.layoutmanager import KeyboardLayoutManager
from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.constants import asyauthSecret
from asysocks.unicomm.common.target import UniTarget, UniProto

from nxc.paths import NXC_PATH


class rdp(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.iosettings = RDPIOSettings()
        self.iosettings.channels = []
        self.iosettings.video_out_format = VIDEO_FORMAT.RAW
        self.iosettings.clipboard_use_pyperclip = False
        self.protoflags_nla = [
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.RDP,
            SUPP_PROTOCOLS.SSL,
            SUPP_PROTOCOLS.RDP,
        ]
        self.protoflags = [
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.RDP,
            SUPP_PROTOCOLS.SSL,
            SUPP_PROTOCOLS.RDP,
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.HYBRID,
            SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.HYBRID_EX,
        ]
        width, height = args.res.upper().split("X")
        height = int(height)
        width = int(width)
        self.iosettings.video_width = width
        self.iosettings.video_height = height
        # servers dont support 8 any more :/
        self.iosettings.video_bpp_min = 15
        self.iosettings.video_bpp_max = 32
        # PIL produces incorrect picture for some reason?! TODO: check bug
        self.iosettings.video_out_format = VIDEO_FORMAT.PNG  #
        self.output_filename = None
        self.domain = None
        self.server_os = None
        self.url = None
        self.nla = True
        self.hybrid = False
        self.target = None
        self.auth = None

        self.rdp_error_status = {
            "0xc0000071": "STATUS_PASSWORD_EXPIRED",
            "0xc0000234": "STATUS_ACCOUNT_LOCKED_OUT",
            "0xc0000072": "STATUS_ACCOUNT_DISABLED",
            "0xc0000193": "STATUS_ACCOUNT_EXPIRED",
            "0xc000006E": "STATUS_ACCOUNT_RESTRICTION",
            "0xc000006F": "STATUS_INVALID_LOGON_HOURS",
            "0xc0000070": "STATUS_INVALID_WORKSTATION",
            "0xc000015B": "STATUS_LOGON_TYPE_NOT_GRANTED",
            "0xc0000224": "STATUS_PASSWORD_MUST_CHANGE",
            "0xc0000022": "STATUS_ACCESS_DENIED",
            "0xc000006d": "STATUS_LOGON_FAILURE",
            "0xc000006a": "STATUS_WRONG_PASSWORD ",
            "KDC_ERR_CLIENT_REVOKED": "KDC_ERR_CLIENT_REVOKED",
            "KDC_ERR_PREAUTH_FAILED": "KDC_ERR_PREAUTH_FAILED",
        }

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        import platform
        if platform.python_version() in ["3.11.5", "3.11.6", "3.12.0"]:
            import sys

            class DevNull:
                def write(self, msg):
                    pass

            sys.stderr = DevNull()

        self.logger = NXCAdapter(
            extra={
                "protocol": "RDP",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        nla = colored(f"nla:{self.nla}", host_info_colors[3], attrs=["bold"]) if self.nla else colored(f"nla:{self.nla}", host_info_colors[2], attrs=["bold"])
        if self.domain is None:
            self.logger.display(f"Probably old, doesn't not support HYBRID or HYBRID_EX ({nla})")
        else:
            self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.domain}) ({nla})")

    def create_conn_obj(self):
        self.target = RDPTarget(ip=self.host, domain="FAKE", port=self.port, timeout=self.args.rdp_timeout)
        self.auth = NTLMCredential(secret="pass", username="user", domain="FAKE", stype=asyauthSecret.PASS)

        self.check_nla()

        for proto in reversed(self.protoflags):
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(
                    iosettings=self.iosettings,
                    target=self.target,
                    credentials=self.auth,
                )
                asyncio.run(self.connect_rdp())
            except OSError as e:
                if "Errno 104" not in str(e):
                    return False
            except Exception as e:
                if "TCPSocket" in str(e):
                    return False
                if "Reason:" not in str(e):
                    try:
                        info_domain = self.conn.get_extra_info()
                    except Exception:
                        pass
                    else:
                        self.domain = info_domain["dnsdomainname"]
                        self.hostname = info_domain["computername"]
                        self.server_os = info_domain["os_guess"] + " Build " + str(info_domain["os_build"])
                        self.logger.extra["hostname"] = self.hostname
                        self.output_filename = os.path.expanduser(f"~/.nxc/logs/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}".replace(":", "-"))
                    break

        if self.args.domain:
            self.domain = self.args.domain
        if self.args.local_auth:
            self.domain = self.hostname

        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

        self.target = RDPTarget(
            ip=self.host,
            hostname=self.hostname,
            port=self.port,
            domain=self.domain,
            dc_ip=self.domain,
            timeout=self.args.rdp_timeout,
        )

        return True

    def check_nla(self):
        self.logger.debug(f"Checking NLA for {self.host}")
        for proto in self.protoflags_nla:
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(
                    iosettings=self.iosettings,
                    target=self.target,
                    credentials=self.auth,
                )
                asyncio.run(self.connect_rdp())
                if proto.value == SUPP_PROTOCOLS.RDP or proto.value == SUPP_PROTOCOLS.SSL or proto.value == SUPP_PROTOCOLS.SSL | SUPP_PROTOCOLS.RDP:
                    self.nla = False
                    return
            except Exception:
                pass

    async def connect_rdp(self):
        _, err = await asyncio.wait_for(self.conn.connect(), timeout=self.args.rdp_timeout)
        if err is not None:
            raise err

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        try:
            lmhash = ""
            nthash = ""
            # This checks to see if we didn't provide the LM Hash
            if ntlm_hash.find(":") != -1:
                lmhash, nthash = ntlm_hash.split(":")
                self.hash = nthash
            else:
                nthash = ntlm_hash
                self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            kerb_pass = next(s for s in [nthash, password, aesKey] if s) if not all(s == "" for s in [nthash, password, aesKey]) else ""

            self.hostname + "." + self.domain
            password = password if password else nthash

            if useCache:
                stype = asyauthSecret.CCACHE
                if not password:
                    password = password if password else getenv("KRB5CCNAME")
                    if "/" in password:
                        self.logger.fail("Kerberos ticket need to be on the local directory")
                        return False
                    ccache = CCache.loadFile(getenv("KRB5CCNAME"))
                    ticketCreds = ccache.credentials[0]
                    username = ticketCreds["client"].prettyPrint().decode().split("@")[0]
            else:
                stype = asyauthSecret.PASS if not nthash else asyauthSecret.NT

            kerberos_target = UniTarget(
                self.host,
                88,
                UniProto.CLIENT_TCP,
                timeout=self.args.rdp_timeout,
                hostname=self.remoteName,
                dc_ip=self.kdcHost,
                domain=self.domain,
                proxies=None,
                dns=None,
            )
            self.auth = KerberosCredential(
                target=kerberos_target,
                secret=password,
                username=username,
                domain=domain,
                stype=stype,
            )
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            asyncio.run(self.connect_rdp())

            self.admin_privs = True
            self.logger.success(
                "{}\\{}{} {}".format(
                    domain,
                    username,
                    (
                        # Show what was used between cleartext, nthash, aesKey and ccache
                        " from ccache" if useCache else f":{process_secret(kerb_pass)}"
                    ),
                    self.mark_pwned(),
                )
            )
            if not self.args.local_auth and self.username != "":
                add_user_bh(username, domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True

        except Exception as e:
            if "KDC_ERR" in str(e):
                reason = None
                for word in self.rdp_error_status:
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                self.logger.fail(
                    (f"{domain}\\{username}{' from ccache' if useCache else f':{process_secret(kerb_pass)}'} ({reason if reason else str(e)})"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "KDC_ERR_C_PRINCIPAL_UNKNOWN") else "red"),
                )
            elif "Authentication failed!" in str(e):
                self.logger.success(f"{domain}\\{username}:{(process_secret(password))} {self.mark_pwned()}")
            elif "No such file" in str(e):
                self.logger.fail(e)
            else:
                reason = None
                for word in self.rdp_error_status:
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                if str(e) == "cannot unpack non-iterable NoneType object":
                    reason = "User valid but cannot connect"
                self.logger.fail(
                    (f"{domain}\\{username}{' from ccache' if useCache else f':{process_secret(kerb_pass)}'} ({reason if reason else str(e)})"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "STATUS_LOGON_FAILURE") else "red"),
                )
            return False

    def plaintext_login(self, domain, username, password):
        try:
            self.auth = NTLMCredential(
                secret=password,
                username=username,
                domain=domain,
                stype=asyauthSecret.PASS,
            )
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            asyncio.run(self.connect_rdp())

            self.admin_privs = True
            self.logger.success(f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}")
            if not self.args.local_auth and self.username != "":
                add_user_bh(username, domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except Exception as e:
            if "Authentication failed!" in str(e):
                self.logger.success(f"{domain}\\{username}:{process_secret(password)} {self.mark_pwned()}")
            else:
                reason = None
                for word in self.rdp_error_status:
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                if str(e) == "cannot unpack non-iterable NoneType object":
                    reason = "User valid but cannot connect"
                self.logger.fail(
                    (f"{domain}\\{username}:{process_secret(password)} ({reason if reason else str(e)})"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "STATUS_LOGON_FAILURE") else "red"),
                )
            return False

    def hash_login(self, domain, username, ntlm_hash):
        try:
            self.auth = NTLMCredential(
                secret=ntlm_hash,
                username=username,
                domain=domain,
                stype=asyauthSecret.NT,
            )
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            asyncio.run(self.connect_rdp())

            self.admin_privs = True
            self.logger.success(f"{self.domain}\\{username}:{process_secret(ntlm_hash)} {self.mark_pwned()}")
            if not self.args.local_auth and self.username != "":
                add_user_bh(username, domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", domain, self.logger, self.config)
            return True
        except Exception as e:
            if "Authentication failed!" in str(e):
                self.logger.success(f"{domain}\\{username}:{process_secret(ntlm_hash)} {self.mark_pwned()}")
            else:
                reason = None
                for word in self.rdp_error_status:
                    if word in str(e):
                        reason = self.rdp_error_status[word]
                if str(e) == "cannot unpack non-iterable NoneType object":
                    reason = "User valid but cannot connect"

                self.logger.fail(
                    (f"{domain}\\{username}:{process_secret(ntlm_hash)} ({reason if reason else str(e)})"),
                    color=("magenta" if ((reason or "CredSSP" in str(e)) and reason != "STATUS_LOGON_FAILURE") else "red"),
                )
            return False
        
    async def _send_keystrokes(self, text, delay=0.02):
        """Helper method to send keystrokes to the RDP session"""
        for char in text:
            key_event = RDP_KEYBOARD_UNICODE()
            key_event.char = char
            key_event.is_pressed = True
            await self.conn.ext_in_queue.put(key_event)
            await asyncio.sleep(delay)
    
    async def _send_enter(self):
        """Helper method to send Enter key to the RDP session"""
        await self.conn.send_key_virtualkey("VK_RETURN", True, False)
        await asyncio.sleep(0.05)
        await self.conn.send_key_virtualkey("VK_RETURN", False, False)
        
    async def _send_win_r(self):
        """Helper method to send Windows+R key combination to open Run dialog"""
        try:
            self.logger.debug("Sending Win+R using scancode method")
                        
            layout = KeyboardLayoutManager().get_layout_by_shortname("enus")
            
            win_scancode = layout.vk_to_scancode("VK_LWIN")
            await self.conn.send_key_scancode(win_scancode, True, False)
            await asyncio.sleep(0.1)
            
            r_scancode = layout.char_to_scancode("r")[0]
            await self.conn.send_key_scancode(r_scancode, True, False)
            await asyncio.sleep(0.1)
            
            await self.conn.send_key_scancode(r_scancode, False, False)
            await asyncio.sleep(0.1)
            
            await self.conn.send_key_scancode(win_scancode, False, False)
            
            await asyncio.sleep(0.5)
            
            self.logger.debug("Win+R sent successfully")
            return True
        except Exception as e:
            self.logger.debug(f"Error sending Win+R: {e!s}")
            
            self.logger.debug("Using fallback approach for opening command prompt")
            return False
    
    async def execute_cmd(self, payload, encoding=None, capture_screenshot=False):
        """Execute a command using cmd.exe"""
        self.logger.debug(f"Executing command: {payload}")
        
        # Create a connection
        try:
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            await self.connect_rdp()
        except Exception as e:
            self.logger.debug(f"Error connecting to RDP: {e!s}")
            return None
        
        # Wait for desktop to be available
        await asyncio.sleep(3)
        
        try:
            # Try to open Run dialog using Windows+R
            self.logger.debug("Attempting to open Run dialog")
            win_r_success = await self._send_win_r()
            
            if win_r_success:
                # Type cmd.exe in Run dialog
                self.logger.debug("Launching cmd.exe via Run dialog")
                await self._send_keystrokes("cmd.exe")
                await self._send_enter()
                await asyncio.sleep(1.5)  # Wait for cmd window to open
            else:
                # Fallback: Try direct command typing (assumes cmd may already be open)
                self.logger.debug("Sending cmd.exe command directly")
                await self._send_keystrokes("cmd.exe")
                await self._send_enter()
                await asyncio.sleep(1.5)
            
            # Type the command
            self.logger.debug(f"Typing command: {payload}")
            await self._send_keystrokes(payload)
            await self._send_enter()
            
            await asyncio.sleep(3.0)
            
            # Take a screenshot if requested
            if capture_screenshot and self.conn is not None:
                self.logger.debug("Waiting for screen to update...")
                await asyncio.sleep(2.0)  # Additional wait to ensure screen is updated
                
                self.logger.debug(f"Desktop buffer has data: {self.conn.desktop_buffer_has_data}")
                try:
                    self.logger.debug("Capturing command output screenshot")
                    buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
                    screenshots_dir = os.path.expanduser("~/.nxc/screenshots")
                    os.makedirs(screenshots_dir, exist_ok=True)  # Ensure the directory exists
                    filename = os.path.join(screenshots_dir, f"{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
                    buffer.save(filename, "png")
                    self.logger.highlight(f"Command output screenshot saved: {filename}")
                except Exception as e:
                    self.logger.debug(f"Error taking screenshot: {e!s}")
            
            self.logger.debug("Command execution completed")
            return True
            
        finally:
            # Always clean up the connection
            if self.conn is not None:
                self.logger.debug("Terminating RDP connection")
                try:
                    await self.conn.terminate()
                except Exception as e:
                    self.logger.debug(f"Error terminating connection: {e!s}")
    
    async def execute_ps(self, payload, capture_screenshot=False):
        """Execute a command using PowerShell"""
        self.logger.debug(f"Executing PowerShell command: {payload}")
        
        # Create a connection
        try:
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            await self.connect_rdp()
        except Exception as e:
            self.logger.debug(f"Error connecting to RDP: {e!s}")
            return None
        
        # Wait for desktop to be available
        await asyncio.sleep(3)
        
        try:
            # Try to open Run dialog using Windows+R
            self.logger.debug("Attempting to open Run dialog")
            win_r_success = await self._send_win_r()
            
            if win_r_success:
                # Type powershell in Run dialog
                self.logger.debug("Launching PowerShell via Run dialog")
                await self._send_keystrokes("powershell")
                await self._send_enter()
                await asyncio.sleep(1.5)  # Wait for PowerShell window to open
            else:
                # Fallback: Try direct PowerShell typing (assumes we might be at a prompt)
                self.logger.debug("Sending powershell command directly")
                await self._send_keystrokes("powershell")
                await self._send_enter()
                await asyncio.sleep(1.5)
            
            # Type the PowerShell command
            self.logger.debug(f"Typing PowerShell command: {payload}")
            await self._send_keystrokes(payload)
            await self._send_enter()
            
            # Wait longer for command to complete execution
            await asyncio.sleep(3.0)  # Increased wait time to ensure command completes
            
            # Take a screenshot if requested
            if capture_screenshot and self.conn is not None:
                await asyncio.sleep(2.0)  # Additional wait to ensure screen is updated
                
                self.logger.debug(f"Desktop buffer has data: {self.conn.desktop_buffer_has_data}")
                try:
                    self.logger.debug("Capturing PowerShell command output screenshot")
                    buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
                    screenshots_dir = os.path.expanduser("~/.nxc/screenshots")
                    os.makedirs(screenshots_dir, exist_ok=True)  # Ensure the directory exists
                    filename = os.path.join(screenshots_dir, f"{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
                    buffer.save(filename, "png")
                    self.logger.highlight(f"PowerShell command output screenshot saved: {filename}")
                except Exception as e:
                    self.logger.debug(f"Error taking screenshot: {e!s}")
            
            # Exit PowerShell
            self.logger.debug("Exiting PowerShell")
            await self._send_keystrokes("exit")
            await self._send_enter()
            await asyncio.sleep(0.5)
            
            self.logger.debug("PowerShell command execution completed")
            return True
            
        finally:
            if self.conn is not None:
                self.logger.debug("Terminating RDP connection")
                try:
                    await self.conn.terminate()
                except Exception as e:
                    self.logger.debug(f"Error terminating connection: {e!s}")
    
    def execute(self, payload=None, get_output=True, shell_type="cmd"):
        """Execute a command via RDP"""
        if not payload:
            payload = self.args.execute
        
        if self.args.no_output:
            get_output = False
            
        # Check if screenshot is requested
        capture_screenshot = hasattr(self.args, "screenshot") and self.args.screenshot
        
        # Debug the args object to verify the screenshot flag
        self.logger.debug(f"Args object has screenshot attribute: {hasattr(self.args, 'screenshot')}")
        if hasattr(self.args, "screenshot"):
            self.logger.debug(f"Screenshot flag value: {self.args.screenshot}")
        
        if capture_screenshot:
            self.logger.info("Will capture screenshot of command output")

        self.logger.info(f"Executing {shell_type} command: {payload}")
        
        try:
            result = asyncio.run(self.execute_cmd(payload, capture_screenshot=capture_screenshot)) if shell_type == "cmd" else asyncio.run(self.execute_ps(payload, capture_screenshot=capture_screenshot))
            
            if result:
                self.logger.success("Command execution completed")
            return result
        except Exception as e:
            self.logger.debug(f"Command execution error: {e!s}")
            if shell_type == "cmd":
                self.logger.info("Cannot execute command via cmd - now switching to PowerShell to attempt execution")
                try:
                    return self.execute(payload, get_output, shell_type="powershell")
                except Exception as e2:
                    self.logger.fail(f"Execute command failed, error: {e2!s}")
            else:
                self.logger.fail(f"Execute command failed, error: {e!s}")

    def ps_execute(self):
        self.execute(payload=self.args.ps_execute, get_output=True, shell_type="powershell")

    async def screen(self):
        try:
            self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)
            await self.connect_rdp()
        except Exception:
            return

        await asyncio.sleep(5)
        if self.conn is not None and self.conn.desktop_buffer_has_data is True:
            buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
            filename = os.path.expanduser(f"~/.nxc/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
            buffer.save(filename, "png")
            self.logger.highlight(f"Screenshot saved {filename}")

    def screenshot(self):
        # Don't take screenshot if we're already taking one during command execution
        if hasattr(self.args, "execute") and self.args.execute is not None:
            self.logger.debug("Skipping generic screenshot as -x is specified with --screenshot")
            return
        
        if hasattr(self.args, "ps_execute") and self.args.ps_execute is not None:
            self.logger.debug("Skipping generic screenshot as -X is specified with --screenshot")
            return
            
        asyncio.run(self.screen())

    async def nla_screen(self):
        self.auth = NTLMCredential(secret="", username="", domain="", stype=asyauthSecret.PASS)

        for proto in self.protoflags_nla:
            try:
                self.iosettings.supported_protocols = proto
                self.conn = RDPConnection(iosettings=self.iosettings, target=self.target, credentials=self.auth)

                await self.connect_rdp()
            except Exception as e:
                self.logger.debug(f"Failed to connect for nla_screenshot with {proto} {e}")
                return

            await asyncio.sleep(int(self.args.screentime))
            if self.conn is not None and self.conn.desktop_buffer_has_data is True:
                buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
                filename = os.path.expanduser(f"{NXC_PATH}/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png")
                buffer.save(filename, "png")
                self.logger.highlight(f"NLA Screenshot saved {filename}")
                return

    def nla_screenshot(self):
        if not self.nla:
            asyncio.run(self.nla_screen())
