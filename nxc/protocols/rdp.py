import asyncio
import base64
import copy
import contextlib
from datetime import datetime
from os import getenv
from uuid import uuid4
from anyio import Path
from termcolor import colored

from impacket.krb5.ccache import CCache

from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter
from nxc.config import host_info_colors, process_secret
from nxc.paths import NXC_PATH

from aardwolf.connection import RDPConnection
from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
from aardwolf.commons.queuedata.keyboard import RDP_KEYBOARD_UNICODE
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.target import RDPTarget
from aardwolf.keyboard.layoutmanager import KeyboardLayoutManager
from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
from aardwolf.network.x224 import X224Network
from aardwolf.network.tpkt import TPKTPacketizer
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.constants import asyauthSecret
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.client import UniClient


class rdp(connection):
    def __init__(self, args, db, host):
        self.domain = None
        self.server_os = None
        self.iosettings = RDPIOSettings()
        self.iosettings.video_out_format = VIDEO_FORMAT.RAW
        self.iosettings.clipboard_use_pyperclip = False
        self.protoflags_nla = [
            SUPP_PROTOCOLS.SSL,
            SUPP_PROTOCOLS.RDP,
        ]
        self.protoflags = [
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
            try:
                self.db.add_host(self.host, self.port, self.hostname, self.domain, self.server_os, self.nla)
            except Exception as e:
                self.logger.debug(f"Error adding host {self.host} into db: {e!s}")

    def _create_rdp_connection(self, credentials, supported_protocols=None):
        iosettings = self.iosettings.clone_for_connection()
        # Explicit protocols are used by discovery and screenshot fallbacks.
        # Authenticated connections leave this unset so aardwolf selects the
        # X224 flags appropriate for the credential type.
        iosettings.supported_protocols = supported_protocols
        return RDPConnection(
            iosettings=iosettings,
            target=copy.deepcopy(self.target),
            credentials=copy.deepcopy(credentials),
        )

    def create_conn_obj(self):
        self.target = RDPTarget(ip=self.host, domain="FAKE", port=self.port, timeout=self.args.rdp_timeout)
        self.auth = NTLMCredential(secret="pass", username="user", domain="FAKE", stype=asyauthSecret.PASS)

        asyncio.run(self.check_nla())

        for proto in reversed(self.protoflags):
            try:
                self.conn = self._create_rdp_connection(
                    self.auth, supported_protocols=proto
                )
                asyncio.run(self.connect_rdp_with_cleanup())
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

    async def check_nla(self):
        self.logger.debug(f"Checking NLA for {self.host}")
        try:
            self.conn = self._create_rdp_connection(
                None, supported_protocols=SUPP_PROTOCOLS.SSL
            )
            packetizer = TPKTPacketizer()
            client = UniClient(self.target, packetizer)
            self.conn._connection = await asyncio.wait_for(client.connect(), timeout=self.args.rdp_timeout)
            self.conn._x224net = X224Network(self.conn._connection)
            _, err = await asyncio.wait_for(self.conn._x224net.client_negotiate(0, SUPP_PROTOCOLS.SSL), timeout=self.args.rdp_timeout)
            # If no error SSL supported if SSL_NOT_ALLOWED_BY_SERVER error, plain RDP supported
            if err is None or "SSL_NOT_ALLOWED_BY_SERVER" in str(err):
                self.nla = False
                return
        except Exception:
            pass

    async def connect_rdp(self, auth_only=False):
        """Connect to the RDP server. Does NOT clean up on exit.

        When auth_only is True, performs only CredSSP/NLA authentication
        without establishing a full RDP session. This verifies credentials
        without creating a disconnected session on single-session hosts.
        """
        _, err = await asyncio.wait_for(self.conn.connect(auth_only=auth_only), timeout=self.args.rdp_timeout)
        if err is not None:
            raise err

    async def terminate_conn(self):
        """Terminate the RDP connection with a timeout so cleanup doesn't hang."""
        if self.conn is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.conn.terminate(), timeout=self.args.rdp_timeout)

    async def connect_rdp_with_cleanup(self, auth_only=False):
        """Connect to the RDP server and always terminate the connection on exit"""
        try:
            await self.connect_rdp(auth_only=auth_only)
        finally:
            await self.terminate_conn()

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
            elif aesKey:
                stype = asyauthSecret.AES
                password = aesKey
            else:
                stype = asyauthSecret.PASS if not nthash else asyauthSecret.NT
                password = password if password else nthash

            kerb_pass = password

            kerberos_target = UniTarget(
                self.kdcHost,
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
            self.conn = self._create_rdp_connection(self.auth)
            asyncio.run(self.connect_rdp_with_cleanup(auth_only=self._execution_pending()))

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

    def _execution_pending(self):
        """Check if command execution will follow authentication."""
        return bool(self.args.execute or self.args.ps_execute)

    def plaintext_login(self, domain, username, password):
        try:
            self.auth = NTLMCredential(
                secret=password,
                username=username,
                domain=domain,
                stype=asyauthSecret.PASS,
            )
            self.conn = self._create_rdp_connection(self.auth)
            # When execution follows, use auth_only to verify credentials
            # without creating a full session (avoids Win11 clipboard issues).
            asyncio.run(self.connect_rdp_with_cleanup(auth_only=self._execution_pending()))

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
            self.conn = self._create_rdp_connection(self.auth)
            asyncio.run(self.connect_rdp_with_cleanup(auth_only=self._execution_pending()))

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
            for is_pressed in (True, False):
                key_event = RDP_KEYBOARD_UNICODE()
                key_event.char = char
                key_event.is_pressed = is_pressed
                await self.conn.ext_in_queue.put(key_event)
            await asyncio.sleep(delay)

    async def _send_enter(self):
        """Helper method to send Enter key to the RDP session"""
        await self.conn.send_key_virtualkey("VK_RETURN", True, False)
        await asyncio.sleep(0.05)
        await self.conn.send_key_virtualkey("VK_RETURN", False, False)

    async def _send_shortcut(self, modifier, key):
        layout = KeyboardLayoutManager().get_layout_by_shortname("enus")
        modifier_scancode = layout.vk_to_scancode(modifier)
        key_scancode = layout.char_to_scancode(key)[0]

        await self.conn.send_key_scancode(modifier_scancode, True, False)
        await asyncio.sleep(0.05)
        await self.conn.send_key_scancode(key_scancode, True, False)
        await asyncio.sleep(0.05)
        await self.conn.send_key_scancode(key_scancode, False, False)
        await asyncio.sleep(0.05)
        await self.conn.send_key_scancode(modifier_scancode, False, False)

    async def _send_win_r(self):
        """Helper method to send Windows+R key combination to open Run dialog"""
        self.logger.debug("Sending Win+R using scancode method")
        for _ in range(2):
            _, err = await self.conn.send_focus_in()
            if err is not None:
                raise err
        await self._send_shortcut("VK_LWIN", "r")
        await asyncio.sleep(0.5)

    @staticmethod
    def _build_execution_command(payload, shell_type, marker, get_output):
        if not get_output:
            if shell_type == "cmd":
                return f"cmd.exe /d /s /c {payload}"
            if shell_type == "powershell":
                return (
                    "powershell.exe -NoLogo -NoProfile -NonInteractive "
                    f"-WindowStyle Hidden -Command {payload}"
                )
            raise ValueError(f"Unsupported shell type: {shell_type}")

        payload_encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
        decode_payload = f"$command = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{payload_encoded}'))"

        if shell_type == "cmd":
            invoke_command = "$output = & $env:ComSpec /d /s /c $command 2>&1"
        elif shell_type == "powershell":
            invoke_command = "$output = & ([ScriptBlock]::Create($command)) 2>&1"
        else:
            raise ValueError(f"Unsupported shell type: {shell_type}")

        start_marker = f"__NXC_RDP_START_{marker}__"
        end_marker = f"__NXC_RDP_END_{marker}__"
        script = f"""
$ErrorActionPreference = 'Continue'
{decode_payload}
try {{
    {invoke_command}
    $succeeded = $?
    $nativeExitCode = $LASTEXITCODE
}} catch {{
    $output = $_
    $succeeded = $false
    $nativeExitCode = $null
}}
$exitCode = if ($null -ne $nativeExitCode) {{ [int]$nativeExitCode }} elseif (-not $succeeded) {{ 1 }} else {{ 0 }}
$outputText = ($output | Out-String -Width 4096).TrimEnd()
$result = @('{start_marker}', [string]$exitCode, $outputText, '{end_marker}') -join [Environment]::NewLine
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::SetText($result)
"""

        encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return f"powershell.exe -NoLogo -NoProfile -NonInteractive -STA -WindowStyle Hidden -EncodedCommand {encoded_script}"

    @staticmethod
    def _parse_execution_result(clipboard_text, marker):
        start_marker = f"__NXC_RDP_START_{marker}__"
        end_marker = f"__NXC_RDP_END_{marker}__"
        normalized = clipboard_text.replace("\r\n", "\n").rstrip("\x00")

        start_index = normalized.find(start_marker)
        end_index = normalized.find(end_marker, start_index + len(start_marker))
        if start_index == -1 or end_index == -1:
            return None

        body = normalized[start_index + len(start_marker):end_index].lstrip("\n")
        exit_code_text, separator, output = body.partition("\n")
        if not separator:
            return None

        try:
            exit_code = int(exit_code_text.strip())
        except ValueError:
            return None
        return exit_code, output.rstrip("\n")

    async def _wait_for_event(self, event_names, max_wait):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max_wait

        while True:
            if self.conn.disconnected_evt.is_set():
                raise ConnectionError("RDP connection was terminated")

            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError

            data = await asyncio.wait_for(self.conn.ext_out_queue.get(), timeout=remaining)
            if data is None:
                raise ConnectionError("RDP connection was terminated")

            event_name = getattr(getattr(data, "type", None), "name", None)
            if event_name in event_names:
                return data

    async def _wait_for_desktop(self):
        loop = asyncio.get_running_loop()
        started_at = loop.time()

        if not self.conn.desktop_buffer_has_data:
            try:
                await self._wait_for_event({"VIDEO"}, self.args.cmd_delay)
            except asyncio.TimeoutError:
                self.logger.debug("No desktop update received before command execution; continuing")

        remaining_delay = self.args.cmd_delay - (loop.time() - started_at)
        if remaining_delay > 0:
            await asyncio.sleep(remaining_delay)

    async def _submit_run_command(self, command):
        await self._send_win_r()
        await self.conn.set_current_clipboard_text(command)
        # server must acknowledge our clipboard data before we trigger the read
        response = await self._wait_for_event(
            {"CLIPBOARD_FORMAT_LIST_RESPONSE"}, self.args.clipboard_delay
        )
        if not response.accepted:
            raise RuntimeError(
                "Remote session rejected the clipboard command data"
            )
        # type a one-liner that reads and executes the clipboard we just set
        # uses .NET WinForms API instead of Get-Clipboard (which requires PS5+)
        await self._send_keystrokes(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -STA "
            '-WindowStyle Hidden -Command "Add-Type -AssemblyName '
            "System.Windows.Forms; Invoke-Expression "
            '([System.Windows.Forms.Clipboard]::GetText())"'
        )
        await self._send_enter()

    async def _submit_typed_run_command(self, command):
        await self._send_win_r()
        await self._send_keystrokes(command, delay=0.005)
        await self._send_enter()

    async def _wait_for_command_result(self, marker):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.args.clipboard_delay

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError

            data = await self._wait_for_event({"CLIPBOARD_DATA_TXT"}, remaining)
            result = self._parse_execution_result(data.data, marker)
            if result is not None:
                return result

    async def execute_shell(self, payload, get_output, shell_type):
        marker = uuid4().hex if get_output else None
        command = self._build_execution_command(
            payload, shell_type, marker, get_output
        )
        self.logger.debug(f"Executing {shell_type} command through {'an encoded PowerShell launcher' if get_output else 'interactive keyboard input'}")

        try:
            self.conn = self._create_rdp_connection(self.auth)
            await self.connect_rdp()
        except Exception as e:
            self.logger.debug(f"Error connecting to RDP: {e!s}")
            if "CredSSP" in str(e) or "STATUS_LOGON" in str(e):
                self.logger.fail(f"Authentication failed: {e!s}")
            await self.terminate_conn()
            return None

        try:
            if get_output:
                self.logger.success("Waiting for clipboard to be ready...")
                try:
                    await self._wait_for_event({"CLIPBOARD_READY"}, self.args.clipboard_delay)
                except asyncio.TimeoutError:
                    self.logger.fail("Clipboard cannot be initialized, no output can be retrieved")
                    return None

            await self._wait_for_desktop()
            if get_output:
                try:
                    await self._submit_run_command(command)
                except asyncio.TimeoutError:
                    self.logger.fail(
                        "Remote session did not acknowledge the clipboard command data"
                    )
                    return None
            else:
                await self._submit_typed_run_command(command)

            if not get_output:
                await asyncio.sleep(self.args.cmd_delay)
                self.logger.success("Executed command without retrieving output")
                return None

            try:
                exit_code, output = await self._wait_for_command_result(marker)
            except asyncio.TimeoutError:
                self.logger.fail("Timed out waiting for command output on the RDP clipboard")
                return None

            if exit_code != 0:
                self.logger.fail(f"Command completed with exit code {exit_code}")
            if output:
                for line in output.splitlines():
                    self.logger.highlight(line)
            else:
                self.logger.debug("Command completed without output")
            return output

        except (ConnectionResetError, ConnectionError, OSError) as e:
            self.logger.debug(f"Connection error: {e!s}")
            self.logger.fail("Connection was reset by the remote host")
            return None
        except Exception as e:
            self.logger.debug(f"Unexpected error: {e!s}")
            self.logger.fail(f"Command execution failed: {e!s}")
            return None
        finally:
            # clean up the connection with a timeout to prevent aardwolf deadlock (see https://github.com/skelsec/aardwolf/issues/43)
            self.logger.debug("Terminating RDP connection")
            await self.terminate_conn()

    def execute(self, payload=None, shell_type="cmd"):
        """Execute a command via RDP"""
        if not payload:
            payload = self.args.execute

        get_output = bool(not self.args.no_output)

        self.logger.success(f"Executing command: {payload}")

        try:
            result = asyncio.run(self.execute_shell(payload, get_output, shell_type))

            if result is not None:
                self.logger.debug("Command execution completed")
            return result
        except Exception as e:
            self.logger.error(f"Command execution error: {e!s}")
            self.logger.fail(f"Execute command failed, error: {e!s}")

    def ps_execute(self):
        self.execute(payload=self.args.ps_execute, shell_type="powershell")

    async def screen(self):
        try:
            self.conn = self._create_rdp_connection(self.auth)
            await self.connect_rdp()

            await asyncio.sleep(5)
            if self.conn is not None and self.conn.desktop_buffer_has_data is True:
                buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
                filename = await Path(f"{NXC_PATH}/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png").expanduser()
                buffer.save(filename, "png")
                self.logger.highlight(f"Screenshot saved {filename}")
        except Exception as e:
            self.logger.debug(f"Error taking screenshot: {e!s}")
        finally:
            await self.terminate_conn()

    def screenshot(self):
        asyncio.run(self.screen())

    async def nla_screen(self):
        self.auth = NTLMCredential(secret="", username="", domain="", stype=asyauthSecret.PASS)

        for proto in self.protoflags_nla:
            try:
                self.conn = self._create_rdp_connection(
                    self.auth, supported_protocols=proto
                )
                await self.connect_rdp()
            except Exception as e:
                self.logger.debug(f"Failed to connect for nla_screenshot with {proto} {e}")
                await self.terminate_conn()
                continue

            try:
                await asyncio.sleep(int(self.args.screentime))
                if self.conn is not None and self.conn.desktop_buffer_has_data is True:
                    buffer = self.conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
                    filename = await Path(f"{NXC_PATH}/screenshots/{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png").expanduser()
                    buffer.save(filename, "png")
                    self.logger.highlight(f"NLA Screenshot saved {filename}")
                    return
            finally:
                await self.terminate_conn()

    def nla_screenshot(self):
        if not self.nla:
            asyncio.run(self.nla_screen())
