import os
import time
import random
import string
import logging
from io import BytesIO
from pathlib import Path
from nxc.paths import DATA_PATH
from threading import Thread, Lock

from impacket import smb
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure
from impacket.examples import serviceinstall
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_21


class PsExecInit1_9(Structure):
    structure = (
        ("PacketSize", "<I"),
        ("PID", "<I"),
        ("Computer", "520s"),
        ("Command", "520s"),
        ("Arguments", "520s"),
        ("OthersOptions", "16385s"),
        ("ElevateToSystem", "1s"),
        ("Interactif", "1s"),
        ("LogonUser", "1s"),
        ("RestrictedToken", "1s"),
        ("HighPrivToken", "1s"),
        ("OthersFlags", "16s"),
        ("Username", "520s=''"),
        ("Password", "520s=''"),
        ("Padding", "18s=''")
    )


lock = Lock()


class PSEXEC:
    def __init__(self, host, share_name, smbconnection, username="", password="", domain="", doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, share=None, port=445, logger=None, tries=None, as_user=False):
        self.logger = logger
        self.host = host
        self.port = port
        self.smbconnection = smbconnection
        self.lmhash = ""
        self.nthash = ""
        self.as_user = as_user
        if hashes is not None:
            if hashes.find(":") != -1:
                self.lmhash, self.nthash = hashes.split(":")
            else:
                self.nthash = hashes
        self.domain = domain
        self.username = username
        self.password = password
        self.aesKey = aesKey
        self.kdcHost = kdcHost
        self.do_kerberos = doKerberos
        self.service_name = "PSEXESVC"
        self.remote_binary_name = "PSEXESVC.exe"
        self.remoteHost = remoteHost
        self.tries = tries

        self.rpctransport = transport.DCERPCTransportFactory(f"ncacn_np:{self.host}[\\pipe\\svcctl]")
        self.rpctransport.set_dport(self.port)
        self.rpctransport.setRemoteHost(self.remoteHost)

        if hasattr(self.rpctransport, "set_credentials"):
            self.rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)

        self.rpctransport.set_kerberos(self.do_kerberos, self.kdcHost)
        self.rpctransport.preferred_dialect(SMB2_DIALECT_21)

    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid, pipe)
                pipeReady = True
            except Exception:
                tries -= 1
                time.sleep(2)

        if tries == 0:
            raise Exception("Pipe not ready, aborting")

        return s.openFile(tid, pipe, accessMask, creationOption=0x40, fileAttributes=0x80)

    def execute(self, command, output=False):
        dce = self.rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            return b""

        global dialect
        dialect = self.rpctransport.get_smb_connection().getDialect()

        s = self.rpctransport.get_smb_connection()
        s.setTimeout(100000)

        psexesvc_path = Path(f"{DATA_PATH}/psexec/binary/PSEXESVC.exe")
        if psexesvc_path.is_file():
            with open(psexesvc_path, "rb") as handle:
                self.psexesvc_buffer = handle.read()
        else:
            self.logger.fail(f"Cannot find {self.psexesvc_buffer}...")
            return b""

        try:

            installService = serviceinstall.ServiceInstall(
                self.rpctransport.get_smb_connection(),
                BytesIO(self.psexesvc_buffer),
                self.service_name,
                self.remote_binary_name
            )
            installService.install()

            tid = s.connectTree("IPC$")
            fid_main = self.openPipe(s, tid, f"\\{self.remote_binary_name.split('.')[0]}", 0x12019f)

            s.writeNamedPipe(tid, fid_main, bytes.fromhex("BE000000"))
            s.readNamedPipe(tid, fid_main, 4)

            init = PsExecInit1_9()
            init["PacketSize"] = 19032
            init["PID"] = os.getpid()
            random_string = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            init["Computer"] = random_string.encode("utf-16le").ljust(520, b"\0")
            init["Command"] = "cmd.exe".encode("utf-16le").ljust(520, b"\0")
            init["Arguments"] = f"/c {command}".encode("utf-16le").ljust(520, b"\0")
            init["OthersOptions"] = "".encode("utf-16le").ljust(16385, b"\0")
            init["Interactif"] = bytes.fromhex("00")
            init["RestrictedToken"] = bytes.fromhex("00")
            init["HighPrivToken"] = bytes.fromhex("01")
            init["LogonUser"] = bytes.fromhex("00")
            init["ElevateToSystem"] = bytes.fromhex("00")
            init["OthersFlags"] = bytes.fromhex("00000000000000000000ffffffff0100")
            init["Padding"] = bytes.fromhex("000000000000010000000000000000000000")

            if not self.as_user:
                init["ElevateToSystem"] = bytes.fromhex("01")
            else:
                init["Username"] = f"{self.domain}\\{self.username}".encode("utf-16le").ljust(520, b"\0")
                init["Password"] = f"{self.password}".encode("utf-16le").ljust(520, b"\0")
                init["LogonUser"] = bytes.fromhex("01")

            data = init.getData()
            s.writeNamedPipe(tid, fid_main, data)

            pipe_base = f"\\{self.remote_binary_name.split('.')[0]}-{random_string}-{init['PID']}"

            stdin_pipe = RemoteStdInPipe(self.rpctransport, f"{pipe_base}-stdin", smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare())
            stdin_pipe.start()
            time.sleep(1)

            stdout_pipe = RemoteStdOutPipe(self.rpctransport, f"{pipe_base}-stdout", smb.FILE_READ_DATA)
            stdout_pipe.start()

            stderr_pipe = RemoteStdErrPipe(self.rpctransport, f"{pipe_base}-stderr", smb.FILE_READ_DATA)
            stderr_pipe.start()

            stdout_pipe.join()
            stderr_pipe.join()

            return stdout_pipe.output + stderr_pipe.output

        except Exception:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            return b""
        finally:
            installService.uninstall()


class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.output = b""

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            self.server = SMBConnection(
                self.transport.get_smb_connection().getRemoteName(),
                self.transport.get_smb_connection().getRemoteHost(),
                sess_port=self.port,
                preferredDialect=SMB2_DIALECT_21
            )
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(
                    user, passwd, domain, lm, nt, aesKey,
                    kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS
                )
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree("IPC$")

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid, self.pipe, self.permissions, creationOption=0x40, fileAttributes=0x80)
            self.server.setTimeout(1000000)
        except Exception:
            lock.release()
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

    def disconnectPipe(self):
        try:
            if self.fid:
                self.server.closeFile(self.tid, self.fid)
            if self.tid:
                self.server.disconnectTree(self.tid)
            if self.server and self.server != 0:
                self.server.logoff()
                self.server.close()
        except Exception:
            pass


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permissions):
        Pipes.__init__(self, transport, pipe, permissions)

    def run(self):
        try:
            self.connectPipe()
            while True:
                try:
                    ans = self.server.readFile(self.tid, self.fid, 0, 4096)
                    if ans:
                        self.output += ans
                    else:
                        break
                except Exception:
                    break
        finally:
            self.disconnectPipe()


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permissions):
        Pipes.__init__(self, transport, pipe, permissions)

    def run(self):
        try:
            self.connectPipe()
            while True:
                try:
                    ans = self.server.readFile(self.tid, self.fid, 0, 4096)
                    if ans:
                        self.output += ans
                    else:
                        break
                except Exception:
                    break
        finally:
            self.disconnectPipe()


class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permissions, share=None):
        Pipes.__init__(self, transport, pipe, permissions, share)

    def run(self):
        try:
            self.connectPipe()
        except Exception:
            pass
        finally:
            self.disconnectPipe()
