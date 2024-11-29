# everything is comming from https://github.com/ly4k/SMBGhost
# credit to @ly4k_
# module by : @r4vanan
import socket
import struct

# Constants
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%

# SMBGhost Packet
SMBGHOST_PKT = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

class NXCModule:
    name = "smbghost"
    description = "Module to check for the SMB dialect 3.1.1 and compression capability of the host, which is an indicator for the SMBGhost vulnerability (CVE-2020-0796)."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        # Define options if needed
        pass

    def on_login(self, context, connection):
        self.context = context
        if self.perform_attack(connection.host):
            self.context.log.highlight("Potentially vulnerable to SMBGhost (CVE-2020-0796)")

    def perform_attack(self, target_ip):
        self.context.log.debug("Performing SMBGhost check...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((target_ip, 445))
                sock.send(SMBGHOST_PKT)

                # Receive the first 4 bytes for length
                nb_data = sock.recv(4)
                if len(nb_data) < 4:
                    self.context.log.debug(f"{target_ip} Connection closed unexpectedly.")
                    return False

                nb, = struct.unpack(">I", nb_data)
                res = sock.recv(nb)

                # Check response for vulnerability
                if res[68:70] == b"\x11\x03" and res[70:72] == b"\x02\x00":
                    return True
                else:
                    self.context.log.debug(f"{target_ip} Not vulnerable.")
                    return False
        except Exception as e:
            self.context.log.fail(f"Error while connecting to host: {e}")
            return False
