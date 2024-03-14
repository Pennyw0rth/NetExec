# All credits to https://github.com/d4t4s3c/Win7Blue
# @d4t4s3c
# Module by @mpgn_x64

from ctypes import c_uint8, c_uint16, c_uint32, c_uint64, Structure
import socket
import struct
from nxc.logger import nxc_logger


class SmbHeader(Structure):
    """SMB Header decoder."""

    _pack_ = 1

    _fields_ = [
        ("server_component", c_uint32),
        ("smb_command", c_uint8),
        ("error_class", c_uint8),
        ("reserved1", c_uint8),
        ("error_code", c_uint16),
        ("flags", c_uint8),
        ("flags2", c_uint16),
        ("process_id_high", c_uint16),
        ("signature", c_uint64),
        ("reserved2", c_uint16),
        ("tree_id", c_uint16),
        ("process_id", c_uint16),
        ("user_id", c_uint16),
        ("multiplex_id", c_uint16),
    ]

    def __init__(self, buffer):
        nxc_logger.debug("server_component : %04x" % self.server_component)
        nxc_logger.debug("smb_command      : %01x" % self.smb_command)
        nxc_logger.debug("error_class      : %01x" % self.error_class)
        nxc_logger.debug("error_code       : %02x" % self.error_code)
        nxc_logger.debug("flags            : %01x" % self.flags)
        nxc_logger.debug("flags2           : %02x" % self.flags2)
        nxc_logger.debug("process_id_high  : %02x" % self.process_id_high)
        nxc_logger.debug("signature        : %08x" % self.signature)
        nxc_logger.debug("reserved2        : %02x" % self.reserved2)
        nxc_logger.debug("tree_id          : %02x" % self.tree_id)
        nxc_logger.debug("process_id       : %02x" % self.process_id)
        nxc_logger.debug("user_id          : %02x" % self.user_id)
        nxc_logger.debug("multiplex_id     : %02x" % self.multiplex_id)

    def __new__(self, buffer=None):
        nxc_logger.debug(f"Creating SMB_HEADER object from buffer: {buffer}")
        return self.from_buffer_copy(buffer)


class NXCModule:
    name = "ms17-010"
    description = "MS17-010 - EternalBlue - NOT TESTED OUTSIDE LAB ENVIRONMENT"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """
        self.logger = context.log

    def on_login(self, context, connection):
        try:
            if self.check(connection.host):
                context.log.highlight("VULNERABLE")
                context.log.highlight("Next step: https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/")
        except ConnectionResetError as e:
            context.log.debug(f"Error connecting to host when checking for MS17-010: {e!s}")
        except ValueError as e:
            if str(e) == "Buffer size too small (0 instead of at least 32 bytes)":
                context.log.debug("Buffer size too small, which means the response was not the expected size")


    def generate_smb_proto_payload(self, *protos):
        """
        Flattens a nested list and merges all bytes objects into a single bytes object.

        Args:
        ----
            *protos (list): The list to flatten and merge.

        Returns:
        -------
            bytes: The merged bytes object.
        """
        self.logger.debug("generate smb proto payload")
        self.logger.debug(f"Protos: {protos}")

        hex_data = b""
        for proto in protos:
            if isinstance(proto, list):
                hex_data += self.generate_smb_proto_payload(*proto)
            elif isinstance(proto, bytes):
                hex_data += proto

        self.logger.debug(f"Packed proto data: {hex_data}")
        return hex_data


    def calculate_doublepulsar_xor_key(self, s):
        """
        Calculate Doublepulsar Xor Key.

        Args:
        ----
            s (int): The input value.

        Returns:
        -------
            int: The calculated xor key.
        """
        nxc_logger.debug(f"Calculating Doublepulsar XOR key for: {s}")
        x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
        return x & 0xffffffff  # truncate to 32 bits



    def negotiate_proto_request(self):
        """Generate a negotiate_proto_request packet."""
        self.logger.debug("generate negotiate proto request")

        # Define the NetBIOS header
        netbios = [
            b"\x00",  # Message Type
            b"\x00\x00\x54",  # Length
        ]

        # Define the SMB header
        smb_header = [
            b"\xFF\x53\x4D\x42",  # Server Component
            b"\x72",  # SMB Command
            b"\x00\x00\x00\x00",  # NT Status
            b"\x18",  # Flags
            b"\x01\x28",  # Flags2
            b"\x00\x00",  # Process ID High
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Signature
            b"\x00\x00",  # Reserved
            b"\x00\x00",  # Tree ID
            b"\x2F\x4B",  # Process ID
            b"\x00\x00",  # User ID
            b"\xC5\x5E",  # Multiplex ID
        ]

        # Define the negotiate_proto_request
        negotiate_proto_request = [
            b"\x00",  # Word Count
            b"\x31\x00",  # Byte Count
            b"\x02",  # Requested Dialects Count
            b"\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00",  # Requested Dialects: LANMAN1.0
            b"\x02",  # Requested Dialects Count
            b"\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00",  # Requested Dialects: LM1.2X002
            b"\x02",  # Requested Dialects Count
            b"\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00",  # Requested Dialects: NT LANMAN 1.0
            b"\x02",  # Requested Dialects Count
            b"\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00",  # Requested Dialects: NT LM 0.12
        ]

        # Return the generated SMB protocol payload
        return self.generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


    def session_setup_andx_request(self):
        """Generate session setup andx request."""
        self.logger.debug("generate session setup andx request"
        )
        # Define the NetBIOS bytes
        netbios = [
            b"\x00",  # length
            b"\x00\x00\x63",  # session service
        ]

        # Define the SMB header bytes
        smb_header = [
            b"\xFF\x53\x4D\x42",  # server component: .SMB
            b"\x73",  # command: Session Setup AndX
            b"\x00\x00\x00\x00",  # NT status
            b"\x18",  # flags
            b"\x01\x20",  # flags2
            b"\x00\x00",  # PID high
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # signature
            b"\x00\x00",  # reserved
            b"\x00\x00",  # tree id
            b"\x2F\x4B",  # pid
            b"\x00\x00",  # uid
            b"\xC5\x5E",  # multiplex id
        ]

        # Define the session setup andx request bytes
        session_setup_andx_request = [
            b"\x0D",  # word count
            b"\xFF",  # andx command: no further commands
            b"\x00",  # reserved
            b"\x00\x00",  # andx offset
            b"\xDF\xFF",  # max buffer
            b"\x02\x00",  # max mpx count
            b"\x01\x00",  # VC number
            b"\x00\x00\x00\x00",  # session key
            b"\x00\x00",  # ANSI password length
            b"\x00\x00",  # Unicode password length
            b"\x00\x00\x00\x00",  # reserved
            b"\x40\x00\x00\x00",  # capabilities
            b"\x26\x00",  # byte count
            b"\x00",  # account
            b"\x2e\x00",  # primary domain
            b"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00",  # Native OS: Windows 2000 2195
            b"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00",  # Native OS: Windows 2000 5.0
        ]

        return self.generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


    def tree_connect_andx_request(self, ip, userid):
        """Generate tree connect andx request.

        Args:
        ----
            ip (str): The IP address.
            userid (str): The user ID.

        Returns:
        -------
            bytes: The generated tree connect andx request payload.
        """
        self.logger.debug("generate tree connect andx request")

        # Initialize the netbios header
        netbios = [
            b"\x00",  # 'Message_Type'
            b"\x00\x00\x47"  # 'Length'
        ]

        # Initialize the SMB header
        smb_header = [
            b"\xFF\x53\x4D\x42",  # server_compnent: .SMB
            b"\x75",  # smb_command: Tree Connect AndX
            b"\x00\x00\x00\x00",  # 'nt_status'
            b"\x18",  # 'flags'
            b"\x01\x20",  # 'flags2'
            b"\x00\x00",  # 'process_id_high'
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # 'signature'
            b"\x00\x00",  # 'reserved'
            b"\x00\x00",  # 'tree_id'
            b"\x2F\x4B",  # 'process_id'
            userid,  # 'user_id'
            b"\xC5\x5E",  # 'multiplex_id'
        ]

        # Create the IPC string
        ipc = f"\\\\{ip}\\IPC$\x00"
        self.logger.debug(f"Connecting to {ip} with UID: {userid.hex()}")

        # Initialize the tree connect andx request
        tree_connect_andx_request = [
            b"\x04",  # Word Count
            b"\xFF",  # AndXCommand: No further commands
            b"\x00",  # Reserved
            b"\x00\x00",  # AndXOffset
            b"\x00\x00",  # Flags
            b"\x01\x00",  # Password Length
            b"\x1A\x00",  # Byte Count
            b"\x00",  # Password
            ipc.encode(),  # \\xxx.xxx.xxx.xxx\IPC$
            b"\x3f\x3f\x3f\x3f\x3f\x00",  # Service
        ]

        # Calculate the length of the payload
        length = len(b"".join(smb_header)) + len(b"".join(tree_connect_andx_request))
        self.logger.debug(f"Length of payload: {length}")

        # Update the length in the netbios header
        netbios[1] = struct.pack(">L", length)[-3:]

        self.logger.debug(f"Netbios: {netbios}")
        self.logger.debug(f"SMB Header: {smb_header}")
        self.logger.debug(f"Tree Connect AndX Request: {tree_connect_andx_request}")

        # Generate the final SMB protocol payload
        return self.generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


    def peeknamedpipe_request(self, treeid, processid, userid, multiplex_id):
        """
        Generate tran2 request.

        Args:
        ----
            treeid (str): The tree ID.
            processid (str): The process ID.
            userid (str): The user ID.
            multiplex_id (str): The multiplex ID.

        Returns:
        -------
            str: The generated SMB protocol payload.
        """
        self.logger.debug("generate peeknamedpipe request")

        # Set the necessary values for the netbios header
        netbios = [
            b"\x00",  # message type
            b"\x00\x00\x4a"  # length
        ]

        # Set the values for the SMB header
        smb_header = [
            b"\xFF\x53\x4D\x42",  # Server Component: .SMB
            b"\x25",  # SMB Command: Trans2
            b"\x00\x00\x00\x00",  # NT Status
            b"\x18",  # flags
            b"\x01\x28",  # flags2
            b"\x00\x00",  # pid high
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # sig
            b"\x00\x00",  # Reserved
            treeid,  # Tree ID
            processid,  # Process ID
            userid,  # User ID
            multiplex_id,  # Multiplex ID
        ]

        # Set the values for the transaction request
        tran_request = [
            b"\x10",  # Word Count
            b"\x00\x00",  # Total Parameter Count
            b"\x00\x00",  # Total Data Count
            b"\xff\xff",  # Max Parameter Count
            b"\xff\xff",  # Max Data Count
            b"\x00",  # Max Setup Count
            b"\x00",  # Reserved
            b"\x00\x00",  # Flags
            b"\x00\x00\x00\x00",  # Timeout
            b"\x00\x00",  # Reserved
            b"\x00\x00",  # Parameter Count
            b"\x4a\x00",  # Parameter Offset
            b"\x00\x00",  # Data Count
            b"\x4a\x00",  # Data Offset
            b"\x02",  # Setup Count
            b"\x00",  # Reserved
            b"\x23\x00",  # SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
            b"\x00\x00",  # SMB Pipe Protocol: FID
            b"\x07\x00",
            b"\x5c\x50\x49\x50\x45\x5c\x00",  # \PIPE\
        ]

        return self.generate_smb_proto_payload(netbios, smb_header, tran_request)


    def trans2_request(self, treeid, processid, userid, multiplex_id):
        """Generate trans2 request.

        Args:
        ----
            treeid: The treeid parameter.
            processid: The processid parameter.
            userid: The userid parameter.
            multiplex_id: The multiplex_id parameter.

        Returns:
        -------
            The generated SMB protocol payload.
        """
        self.logger.debug("generate trans2 request")

        # Define the netbios section of the SMB request
        netbios = [
            b"\x00",
            b"\x00\x00\x4f"
        ]

        # Define the SMB header section of the SMB request
        smb_header = [
            b"\xFF\x53\x4D\x42",  # 'server_component': .SMB
            b"\x32",  # 'smb_command': Trans2
            b"\x00\x00\x00\x00",
            b"\x18",
            b"\x07\xc0",
            b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00",
            treeid,
            processid,
            userid,
            multiplex_id,
        ]

        # Define the trans2 request section of the SMB request
        trans2_request = [
            b"\x0f",
            b"\x0c\x00",
            b"\x00\x00",
            b"\x01\x00",
            b"\x00\x00",
            b"\x00",
            b"\x00",
            b"\x00\x00",
            b"\xa6\xd9\xa4\x00",  # Timeout: 3 hours, 3.622 seconds
            b"\x00\x00",
            b"\x0c\x00",
            b"\x42\x00",
            b"\x00\x00",
            b"\x4e\x00",
            b"\x01",
            b"\x00",
            b"\x0e\x00",  # subcommand: SESSION_SETUP
            b"\x00\x00",
            b"\x0c\x00" + b"\x00" * 12,
        ]

        return self.generate_smb_proto_payload(netbios, smb_header, trans2_request)


    def check(self, ip, port=445):
        """Check if MS17_010 SMB Vulnerability exists.

        Args:
        ----
            ip (str): The IP address of the target machine.
            port (int, optional): The port number to connect to. Defaults to 445.

        Returns:
        -------
            bool: True if the vulnerability exists, False otherwise.
        """
        buffersize = 1024
        timeout = 5.0

        # Send smb request based on socket.
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))

        # SMB - Negotiate Protocol Request
        raw_proto = self.negotiate_proto_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        # SMB - Session Setup AndX Request
        raw_proto = self.session_setup_andx_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        tcp_response[:4]
        smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
        smb = SmbHeader(smb_header)

        user_id = struct.pack("<H", smb.user_id)

        # parse native_os from Session Setup Andx Response
        session_setup_andx_response = tcp_response[36:]
        native_os = session_setup_andx_response[9:].split(b"\x00")[0]

        # SMB - Tree Connect AndX Request
        raw_proto = self.tree_connect_andx_request(ip, user_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        tcp_response[:4]
        smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
        smb = SmbHeader(smb_header)

        tree_id = struct.pack("<H", smb.tree_id)
        process_id = struct.pack("<H", smb.process_id)
        user_id = struct.pack("<H", smb.user_id)
        multiplex_id = struct.pack("<H", smb.multiplex_id)

        # SMB - PeekNamedPipe Request
        raw_proto = self.peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SmbHeader(smb_header)

        nt_status = struct.pack("BBH", smb.error_class, smb.reserved1, smb.error_code)
        self.logger.debug(f"NT Status: {nt_status}")

        # 0xC0000205 - STATUS_INSUFF_SERVER_RESOURCES - vulnerable
        # 0xC0000008 - STATUS_INVALID_HANDLE
        # 0xC0000022 - STATUS_ACCESS_DENIED

        if nt_status == b"\x05\x02\x00\xc0":
            self.logger.highlight(f"[+] {ip} is likely VULNERABLE to MS17-010! ({native_os.decode()})")

            # vulnerable to MS17-010, check for DoublePulsar infection
            raw_proto = self.trans2_request(tree_id, process_id, user_id, multiplex_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)

            tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SmbHeader(smb_header)

            if smb.multiplex_id == 0x0051:
                key = self.calculate_doublepulsar_xor_key(smb.signature)
                self.logger.highlight(f"Host is likely INFECTED with DoublePulsar! - XOR Key: {key.decode()}")
        elif nt_status in (b"\x08\x00\x00\xc0", b"\x22\x00\x00\xc0"):
            self.logger.fail(f"{ip} does NOT appear vulnerable")
        else:
            self.logger.fail(f"{ip} Unable to detect if this host is vulnerable")

        client.close()
