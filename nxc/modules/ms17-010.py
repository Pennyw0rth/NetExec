#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All credits to https://github.com/d4t4s3c/Win7Blue
# @d4t4s3c
# Module by @mpgn_x64

from ctypes import *
import socket
import struct


class NXCModule:
    name = "ms17-010"
    description = "MS17-010, /!\ not tested oustide home lab"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """ """

    def on_login(self, context, connection):
        if check(connection.host):
            context.log.highlight("VULNERABLE")
            context.log.highlight("Next step: https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/")


class SmbHeader(Structure):
    """SMB Header decoder."""

    _pack_ = 1

    _fields_ = [
        ("server_component", c_uint32),  # noqa: F405
        ("smb_command", c_uint8),  # noqa: F405
        ("error_class", c_uint8),  # noqa: F405
        ("reserved1", c_uint8),  # noqa: F405
        ("error_code", c_uint16),  # noqa: F405
        ("flags", c_uint8),  # noqa: F405
        ("flags2", c_uint16),  # noqa: F405
        ("process_id_high", c_uint16),  # noqa: F405
        ("signature", c_uint64),  # noqa: F405
        ("reserved2", c_uint16),  # noqa: F405
        ("tree_id", c_uint16),  # noqa: F405
        ("process_id", c_uint16),  # noqa: F405
        ("user_id", c_uint16),  # noqa: F405
        ("multiplex_id", c_uint16),  # noqa: F405
    ]

    def __new__(cls, buffer=None):
        return cls.from_buffer_copy(buffer)


def generate_smb_proto_payload(*protos):
    """
    Generates an SMB Protocol payload by concatenating a list of packet protos.

    Args:
        *protos (list): List of packet protos.

    Returns:
        str: The generated SMB Protocol payload.
    """
    # Initialize an empty list to store the hex data
    hex_data = []

    # Iterate over each proto in the input list
    for proto in protos:
        # Extend the hex_data list with the elements of the current proto
        hex_data.extend(proto)

    # Join the elements of the hex_data list into a single string and return it
    return "".join(hex_data)


def calculate_doublepulsar_xor_key(s):
    """
    Calculate Doublepulsar Xor Key.

    Args:
        s (int): The input value.

    Returns:
        int: The calculated xor key.
    """
    # Shift the value 16 bits to the left and combine it with the value shifted 8 bits to the left
    # OR the result with s shifted 16 bits to the right and combined with s masked with 0xFF0000
    temp = ((s & 0xFF00) | (s << 16)) << 8 | (((s >> 16) | s & 0xFF0000) >> 8)

    # Multiply the temp value by 2 and perform a bitwise XOR with 0xFFFFFFFF
    x = 2 * temp ^ 0xFFFFFFFF

    return x


def negotiate_proto_request():
    """Generate a negotiate_proto_request packet."""

    # Define the NetBIOS header
    netbios = [
        "\x00",  # Message Type
        "\x00\x00\x54"  # Length
    ]

    # Define the SMB header
    smb_header = [
        "\xFF\x53\x4D\x42",  # Server Component
        "\x72",  # SMB Command
        "\x00\x00\x00\x00",  # NT Status
        "\x18",  # Flags
        "\x01\x28",  # Flags2
        "\x00\x00",  # Process ID High
        "\x00\x00\x00\x00\x00\x00\x00\x00",  # Signature
        "\x00\x00",  # Reserved
        "\x00\x00",  # Tree ID
        "\x2F\x4B",  # Process ID
        "\x00\x00",  # User ID
        "\xC5\x5E"  # Multiplex ID
    ]

    # Define the negotiate_proto_request
    negotiate_proto_request = [
        "\x00",  # Word Count
        "\x31\x00",  # Byte Count
        "\x02",  # Requested Dialects Count
        "\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00",  # Requested Dialects
        "\x02",  # Requested Dialects Count
        "\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00",  # Requested Dialects
        "\x02",  # Requested Dialects Count
        "\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00",  # Requested Dialects
        "\x02",  # Requested Dialects Count
        "\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00"  # Requested Dialects
    ]

    # Return the generated SMB protocol payload
    return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
    """Generate session setup andx request."""
    # Define the NetBIOS bytes
    netbios = [
        "\x00",   # length
        "\x00\x00\x63"   # session service
    ]

    # Define the SMB header bytes
    smb_header = [
        "\xFF\x53\x4D\x42",   # server component
        "\x73",   # command
        "\x00\x00\x00\x00",   # NT status
        "\x18",   # flags
        "\x01\x20",   # flags2
        "\x00\x00",   # PID high
        "\x00\x00\x00\x00\x00\x00\x00\x00",   # signature
        "\x00\x00",   # reserved
        "\x00\x00",   # tid
        "\x2F\x4B",   # pid
        "\x00\x00",   # uid
        "\xC5\x5E"   # mid
    ]

    # Define the session setup andx request bytes
    session_setup_andx_request = [
        "\x0D",   # word count
        "\xFF",   # andx command
        "\x00",   # reserved
        "\x00\x00",   # andx offset
        "\xDF\xFF",   # max buffer
        "\x02\x00",   # max mpx count
        "\x01\x00",   # VC number
        "\x00\x00\x00\x00",   # session key
        "\x00\x00",   # ANSI password length
        "\x00\x00",   # Unicode password length
        "\x00\x00\x00\x00",   # reserved
        "\x40\x00\x00\x00",   # capabilities
        "\x26\x00",   # byte count
        "\x00",   # account name length
        "\x2e\x00",   # account name offset
        "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00",   # account name
        "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00"   # primary domain
    ]

    # Call the generate_smb_proto_payload function and return the result
    return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip: str, userid: str) -> str:
    """Generate tree connect andx request.

    Args:
        ip (str): The IP address.
        userid (str): The user ID.

    Returns:
        bytes: The generated tree connect andx request payload.
    """

    # Initialize the netbios header
    netbios = [b"\x00", b"\x00\x00\x47"]

    # Initialize the SMB header
    smb_header = [
        b"\xFF\x53\x4D\x42",
        b"\x75",
        b"\x00\x00\x00\x00",
        b"\x18",
        b"\x01\x20",
        b"\x00\x00",
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x00\x00",
        b"\x00\x00",
        b"\x2F\x4B",
        userid,
        b"\xC5\x5E",
    ]

    # Create the IPC string
    ipc = "\\\\{}\\IPC$\\x00".format(ip)

    # Initialize the tree connect andx request
    tree_connect_andx_request = [
        b"\x04",
        b"\xFF",
        b"\x00",
        b"\x00\x00",
        b"\x00\x00",
        b"\x01\x00",
        b"\x1A\x00",
        b"\x00",
        ipc.encode(),
        b"\x3f\x3f\x3f\x3f\x3f\x00",
    ]

    # Calculate the length of the payload
    length = len(b"".join(smb_header)) + len(b"".join(tree_connect_andx_request))

    # Update the length in the netbios header
    netbios[1] = struct.pack(">L", length)[-3:]

    # Generate the final SMB protocol payload
    return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
    """
    Generate tran2 request.

    Args:
        treeid (str): The tree ID.
        processid (str): The process ID.
        userid (str): The user ID.
        multiplex_id (str): The multiplex ID.

    Returns:
        str: The generated SMB protocol payload.
    """

    # Set the necessary values for the netbios header
    netbios = ["\x00", "\x00\x00\x4a"]

    # Set the values for the SMB header
    smb_header = [
        "\xFF\x53\x4D\x42",  # Server Component
        "\x25",  # SMB Command
        "\x00\x00\x00\x00",  # NT Status
        "\x18",  # Flags2
        "\x01\x28",  # Process ID High & Multiplex ID
        "\x00\x00",  # Tree ID
        "\x00\x00\x00\x00\x00\x00\x00\x00",  # NT Time
        "\x00\x00",  # Process ID Low
        treeid,  # Tree ID
        processid,  # Process ID
        userid,  # User ID
        multiplex_id,  # Multiplex ID
    ]

    # Set the values for the transaction request
    tran_request = [
        "\x10",  # Word Count
        "\x00\x00",  # Total Parameter Count
        "\x00\x00",  # Total Data Count
        "\xff\xff",  # Max Parameter Count
        "\xff\xff",  # Max Data Count
        "\x00",  # Max Setup Count
        "\x00",  # Reserved
        "\x00\x00",  # Flags
        "\x00\x00\x00\x00",  # Timeout
        "\x00\x00",  # Reserved
        "\x00\x00",  # Parameter Count
        "\x4a\x00",  # Parameter Offset
        "\x00\x00",  # Data Count
        "\x4a\x00",  # Data Offset
        "\x02",  # Setup Count
        "\x00",  # Reserved
        "\x23\x00",  # Function Code
        "\x00\x00",  # Reserved2
        "\x07\x00",  # Byte Count
        "\x5c\x50\x49\x50\x45\x5c\x00",  # Transaction Name
    ]

    # Generate the SMB protocol payload
    return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid: str, processid: str, userid: str, multiplex_id: str) -> str:
    """Generate trans2 request.

    Args:
        treeid: The treeid parameter.
        processid: The processid parameter.
        userid: The userid parameter.
        multiplex_id: The multiplex_id parameter.

    Returns:
        The generated SMB protocol payload.
    """

    # Define the netbios section of the SMB request
    netbios = ["\x00", "\x00\x00\x4f"]

    # Define the SMB header section of the SMB request
    smb_header = [
        "\xFF\x53\x4D\x42",
        "\x32",
        "\x00\x00\x00\x00",
        "\x18",
        "\x07\xc0",
        "\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00",
        treeid,
        processid,
        userid,
        multiplex_id,
    ]

    # Define the trans2 request section of the SMB request
    trans2_request = [
        "\x0f",
        "\x0c\x00",
        "\x00\x00",
        "\x01\x00",
        "\x00\x00",
        "\x00",
        "\x00",
        "\x00\x00",
        "\xa6\xd9\xa4\x00",
        "\x00\x00",
        "\x0c\x00",
        "\x42\x00",
        "\x00\x00",
        "\x4e\x00",
        "\x01",
        "\x00",
        "\x0e\x00",
        "\x00\x00",
        "\x0c\x00" + "\x00" * 12,
    ]

    # Generate the SMB protocol payload by combining the netbios, smb_header, and trans2_request sections
    return generate_smb_proto_payload(netbios, smb_header, trans2_request)


def check(ip, port=445):
    """Check if MS17_010 SMB Vulnerability exists.

    Args:
        ip (str): The IP address of the target machine.
        port (int, optional): The port number to connect to. Defaults to 445.

    Returns:
        bool: True if the vulnerability exists, False otherwise.
    """
    try:
        buffersize = 1024
        timeout = 5.0

        # Create a socket and connect to the target IP and port
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))

        # Send negotiate protocol request and receive response
        raw_proto = negotiate_proto_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        # Send session setup request and receive response
        raw_proto = session_setup_andx_request()
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)
        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SmbHeader(smb_header)

        user_id = struct.pack("<H", smb.user_id)

        # Extract native OS from session setup response
        session_setup_andx_response = tcp_response[36:]
        native_os = session_setup_andx_response[9:].split("\x00")[0]

        # Send tree connect request and receive response
        raw_proto = tree_connect_andx_request(ip, user_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SmbHeader(smb_header)

        tree_id = struct.pack("<H", smb.tree_id)
        process_id = struct.pack("<H", smb.process_id)
        user_id = struct.pack("<H", smb.user_id)
        multiplex_id = struct.pack("<H", smb.multiplex_id)

        # Send peek named pipe request and receive response
        raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SmbHeader(smb_header)

        nt_status = struct.pack("BBH", smb.error_class, smb.reserved1, smb.error_code)

        # Check the NT status to determine if the vulnerability exists
        if nt_status == "\x05\x02\x00\xc0":
            return True
        else:
            return False

    except Exception:
        return False
    finally:
        client.close()
