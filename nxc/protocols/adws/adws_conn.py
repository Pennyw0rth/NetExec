"""
Self-contained ADWS protocol library.

Implements the full protocol stack for Active Directory Web Services (TCP 9389):
  NMF  (.NET Message Framing)      [MC-NMF]
  NNS  (.NET NegotiateStream)      [MC-NNS]
  NBFSE (.NET Binary Format: SOAP) [MC-NBFSE]
  ADWS SOAP envelope construction  [MS-ADDM]

Based on research by Logan Goins (@_logangoins) / SpecterOps and the SOAPy project.
"""

import base64
import datetime
import logging
import re
import socket
import struct
import time
from base64 import b64decode
from enum import IntEnum, IntFlag
from html import unescape
from html.parser import HTMLParser
from io import BytesIO
from typing import Optional
from uuid import UUID, uuid4
from xml.etree import ElementTree
from xml.sax.saxutils import escape as xml_escape, quoteattr

import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from impacket.hresult_errors import ERROR_MESSAGES
from impacket.krb5 import constants as krb5_constants
from impacket.krb5.asn1 import AP_REP, AP_REQ, Authenticator, EncAPRepPart, TGS_REP, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import (
    GSSAPI, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG, KRB5_AP_REQ, CheckSumField,
)
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ldap.ldaptypes import LDAP_SID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

log = logging.getLogger(__name__)

ADWS_PORT = 9389
KRB5_AP_REP_TOKEN = b"\x02\x00"

_BARE_AMPERSAND_RE = re.compile(r"&(?!amp;|lt;|gt;|apos;|quot;|#[0-9]+;|#x[0-9a-fA-F]+;)")
_REQUEST_RETRIES = 3
_RETRY_BASE_DELAY = 1
_RENEW_INTERVAL = 300
_RENEW_DURATION = "PT30M"
_TRANSIENT_FAULTS = ("OperationTimeout", "ReservedConnectionInvalidated")


# --- datatypes ---

class MultiByteInt31:
    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        v = self.value
        if v < 0:
            raise ValueError("negative not supported")
        if v <= 0x7F:
            return bytes([v])
        result = []
        for _ in range(5):
            b = v & 0x7F
            v >>= 7
            if v:
                b |= 0x80
            result.append(b)
            if not v:
                break
        return bytes(result)

    @classmethod
    def parse(cls, fp):
        value = 0
        for i in range(5):
            b = struct.unpack("<B", fp.read(1))[0]
            value |= (b & 0x7F) << (7 * i)
            if not (b & 0x80):
                break
        return cls(value)

    @staticmethod
    def encode7bit(value):
        if value <= 0x7F:
            return bytes([value])
        result = []
        for _ in range(5):
            b = value & 0x7F
            value >>= 7
            if value:
                b |= 0x80
            result.append(b)
            if not value:
                break
        return bytes(result)

    @staticmethod
    def decode7bit(data):
        value = 0
        length = 0
        for i in range(min(len(data), 5)):
            length += 1
            b = data[i]
            value |= (b & 0x7F) << (7 * i)
            if not (b & 0x80):
                break
        return value, length


class Utf8String:
    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        data = self.value.encode("utf-8")
        return MultiByteInt31(len(data)).to_bytes() + data

    def __str__(self):
        return self.value

    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<B", fp.read(1))[0]
        return cls(fp.read(ln).decode("utf8", errors="ignore"))


class NBFSEDecimal:
    def __init__(self, sign, high, low, scale):
        self.sign = sign
        self.high = high
        self.low = low
        self.scale = scale

    def to_bytes(self):
        out = struct.pack("<H", 0)
        out += struct.pack("<B", self.scale)
        out += struct.pack("<B", 0x80 if self.sign else 0x00)
        out += struct.pack("<I", self.high)
        out += struct.pack("<Q", self.low)
        return out

    def __str__(self):
        value = str(self.high * 2**64 + self.low)
        if self.scale > 0:
            value = value[:-self.scale] + "." + value[-self.scale:]
        return ("-%s" % value) if self.sign else value

    @classmethod
    def parse(cls, fp):
        fp.read(2)
        scale = struct.unpack("<B", fp.read(1))[0]
        sign = struct.unpack("<B", fp.read(1))[0] & 0x80
        high = struct.unpack("<I", fp.read(4))[0]
        low = struct.unpack("<Q", fp.read(8))[0]
        return cls(sign, high, low, scale)


# --- NBFSE dictionary [MC-NBFX] 2.2.4 ---

NBFSE_DICT = {
    0x00: "mustUnderstand", 0x02: "Envelope",
    0x04: "http://www.w3.org/2003/05/soap-envelope",
    0x06: "http://www.w3.org/2005/08/addressing",
    0x08: "Header", 0x0A: "Action", 0x0C: "To", 0x0E: "Body",
    0x10: "Algorithm", 0x12: "RelatesTo",
    0x14: "http://www.w3.org/2005/08/addressing/anonymous",
    0x16: "URI", 0x18: "Reference", 0x1A: "MessageID", 0x1C: "Id",
    0x1E: "Identifier",
    0x20: "http://schemas.xmlsoap.org/ws/2005/02/rm",
    0x22: "Transforms", 0x24: "Transform", 0x26: "DigestMethod",
    0x28: "DigestValue", 0x2A: "Address", 0x2C: "ReplyTo",
    0x2E: "SequenceAcknowledgement", 0x30: "AcknowledgementRange",
    0x32: "Upper", 0x34: "Lower", 0x36: "BufferRemaining",
    0x38: "http://schemas.microsoft.com/ws/2006/05/rm",
    0x3A: "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement",
    0x3C: "SecurityTokenReference", 0x3E: "Sequence",
    0x40: "MessageNumber",
    0x42: "http://www.w3.org/2000/09/xmldsig#",
    0x44: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    0x46: "KeyInfo",
    0x48: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    0x4A: "http://www.w3.org/2001/04/xmlenc#",
    0x4C: "http://schemas.xmlsoap.org/ws/2005/02/sc",
    0x4E: "DerivedKeyToken", 0x50: "Nonce", 0x52: "Signature",
    0x54: "SignedInfo", 0x56: "CanonicalizationMethod",
    0x58: "SignatureMethod", 0x5A: "SignatureValue",
    0x5C: "DataReference", 0x5E: "EncryptedData",
    0x60: "EncryptionMethod", 0x62: "CipherData", 0x64: "CipherValue",
    0x66: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    0x68: "Security", 0x6A: "Timestamp", 0x6C: "Created",
    0x6E: "Expires", 0x70: "Length", 0x72: "ReferenceList",
    0x74: "ValueType", 0x76: "Type", 0x78: "EncryptedHeader",
    0x7A: "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd",
    0x7C: "RequestSecurityTokenResponseCollection",
    0x7E: "http://schemas.xmlsoap.org/ws/2005/02/trust",
    0x80: "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret",
    0x82: "http://schemas.microsoft.com/ws/2006/02/transactions",
    0x84: "s", 0x86: "Fault", 0x88: "MustUnderstand",
    0x8A: "role", 0x8C: "relay", 0x8E: "Code", 0x90: "Reason",
    0x92: "Text", 0x94: "Node", 0x96: "Role", 0x98: "Detail",
    0x9A: "Value", 0x9C: "Subcode", 0x9E: "NotUnderstood",
    0xA0: "qname", 0xA2: '"', 0xA4: "From", 0xA6: "FaultTo",
    0xA8: "EndpointReference", 0xAA: "PortType",
    0xAC: "ServiceName", 0xAE: "PortName",
    0xB0: "ReferenceProperties", 0xB2: "RelationshipType",
    0xB4: "Reply", 0xB6: "a",
    0xB8: "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity",
    0xBA: "Identity", 0xBC: "Spn", 0xBE: "Upn", 0xC0: "Rsa",
    0xC2: "Dns", 0xC4: "X509v3Certificate",
    0xC6: "http://www.w3.org/2005/08/addressing/fault",
    0xC8: "ReferenceParameters", 0xCA: "IsReferenceParameter",
    0xCC: "http://www.w3.org/2005/08/addressing/reply",
    0xCE: "http://www.w3.org/2005/08/addressing/none",
    0xD0: "Metadata",
    0xD2: "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    0xD4: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
    0xD6: "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault",
    0xD8: "http://schemas.xmlsoap.org/ws/2004/06/addressingex",
    0xDA: "RedirectTo", 0xDC: "Via",
    0xDE: "http://www.w3.org/2001/10/xml-exc-c14n#",
    0xE0: "PrefixList", 0xE2: "InclusiveNamespaces", 0xE4: "ec",
    0xE6: "SecurityContextToken", 0xE8: "Generation", 0xEA: "Label",
    0xEC: "Offset", 0xEE: "Properties", 0xF0: "Cookie", 0xF2: "wsc",
    0xF4: "http://schemas.xmlsoap.org/ws/2004/04/sc",
    0xF6: "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk",
    0xF8: "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct",
    0xFA: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT",
    0xFC: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT",
    0xFE: "RenewNeeded", 0x100: "BadContextToken", 0x102: "c",
    0x104: "http://schemas.xmlsoap.org/ws/2005/02/sc/dk",
    0x106: "http://schemas.xmlsoap.org/ws/2005/02/sc/sct",
    0x256: "xmlns", 0x258: "Resource",
    0x262: "u", 0x274: "e", 0x2B4: "r",
    0x372: "http://www.w3.org/2001/XMLSchema-instance",
    0x374: "http://www.w3.org/2001/XMLSchema",
    0x376: "nil", 0x378: "type", 0x37A: "char",
    0x37C: "boolean", 0x37E: "byte", 0x380: "unsignedByte",
    0x382: "short", 0x384: "unsignedShort", 0x386: "int",
    0x388: "unsignedInt", 0x38A: "long", 0x38C: "unsignedLong",
    0x38E: "float", 0x390: "double", 0x392: "decimal",
    0x394: "dateTime", 0x396: "string", 0x398: "base64Binary",
    0x39A: "anyType", 0x39C: "duration", 0x39E: "guid",
    0x3A0: "anyURI", 0x3A2: "QName",
}

# fill odd-indexed placeholders
for _i in range(0x01, 0xFFF, 2):
    if _i not in NBFSE_DICT:
        NBFSE_DICT[_i] = "[[VALUE_0x%02x]]" % _i
# fill remaining even gaps for completeness
for _i in range(0x00, 0x3D0, 2):
    if _i not in NBFSE_DICT:
        NBFSE_DICT[_i] = "[[VALUE_0x%02x]]" % _i

NBFSE_INVERTED = {v: k for k, v in NBFSE_DICT.items()}


# --- record base classes ---

class _Record:
    _registry = {}

    @classmethod
    def register(cls, *classes):
        for c in classes:
            cls._registry[c.type] = c

    def to_bytes(self):
        return struct.pack("<B", self.type)

    @classmethod
    def parse_stream(cls, fp):
        root = []
        records = root
        parents = []
        last_el = None
        while True:
            tb = fp.read(1)
            if not tb:
                return root
            t = struct.unpack("<B", tb)[0]
            if t in cls._registry:
                obj = cls._registry[t].parse(fp)
                if isinstance(obj, _EndElement):
                    if parents:
                        records = parents.pop()
                elif isinstance(obj, _Element):
                    last_el = obj
                    records.append(obj)
                    parents.append(records)
                    obj.childs = []
                    records = obj.childs
                elif isinstance(obj, _Attribute) and last_el:
                    last_el.attributes.append(obj)
                else:
                    records.append(obj)
            elif t - 1 in cls._registry:
                records.append(cls._registry[t - 1].parse(fp))
                last_el = None
                if parents:
                    records = parents.pop()
        return root


class _Element(_Record):
    pass

class _EndElement(_Element):
    type = 0x01
    @classmethod
    def parse(cls, fp):
        return cls()

class _Attribute(_Record):
    pass

class _Text(_Record):
    pass


# --- text records ---

class ZeroText(_Text):
    type = 0x80
    def __str__(self): return "0"
    @classmethod
    def parse(cls, fp): return cls()

class OneText(_Text):
    type = 0x82
    def __str__(self): return "1"
    @classmethod
    def parse(cls, fp): return cls()

class FalseText(_Text):
    type = 0x84
    def __str__(self): return "false"
    @classmethod
    def parse(cls, fp): return cls()

class TrueText(_Text):
    type = 0x86
    def __str__(self): return "true"
    @classmethod
    def parse(cls, fp): return cls()

class Int8Text(_Text):
    type = 0x88
    def __init__(self, v=0): self.value = v
    def to_bytes(self): return super().to_bytes() + struct.pack("<b", self.value)
    def __str__(self): return str(self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<b", fp.read(1))[0])

class Int16Text(Int8Text):
    type = 0x8A
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<h", self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<h", fp.read(2))[0])

class Int32Text(Int8Text):
    type = 0x8C
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<i", self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<i", fp.read(4))[0])

class Int64Text(Int8Text):
    type = 0x8E
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<q", self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<q", fp.read(8))[0])

class UInt64Text(Int8Text):
    type = 0xB2
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<Q", self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<Q", fp.read(8))[0])

class BoolText(_Text):
    type = 0xB4
    def __init__(self, v=False): self.value = v
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<B", 1 if self.value else 0)
    def __str__(self): return str(self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<B", fp.read(1))[0] == 1)

class FloatText(_Text):
    type = 0x90
    def __init__(self, v=0.0): self.value = v
    def to_bytes(self): return super().to_bytes() + struct.pack("<f", self.value)
    def __str__(self):
        try:
            return ("%.0f" % self.value) if self.value == int(self.value) else str(self.value)
        except:
            return str(self.value).upper()
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<f", fp.read(4))[0])

class DoubleText(FloatText):
    type = 0x92
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<d", self.value)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<d", fp.read(8))[0])

class DecimalText(_Text):
    type = 0x94
    def __init__(self, v=None): self.value = v
    def __str__(self): return str(self.value)
    def to_bytes(self): return super().to_bytes() + self.value.to_bytes()
    @classmethod
    def parse(cls, fp): return cls(NBFSEDecimal.parse(fp))

class DatetimeText(_Text):
    type = 0x96
    def __init__(self, v=0, tz=0): self.value = v; self.tz = tz
    def __str__(self):
        dt = datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=self.value / 10)
        return dt.isoformat()
    def to_bytes(self):
        return super().to_bytes() + struct.pack("<Q", (self.tz & 3) | (self.value & 0x1FFFFFFFFFFFFFFF) << 2)
    @classmethod
    def parse(cls, fp):
        data = struct.unpack("<Q", fp.read(8))[0]
        return cls(data, data & 3)

class Chars8Text(_Text):
    type = 0x98
    def __init__(self, v=""): self.value = v
    def __str__(self): return self.value
    def to_bytes(self):
        data = self.value.encode("utf-8")
        return struct.pack("<B", self.type) + struct.pack("<B", len(data)) + data
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<B", fp.read(1))[0]
        return cls(fp.read(ln).decode("utf-8"))

class Chars16Text(_Text):
    type = 0x9A
    def __init__(self, v=""): self.value = v
    def __str__(self): return self.value
    def to_bytes(self):
        data = self.value.encode("utf-8")
        return struct.pack("<B", self.type) + struct.pack("<H", len(data)) + data
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<H", fp.read(2))[0]
        return cls(fp.read(ln).decode("utf-8"))

class Chars32Text(_Text):
    type = 0x9C
    def __init__(self, v=""): self.value = v
    def __str__(self): return self.value
    def to_bytes(self):
        data = self.value.encode("utf-8")
        return struct.pack("<B", self.type) + struct.pack("<I", len(data)) + data
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<I", fp.read(4))[0]
        return cls(fp.read(ln).decode("utf-8"))

class Bytes8Text(_Text):
    type = 0x9E
    def __init__(self, v=b""): self.value = v
    def __str__(self): return base64.b64encode(self.value).decode()
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<B", len(self.value)) + self.value
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<B", fp.read(1))[0]
        return cls(fp.read(ln))

class Bytes16Text(_Text):
    type = 0xA0
    def __init__(self, v=b""): self.value = v
    def __str__(self): return base64.b64encode(self.value).decode()
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<H", len(self.value)) + self.value
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<H", fp.read(2))[0]
        return cls(fp.read(ln))

class Bytes32Text(_Text):
    type = 0xA2
    def __init__(self, v=b""): self.value = v
    def __str__(self): return base64.b64encode(self.value).decode()
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<I", len(self.value)) + self.value
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<I", fp.read(4))[0]
        return cls(fp.read(ln))

class EmptyText(_Text):
    type = 0xA8
    def __str__(self): return ""
    @classmethod
    def parse(cls, fp): return cls()

class DictText(_Text):
    type = 0xAA
    def __init__(self, idx=0): self.index = idx
    def to_bytes(self): return super().to_bytes() + MultiByteInt31(self.index).to_bytes()
    def __str__(self): return NBFSE_DICT.get(self.index, "")
    @classmethod
    def parse(cls, fp): return cls(MultiByteInt31.parse(fp).value)

class UniqueIdText(_Text):
    type = 0xAC
    def __init__(self, uuid_val=None):
        if isinstance(uuid_val, (list, tuple)):
            self.uuid = uuid_val
        elif uuid_val:
            u = uuid_val.replace("urn:uuid:", "").split("-")
            tmp = u[0:3] + [u[3][0:2], u[3][2:], u[4][0:2], u[4][2:4], u[4][4:6], u[4][6:8], u[4][8:10], u[4][10:]]
            self.uuid = [int(s, 16) for s in tmp]
        else:
            self.uuid = [0]*11
    def to_bytes(self): return super().to_bytes() + struct.pack("<IHHBBBBBBBB", *self.uuid)
    def __str__(self): return "urn:uuid:%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % tuple(self.uuid)
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<IHHBBBBBBBB", fp.read(16)))

class UuidText(UniqueIdText):
    type = 0xB0
    def __str__(self): return "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % tuple(self.uuid)

class TimeSpanText(_Text):
    type = 0xAE
    def __init__(self, v=0): self.value = v
    def to_bytes(self): return super().to_bytes() + struct.pack("<q", self.value)
    def __str__(self): return str(datetime.timedelta(microseconds=self.value / 10))
    @classmethod
    def parse(cls, fp): return cls(struct.unpack("<q", fp.read(8))[0])

class QNameDictText(_Text):
    type = 0xBC
    def __init__(self, prefix="a", idx=0): self.prefix = prefix; self.index = idx
    def to_bytes(self): return struct.pack("<B", self.type) + struct.pack("<B", ord(self.prefix) - ord("a")) + MultiByteInt31(self.index).to_bytes()
    def __str__(self): return "%s:%s" % (self.prefix, NBFSE_DICT.get(self.index, ""))
    @classmethod
    def parse(cls, fp):
        p = chr(struct.unpack("<B", fp.read(1))[0] + ord("a"))
        return cls(p, MultiByteInt31.parse(fp).value)

class UnicodeChars8Text(_Text):
    type = 0xB6
    def __init__(self, v=""): self.value = v
    def to_bytes(self):
        data = self.value.encode("utf-16")[2:]
        return struct.pack("<B", self.type) + struct.pack("<B", len(data)) + data
    def __str__(self): return self.value
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<B", fp.read(1))[0]
        return cls(fp.read(ln).decode("utf-16"))

class UnicodeChars16Text(UnicodeChars8Text):
    type = 0xB8
    def to_bytes(self):
        data = self.value.encode("utf-16")[2:]
        return struct.pack("<B", self.type) + struct.pack("<H", len(data)) + data
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<H", fp.read(2))[0]
        return cls(fp.read(ln).decode("utf-16"))

class UnicodeChars32Text(UnicodeChars8Text):
    type = 0xBA
    def to_bytes(self):
        data = self.value.encode("utf-16")[2:]
        return struct.pack("<B", self.type) + struct.pack("<I", len(data)) + data
    @classmethod
    def parse(cls, fp):
        ln = struct.unpack("<I", fp.read(4))[0]
        return cls(fp.read(ln).decode("utf-16"))

class StartListText(_Text):
    type = 0xA4
    @classmethod
    def parse(cls, fp): return cls()

class EndListText(_Text):
    type = 0xA6
    @classmethod
    def parse(cls, fp): return cls()


# --- element records ---

class ShortElement(_Element):
    type = 0x40
    def __init__(self, name=""):
        self.childs = []; self.name = name; self.attributes = []
    def to_bytes(self):
        out = super().to_bytes() + Utf8String(self.name).to_bytes()
        for a in self.attributes: out += a.to_bytes()
        return out
    def __str__(self):
        a = " ".join(str(x) for x in self.attributes)
        return "<%s%s>" % (self.name, (" " + a) if a else "")
    @classmethod
    def parse(cls, fp): return cls(Utf8String.parse(fp).value)

class ElementRec(ShortElement):
    type = 0x41
    def __init__(self, prefix="", name=""):
        super().__init__(name); self.prefix = prefix
    def to_bytes(self):
        data = super().to_bytes()
        return data[0:1] + Utf8String(self.prefix).to_bytes() + data[1:]
    def __str__(self):
        a = " ".join(str(x) for x in self.attributes)
        return "<%s:%s%s>" % (self.prefix, self.name, (" " + a) if a else "")
    @classmethod
    def parse(cls, fp):
        return cls(Utf8String.parse(fp).value, Utf8String.parse(fp).value)

class ShortDictElement(_Element):
    type = 0x42
    def __init__(self, idx=0):
        self.childs = []; self.index = idx; self.attributes = []
        self.name = NBFSE_DICT.get(idx, "")
    def to_bytes(self):
        out = super().to_bytes() + MultiByteInt31(self.index).to_bytes()
        for a in self.attributes: out += a.to_bytes()
        return out
    def __str__(self):
        a = " ".join(str(x) for x in self.attributes)
        return "<%s%s>" % (self.name, (" " + a) if a else "")
    @classmethod
    def parse(cls, fp): return cls(MultiByteInt31.parse(fp).value)

class DictElement(_Element):
    type = 0x43
    def __init__(self, prefix="", idx=0):
        self.childs = []; self.prefix = prefix; self.index = idx; self.attributes = []
        self.name = NBFSE_DICT.get(idx, "")
    def to_bytes(self):
        out = super().to_bytes() + Utf8String(self.prefix).to_bytes() + MultiByteInt31(self.index).to_bytes()
        for a in self.attributes: out += a.to_bytes()
        return out
    def __str__(self):
        a = " ".join(str(x) for x in self.attributes)
        return "<%s:%s%s>" % (self.prefix, self.name, (" " + a) if a else "")
    @classmethod
    def parse(cls, fp):
        return cls(Utf8String.parse(fp).value, MultiByteInt31.parse(fp).value)

class _PrefixElement(ElementRec):
    def __init__(self, name=""):
        super().__init__(self.char, name)
    def to_bytes(self):
        out = struct.pack("<B", self.type) + Utf8String(self.name).to_bytes()
        for a in self.attributes: out += a.to_bytes()
        return out
    @classmethod
    def parse(cls, fp): return cls(Utf8String.parse(fp).value)

class _PrefixDictElement(DictElement):
    def __init__(self, idx=0):
        super().__init__(self.char, idx)
    def to_bytes(self):
        out = struct.pack("<B", self.type) + MultiByteInt31(self.index).to_bytes()
        for a in self.attributes: out += a.to_bytes()
        return out
    @classmethod
    def parse(cls, fp): return cls(MultiByteInt31.parse(fp).value)


# --- attribute records ---

class ShortAttr(_Attribute):
    type = 0x04
    def __init__(self, name="", value=None): self.name = name; self.value = value
    def to_bytes(self): return super().to_bytes() + Utf8String(self.name).to_bytes() + self.value.to_bytes()
    def __str__(self): return "%s=%s" % (self.name, quoteattr(str(self.value)))
    @classmethod
    def parse(cls, fp):
        name = Utf8String.parse(fp).value
        t = struct.unpack("<B", fp.read(1))[0]
        return cls(name, _Record._registry[t].parse(fp))

class AttrRec(_Attribute):
    type = 0x05
    def __init__(self, prefix="", name="", value=None): self.prefix = prefix; self.name = name; self.value = value
    def to_bytes(self): return super().to_bytes() + Utf8String(self.prefix).to_bytes() + Utf8String(self.name).to_bytes() + self.value.to_bytes()
    def __str__(self): return "%s:%s=%s" % (self.prefix, self.name, quoteattr(str(self.value)))
    @classmethod
    def parse(cls, fp):
        p = Utf8String.parse(fp).value; n = Utf8String.parse(fp).value
        t = struct.unpack("<B", fp.read(1))[0]
        return cls(p, n, _Record._registry[t].parse(fp))

class ShortDictAttr(_Attribute):
    type = 0x06
    def __init__(self, idx=0, value=None): self.index = idx; self.value = value
    def to_bytes(self): return super().to_bytes() + MultiByteInt31(self.index).to_bytes() + self.value.to_bytes()
    def __str__(self): return "%s=%s" % (NBFSE_DICT.get(self.index, ""), quoteattr(str(self.value)))
    @classmethod
    def parse(cls, fp):
        idx = MultiByteInt31.parse(fp).value
        t = struct.unpack("<B", fp.read(1))[0]
        return cls(idx, _Record._registry[t].parse(fp))

class DictAttr(_Attribute):
    type = 0x07
    def __init__(self, prefix="", idx=0, value=None): self.prefix = prefix; self.index = idx; self.value = value
    def to_bytes(self): return super().to_bytes() + Utf8String(self.prefix).to_bytes() + MultiByteInt31(self.index).to_bytes() + self.value.to_bytes()
    def __str__(self): return "%s:%s=%s" % (self.prefix, NBFSE_DICT.get(self.index, ""), quoteattr(str(self.value)))
    @classmethod
    def parse(cls, fp):
        p = Utf8String.parse(fp).value; idx = MultiByteInt31.parse(fp).value
        t = struct.unpack("<B", fp.read(1))[0]
        return cls(p, idx, _Record._registry[t].parse(fp))

class ShortXmlns(_Attribute):
    type = 0x08
    def __init__(self, value=""): self.value = value
    def to_bytes(self): return struct.pack("<B", self.type) + Utf8String(self.value).to_bytes()
    def __str__(self): return "xmlns=%s" % quoteattr(self.value)
    @classmethod
    def parse(cls, fp): return cls(Utf8String.parse(fp).value)

class XmlnsAttr(_Attribute):
    type = 0x09
    def __init__(self, name="", value=""): self.name = name; self.value = value
    def to_bytes(self): return struct.pack("<B", self.type) + Utf8String(self.name).to_bytes() + Utf8String(self.value).to_bytes()
    def __str__(self): return "xmlns:%s=%s" % (self.name, quoteattr(self.value))
    @classmethod
    def parse(cls, fp): return cls(Utf8String.parse(fp).value, Utf8String.parse(fp).value)

class ShortDictXmlns(_Attribute):
    type = 0x0A
    def __init__(self, idx=0): self.index = idx
    def __str__(self): return "xmlns=%s" % quoteattr(NBFSE_DICT.get(self.index, ""))
    def to_bytes(self): return struct.pack("<B", self.type) + MultiByteInt31(self.index).to_bytes()
    @classmethod
    def parse(cls, fp): return cls(MultiByteInt31.parse(fp).value)

class DictXmlns(_Attribute):
    type = 0x0B
    def __init__(self, prefix="", idx=0): self.prefix = prefix; self.index = idx
    def __str__(self): return "xmlns:%s=%s" % (self.prefix, quoteattr(NBFSE_DICT.get(self.index, "")))
    def to_bytes(self): return struct.pack("<B", self.type) + Utf8String(self.prefix).to_bytes() + MultiByteInt31(self.index).to_bytes()
    @classmethod
    def parse(cls, fp): return cls(Utf8String.parse(fp).value, MultiByteInt31.parse(fp).value)

class _PrefixAttr(AttrRec):
    def __init__(self, name="", value=None): super().__init__(self.char, name, value)
    def to_bytes(self): return struct.pack("<B", self.type) + Utf8String(self.name).to_bytes() + self.value.to_bytes()
    @classmethod
    def parse(cls, fp):
        n = Utf8String.parse(fp).value
        t = struct.unpack("<B", fp.read(1))[0]
        return cls(n, _Record._registry[t].parse(fp))

class _PrefixDictAttr(DictAttr):
    def __init__(self, idx=0, value=None): super().__init__(self.char, idx, value)
    def to_bytes(self): return struct.pack("<B", self.type) + MultiByteInt31(self.index).to_bytes() + self.value.to_bytes()
    @classmethod
    def parse(cls, fp):
        idx = MultiByteInt31.parse(fp).value
        t = struct.unpack("<B", fp.read(1))[0]
        return cls(idx, _Record._registry[t].parse(fp))


# --- register all records ---

_Record.register(
    _EndElement,
    ShortElement, ElementRec, ShortDictElement, DictElement,
    ShortAttr, AttrRec, ShortDictAttr, DictAttr,
    ShortXmlns, XmlnsAttr, ShortDictXmlns, DictXmlns,
    ZeroText, OneText, FalseText, TrueText,
    Int8Text, Int16Text, Int32Text, Int64Text, UInt64Text, BoolText,
    FloatText, DoubleText, DecimalText, DatetimeText,
    Chars8Text, Chars16Text, Chars32Text,
    Bytes8Text, Bytes16Text, Bytes32Text,
    EmptyText, DictText, UniqueIdText, UuidText, TimeSpanText, QNameDictText,
    UnicodeChars8Text, UnicodeChars16Text, UnicodeChars32Text,
    StartListText, EndListText,
)

# dynamically generate prefix element/attribute classes for a-z
for _c in range(0x44, 0x5E):
    _ch = chr(_c - 0x44 + ord("a"))
    _Record.register(type("PDE_%s" % _ch, (_PrefixDictElement,), {"type": _c, "char": _ch}))
for _c in range(0x5E, 0x78):
    _ch = chr(_c - 0x5E + ord("a"))
    _Record.register(type("PE_%s" % _ch, (_PrefixElement,), {"type": _c, "char": _ch}))
for _c in range(0x0C, 0x26):
    _ch = chr(_c - 0x0C + ord("a"))
    _Record.register(type("PDA_%s" % _ch, (_PrefixDictAttr,), {"type": _c, "char": _ch}))
for _c in range(0x26, 0x40):
    _ch = chr(_c - 0x26 + ord("a"))
    _Record.register(type("PA_%s" % _ch, (_PrefixAttr,), {"type": _c, "char": _ch}))


# --- serialization helpers ---

def _escape_xml_text(value):
    return xml_escape(value, {'"': "&quot;"})

def _dump_records(records):
    out = b""
    for r in records:
        msg_type = getattr(r, "type", None)
        if isinstance(r, _Text) and r == records[-1]:
            r.type = r.type + 1  # WithEndElement variant
        out += r.to_bytes()
        if hasattr(r, "childs"):
            out += _dump_records(r.childs)
            if (not r.childs or not isinstance(r.childs[-1], _Text)) and not isinstance(r, _Text):
                out += _EndElement().to_bytes()
        elif isinstance(r, _Element) and not isinstance(r, _EndElement):
            out += _EndElement().to_bytes()
        if msg_type is not None and isinstance(r, _Text):
            r.type = msg_type  # restore
    return out

def _print_records(records):
    if not records:
        return ""
    output = ""
    for r in records:
        if isinstance(r, _EndElement):
            continue
        output += _escape_xml_text(str(r)) if isinstance(r, _Text) else str(r)
        if hasattr(r, "childs"):
            output += _print_records(r.childs)
        if isinstance(r, _Element) and not isinstance(r, _EndElement):
            if hasattr(r, "prefix"):
                output += "</%s:%s>" % (r.prefix, r.name)
            else:
                output += "</%s>" % r.name
    return output


# --- XML parser (XML string -> NBFSE record tree) ---

_tagfind = re.compile(r"([a-zA-Z][^\t\n\r\f />\x00]*)(?:\s|/(?!>))*")
_attrfind = re.compile(r'((?<=[\'"\s/])[^\s/>][^\s/=>]*)(\s*=+\s*(\'[^\']*\'|"[^"]*"|(?![\'"])[^>\s]*))?(?:\s|/(?!>))*')
_endtagfind = re.compile(r"</\s*([a-zA-Z][-.a-zA-Z0-9:_]*)\s*>")
_int_re = re.compile(r"^-?\d+$")
_uuid_re = re.compile(r"^(([a-fA-F0-9]{8})-(([a-fA-F0-9]{4})-){3}([a-fA-F0-9]{12}))$")
_uniqueid_re = re.compile(r"^urn:uuid:(([a-fA-F0-9]{8})-(([a-fA-F0-9]{4})-){3}([a-fA-F0-9]{12}))$")
_b64_re = re.compile(r"^[a-zA-Z0-9/+]*={0,2}$")
_float_re = re.compile(r"^-?(INF)|(NaN)|(\d+(\.\d+)?)$")

_all_classes = {c.__name__: c for c in _Record._registry.values()}

class _XMLParser(HTMLParser):
    def reset(self):
        HTMLParser.reset(self)
        self.records = []
        self._stack = [self.records]
        self._current = type("R", (), {"childs": self.records})()
        self._data = None

    def parse_starttag(self, i):
        endpos = self.check_for_whole_start_tag(i)
        if endpos < 0:
            return endpos
        rawdata = self.rawdata
        attrs = []
        match = _tagfind.match(rawdata, i + 1)
        assert match
        k = match.end()
        tag = match.group(1)
        self.lasttag = tag
        while k < endpos:
            m = _attrfind.match(rawdata, k)
            if not m:
                break
            an, rest, av = m.group(1, 2, 3)
            if not rest:
                av = None
            elif (av[:1] == "'" == av[-1:]) or (av[:1] == '"' == av[-1:]):
                av = av[1:-1]
            if av:
                av = unescape(av)
            attrs.append((an, av))
            k = m.end()
        end = rawdata[k:endpos].strip()
        if end not in (">", "/>"):
            self.handle_data(rawdata[i:endpos])
            return endpos
        if end.endswith("/>"):
            self.handle_startendtag(tag, attrs)
        else:
            self.handle_starttag(tag, attrs)
            if tag in self.CDATA_CONTENT_ELEMENTS:
                self.set_cdata_mode(tag)
        return endpos

    def parse_endtag(self, i):
        rawdata = self.rawdata
        match = _endtagfind.match(rawdata, i)
        if not match:
            gtpos = rawdata.find(">", i + 1)
            if gtpos < 0:
                return -1
            self.handle_endtag(rawdata[i+2:gtpos].strip())
            return gtpos + 1
        self.handle_endtag(match.group(1))
        self.clear_cdata_mode()
        return match.end()

    def _parse_tag(self, tag):
        if ":" in tag:
            prefix, name = tag.split(":", 1)
            if len(prefix) == 1:
                if name in NBFSE_INVERTED:
                    cls_name = "PDE_%s" % prefix
                    for c in _Record._registry.values():
                        if c.__name__ == cls_name:
                            return c(NBFSE_INVERTED[name])
                cls_name = "PE_%s" % prefix
                for c in _Record._registry.values():
                    if c.__name__ == cls_name:
                        return c(name)
                return ElementRec(prefix, name)
            else:
                if name in NBFSE_INVERTED:
                    return DictElement(prefix, NBFSE_INVERTED[name])
                return ElementRec(prefix, name)
        else:
            if tag in NBFSE_INVERTED:
                return ShortDictElement(NBFSE_INVERTED[tag])
            return ShortElement(tag)

    def _parse_data(self, data):
        data = data.strip() if data else data
        if data == "0": return ZeroText()
        if data == "1": return OneText()
        if data.lower() == "false": return FalseText()
        if data.lower() == "true": return TrueText()
        if len(data) > 3 and data[1] == ":" and data[2:] in NBFSE_INVERTED:
            return QNameDictText(data[0], NBFSE_INVERTED[data[2:]])
        m = _uniqueid_re.match(data)
        if m: return UniqueIdText(m.group(1))
        m = _uuid_re.match(data)
        if m: return UuidText(m.group(1))
        if _int_re.match(data):
            val = int(data)
            if -(2**7) <= val <= 2**7 - 1: return Int8Text(val)
            if -(2**15) <= val <= 2**15 - 1: return Int16Text(val)
            if -(2**31) <= val <= 2**31 - 1: return Int32Text(val)
            if -(2**63) <= val <= 2**63 - 1: return Int64Text(val)
            ln = len(data)
            if ln < 256: return Chars8Text(data)
            if ln < 65536: return Chars16Text(data)
            return Chars32Text(data)
        if data == "": return EmptyText()
        b64 = False
        try:
            if _b64_re.match(data):
                base64.b64decode(data)
                b64 = True
        except: pass
        if b64:
            raw = base64.b64decode(data)
            ln = len(raw)
            if ln < 256: return Bytes8Text(raw)
            if ln < 65536: return Bytes16Text(raw)
            return Bytes32Text(raw)
        if _float_re.match(data):
            return DoubleText(float(data))
        if data in NBFSE_INVERTED:
            return DictText(NBFSE_INVERTED[data])
        ln = len(data)
        if ln < 256: return Chars8Text(data)
        if ln < 65536: return Chars16Text(data)
        return Chars32Text(data)

    def _parse_attr(self, name, value):
        if ":" in name:
            prefix, aname = name.split(":", 1)
            if prefix == "xmlns":
                if value in NBFSE_INVERTED:
                    return DictXmlns(aname, NBFSE_INVERTED[value])
                return XmlnsAttr(aname, value)
            elif len(prefix) == 1:
                val = self._parse_data(value)
                if aname in NBFSE_INVERTED:
                    cls_name = "PDA_%s" % prefix
                    for c in _Record._registry.values():
                        if c.__name__ == cls_name:
                            return c(NBFSE_INVERTED[aname], val)
                cls_name = "PA_%s" % prefix
                for c in _Record._registry.values():
                    if c.__name__ == cls_name:
                        return c(aname, val)
                return AttrRec(prefix, aname, val)
            else:
                val = self._parse_data(value)
                if aname in NBFSE_INVERTED:
                    return DictAttr(prefix, NBFSE_INVERTED[aname], val)
                return AttrRec(prefix, aname, val)
        elif name == "xmlns":
            if value in NBFSE_INVERTED:
                return ShortDictXmlns(NBFSE_INVERTED[value])
            return ShortXmlns(value)
        else:
            val = self._parse_data(value)
            if name in NBFSE_INVERTED:
                return ShortDictAttr(NBFSE_INVERTED[name], val)
            return ShortAttr(name, val)

    def handle_starttag(self, tag, attrs):
        if self._data:
            self._current.childs.append(self._parse_data(self._data))
            self._data = None
        el = self._parse_tag(tag)
        for n, v in attrs:
            el.attributes.append(self._parse_attr(n, v))
        self._current.childs.append(el)
        el.parent = self._current
        self._current = el

    def handle_startendtag(self, tag, attrs):
        if self._data:
            self._current.childs.append(self._parse_data(self._data))
            self._data = None
        el = self._parse_tag(tag)
        for n, v in attrs:
            el.attributes.append(self._parse_attr(n, v))
        self._current.childs.append(el)

    def handle_endtag(self, tag):
        if self._data:
            self._current.childs.append(self._parse_data(self._data))
            self._data = None
        self._current = self._current.parent

    def handle_data(self, data):
        self._data = (self._data or "") + data

    def handle_charref(self, name):
        self.handle_data(chr(int(name[1:], 16) if name[0] == "x" else int(name, 10)))

    def handle_entityref(self, name):
        self.handle_data(unescape("&%s;" % name))


def _xml_to_records(xml_str):
    p = _XMLParser()
    p.feed(xml_str)
    return p.records


# --- NBFSE Encoder ---

class NBFSEEncoder:
    def encode(self, xml):
        records = _xml_to_records(xml)
        payload = _dump_records(records)
        return MultiByteInt31.encode7bit(0) + payload  # empty inband dict

    def decode(self, data):
        size, ll = MultiByteInt31.decode7bit(data)
        data = data[ll + size:]
        records = _Record.parse_stream(BytesIO(data))
        return _print_records(records)


class _NNSHandshake(impacket.structure.Structure):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

class _NNSData(impacket.structure.Structure):
    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )

_NNS_IN_PROGRESS = 0x16
_NNS_ERROR = 0x15
_NNS_DONE = 0x14


def _decode_der_length(data, offset=0):
    first = data[offset]; offset += 1
    if first < 0x80:
        return first, offset
    ll = first & 0x7F
    return int.from_bytes(data[offset:offset + ll], "big"), offset + ll

def _unwrap_gss_mech(data):
    if not data.startswith(b"\x60"):
        raise ValueError("not a GSS mechanism token")
    tl, off = _decode_der_length(data, 1)
    tok = data[off:off + tl]
    if not tok.startswith(b"\x06"):
        raise ValueError("missing OID")
    ol, ov = _decode_der_length(tok, 1)
    return tok[ov + ol:]


class NNS:
    def __init__(self, sock, fqdn, domain, username,
                 password=None, nt="", lm="", auth_protocol="ntlm", kdc_host=None):
        self._sock = sock
        self._nt = bytes.fromhex(nt.zfill(32)) if nt else ""
        self._lm = bytes.fromhex(lm.zfill(32)) if lm else ""
        self._username = username
        self._password = password
        self._domain = domain
        self._fqdn = fqdn
        self._auth_protocol = auth_protocol
        self._kdc_host = kdc_host
        self._session_key = b""
        self._flags = -1
        self._sequence = 0
        self._server_sequence = 0
        self._gss = None

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("NNS: connection closed")
            buf += chunk
        return buf

    def _recv_handshake(self):
        hs = _NNSHandshake()
        hs["message_id"] = int.from_bytes(self._recv_exact(1), "big")
        hs["major_version"] = int.from_bytes(self._recv_exact(1), "big")
        hs["minor_version"] = int.from_bytes(self._recv_exact(1), "big")
        hs["payload"] = self._recv_exact(int.from_bytes(self._recv_exact(2), "big"))
        return hs

    def _check_error(self, auth_name, msg):
        if msg["message_id"] != _NNS_ERROR:
            return
        code = int.from_bytes(msg["payload"], "big")
        et, em = ERROR_MESSAGES.get(code, ("0x%08x" % code, "Unknown"))
        raise SystemExit("[-] %s Auth Failed: %s %s" % (auth_name, et, em))

    def auth(self):
        if self._auth_protocol == "kerberos":
            self._auth_krb()
        else:
            self._auth_ntlm()

    def _auth_ntlm(self):
        nego = impacket.ntlm.getNTLMSSPType1("", "", signingRequired=True, use_ntlmv2=True)
        token_init = impacket.spnego.SPNEGO_NegTokenInit()
        token_init["MechTypes"] = [
            impacket.spnego.TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech["NEGOEX - SPNEGO Extended Negotiation Security Mechanism"],
        ]
        token_init["MechToken"] = nego.getData()
        hs = _NNSHandshake()
        hs["message_id"] = _NNS_IN_PROGRESS
        hs["major_version"] = 1; hs["minor_version"] = 0
        hs["payload"] = token_init.getData()
        self._sock.sendall(hs.getData())

        challenge_msg = self._recv_handshake()
        self._check_error("NTLM", challenge_msg)
        targ = impacket.spnego.SPNEGO_NegTokenResp(challenge_msg["payload"])
        challenge = impacket.ntlm.NTLMAuthChallenge(targ["ResponseToken"])

        auth_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=nego, type2=challenge.getData(),
            user=self._username, password=self._password,
            domain=self._domain, lmhash=self._lm, nthash=self._nt,
        )
        self._flags = auth_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self._client_signing_key = impacket.ntlm.SIGNKEY(self._flags, self._session_key)
            self._server_signing_key = impacket.ntlm.SIGNKEY(self._flags, self._session_key, "Server")
            self._client_sealing_key = impacket.ntlm.SEALKEY(self._flags, self._session_key)
            self._server_sealing_key = impacket.ntlm.SEALKEY(self._flags, self._session_key, "Server")
            self._client_sealing_handle = ARC4.new(self._client_sealing_key).encrypt
            self._server_sealing_handle = ARC4.new(self._server_sealing_key).encrypt
        else:
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            h = ARC4.new(self._session_key).encrypt
            self._client_sealing_handle = h
            self._server_sealing_handle = h

        resp = impacket.spnego.SPNEGO_NegTokenResp()
        resp["ResponseToken"] = auth_resp.getData()
        hs2 = _NNSHandshake()
        hs2["message_id"] = _NNS_IN_PROGRESS
        hs2["major_version"] = 1; hs2["minor_version"] = 0
        hs2["payload"] = resp.getData()
        self._sock.sendall(hs2.getData())

        done = self._recv_handshake()
        self._check_error("NTLM", done)
        if done["message_id"] != _NNS_DONE:
            raise ConnectionError("NTLM handshake failed: 0x%x" % done["message_id"])

    def _auth_krb(self):
        target = "LDAP/%s" % self._fqdn
        domain, username, tgt, tgs = CCache.parseFile(
            domain=self._domain, username=self._username, target=target)
        self._domain = domain; self._username = username

        if tgs:
            tgs_bytes = tgs["KDC_REP"]; cipher = tgs["cipher"]; session_key = tgs["sessionKey"]
        elif tgt:
            spn = Principal(target, type=krb5_constants.PrincipalNameType.NT_SRV_INST.value)
            tgs_bytes, cipher, _, session_key = getKerberosTGS(
                serverName=spn, domain=self._domain,
                kdcHost=self._kdc_host or self._fqdn,
                tgt=tgt["KDC_REP"], cipher=tgt["cipher"], sessionKey=tgt["sessionKey"])
        else:
            raise SystemExit("[-] Kerberos: no usable TGS or TGT in KRB5CCNAME")

        tgs_rep = decoder.decode(tgs_bytes, asn1Spec=TGS_REP())[0]
        self._domain = str(tgs_rep["crealm"])
        ticket = Ticket(); ticket.from_asn1(tgs_rep["ticket"])
        user_p = Principal(self._username, type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value)

        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(krb5_constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = krb5_constants.encodeFlags([krb5_constants.APOptions.mutual_required.value])
        seq_set(ap_req, "ticket", ticket.to_asn1)

        auth = Authenticator()
        auth["authenticator-vno"] = 5; auth["crealm"] = self._domain
        seq_set(auth, "cname", user_p.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        auth["cusec"] = now.microsecond
        auth["ctime"] = KerberosTime.to_asn1(now)
        auth["cksum"] = noValue; auth["cksum"]["cksumtype"] = 0x8003
        cksum = CheckSumField(); cksum["Lgth"] = 16
        cksum["Flags"] = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG
        auth["cksum"]["checksum"] = cksum.getData()
        auth["seq-number"] = 0

        enc_auth = cipher.encrypt(session_key, 11, encoder.encode(auth), None)
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = enc_auth

        nti = impacket.spnego.SPNEGO_NegTokenInit()
        nti["MechTypes"] = [
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech["NEGOEX - SPNEGO Extended Negotiation Security Mechanism"],
            impacket.spnego.TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"],
        ]
        nti["MechToken"] = struct.pack("B", impacket.spnego.ASN1_AID) + impacket.spnego.asn1encode(
            struct.pack("B", impacket.spnego.ASN1_OID)
            + impacket.spnego.asn1encode(impacket.spnego.TypesMech["KRB5 - Kerberos 5"])
            + KRB5_AP_REP_TOKEN + encoder.encode(ap_req)
        )

        hs = _NNSHandshake()
        hs["message_id"] = _NNS_IN_PROGRESS; hs["major_version"] = 1; hs["minor_version"] = 0
        hs["payload"] = nti.getData()
        self._sock.sendall(hs.getData())

        done = self._recv_handshake()
        self._check_error("Kerberos", done)
        if done["message_id"] != _NNS_DONE:
            raise ConnectionError("Kerberos handshake failed: 0x%x" % done["message_id"])

        ntr = impacket.spnego.SPNEGO_NegTokenResp(done["payload"])
        if "ResponseToken" in ntr.fields:
            rt = ntr["ResponseToken"]
            if rt.startswith(b"\x60"):
                rt = _unwrap_gss_mech(rt)
            if rt.startswith(KRB5_AP_REP_TOKEN):
                rt = rt[len(KRB5_AP_REP_TOKEN):]
            ap_rep = decoder.decode(rt, asn1Spec=AP_REP())[0]
            pt = cipher.decrypt(session_key, 12, ap_rep["enc-part"]["cipher"])
            enc_part = decoder.decode(pt, asn1Spec=EncAPRepPart())[0]
            if enc_part["seq-number"].hasValue():
                self._server_sequence = int(enc_part["seq-number"])
            if enc_part["subkey"].hasValue():
                cipher = _enctype_table[int(enc_part["subkey"]["keytype"])]()
                session_key = Key(cipher.enctype, enc_part["subkey"]["keyvalue"].asOctets())

        self._session_key = session_key
        self._gss = GSSAPI(cipher)
        self._sequence = 0

    def sendall(self, data):
        pkt = _NNSData()
        if self._auth_protocol == "kerberos":
            ct, sig = self._gss.GSS_Wrap_LDAP(self._session_key, data, self._sequence)
            pkt["payload"] = sig + ct
        else:
            ct, sig = impacket.ntlm.SEAL(
                self._flags, self._client_signing_key, self._client_sealing_key,
                data, data, self._sequence, self._client_sealing_handle)
            pkt["payload"] = sig.getData() + ct
        self._sock.sendall(pkt.getData())
        self._sequence += 1

    def recv(self, _=0):
        first = self._recv_one()
        if first[0] != 0x06:
            return first
        sz, ll = MultiByteInt31.decode7bit(first[1:])
        if sz < 0xFC30:
            return first
        pkt = first; sz -= len(first[ll:])
        while sz > 0:
            frag = self._recv_one()
            pkt += frag; sz -= len(frag)
        return pkt

    def _recv_one(self):
        size = int.from_bytes(self._recv_exact(4), "little")
        payload = self._recv_exact(size)
        if self._auth_protocol == "kerberos":
            ct = self._kerberos_unwrap(payload)
            self._server_sequence += 1
            return ct
        sig = payload[:16]; ct = payload[16:]
        server = bool(self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        clear, _ = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            ct, ct, self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle)
        return clear

    def _kerberos_unwrap(self, payload):
        if payload.startswith(b"\x60"):
            token_data = _unwrap_gss_mech(payload)
            wrap_len = len(self._gss.WRAP())
            wrap = self._gss.WRAP(token_data[:wrap_len])
            ct = token_data[wrap_len:]
            kseq = HMAC.new(self._session_key.contents, struct.pack("<L", 0), MD5).digest()
            kseq = HMAC.new(kseq, wrap["SGN_CKSUM"], MD5).digest()
            ARC4.new(kseq).encrypt(wrap["SND_SEQ"])
            klocal = bytearray(b ^ 0xF0 for b in self._session_key.contents)
            kcrypt = HMAC.new(klocal, struct.pack("<L", 0), MD5).digest()
            kcrypt = HMAC.new(kcrypt, ARC4.new(kseq).encrypt(wrap["SND_SEQ"])[:4], MD5).digest()
            return ARC4.new(kcrypt).decrypt(wrap["Confounder"] + ct)[8:-1]
        clear, _ = self._gss.GSS_Unwrap_LDAP(self._session_key, payload, self._server_sequence, direction="accept")
        return clear


class NMFConnection:
    DUPLEX = 0x02
    NBFSE_INBAND = 0x08

    def __init__(self, nns, fqdn, mode=DUPLEX, encoding=NBFSE_INBAND):
        self._nns = nns
        self._sock = nns._sock
        self._transport = self._sock
        self._fqdn = fqdn
        self._mode = mode
        self._encoding = encoding
        self._encoder = NBFSEEncoder()
        self._recv_buffer = b""

    def connect(self, resource):
        via = "net.tcp://%s:%d/ActiveDirectoryWebServices/%s" % (self._fqdn, ADWS_PORT, resource)
        via_b = via.encode("utf-8")
        preamble = bytes([0x00, 1, 0])  # version
        preamble += bytes([0x01, self._mode])  # mode
        preamble += bytes([0x02]) + MultiByteInt31.encode7bit(len(via_b)) + via_b  # via
        preamble += bytes([0x03, self._encoding])  # encoding
        self._transport.sendall(preamble)

        if isinstance(self._nns, NNS):
            # upgrade request
            proto = b"application/negotiate"
            self._transport.sendall(bytes([0x09]) + MultiByteInt31.encode7bit(len(proto)) + proto)
            self._expect_record(0x0A)  # upgrade response
            self._nns.auth()
            self._recv_buffer = b""
            self._transport = self._nns

        self._transport.sendall(bytes([0x0C]))  # preamble end
        self._expect_record(0x0B)  # preamble ack

    def send(self, data):
        encoded = self._encoder.encode(data)
        payload = bytes([0x06]) + MultiByteInt31.encode7bit(len(encoded)) + encoded
        self._transport.sendall(payload)

    def recv(self):
        data = self._recv_record()
        if data[0] != 0x06:
            raise ConnectionError("expected sized envelope, got 0x%02x" % data[0])
        sz, ll = MultiByteInt31.decode7bit(data[1:])
        payload = data[1 + ll:1 + ll + sz]
        return self._encoder.decode(payload)

    def _recv_more(self):
        data = self._transport.recv(4096)
        if not data:
            raise ConnectionError("NMF: connection closed")
        self._recv_buffer += data

    def _recv_record(self):
        fixed = {0x00: 3, 0x01: 2, 0x03: 2, 0x07: 1, 0x0A: 1, 0x0B: 1, 0x0C: 1}
        variable = {0x02, 0x06, 0x08, 0x09}
        while not self._recv_buffer:
            self._recv_more()
        rt = self._recv_buffer[0]
        if rt in fixed:
            total = fixed[rt]
            while len(self._recv_buffer) < total:
                self._recv_more()
        elif rt in variable:
            info = None
            while info is None:
                if len(self._recv_buffer) > 1:
                    info = self._try_decode_size(self._recv_buffer[1:])
                if info is None:
                    self._recv_more()
            psz, sl = info
            total = 1 + sl + psz
            while len(self._recv_buffer) < total:
                self._recv_more()
        else:
            total = 1
        rec = self._recv_buffer[:total]
        self._recv_buffer = self._recv_buffer[total:]
        return rec

    def _expect_record(self, expected_type):
        rec = self._recv_record()
        if rec[0] != expected_type:
            if rec[0] == 0x08:
                sz, ll = MultiByteInt31.decode7bit(rec[1:])
                raise ConnectionError("NMF fault: %s" % rec[1+ll:1+ll+sz].decode("utf-8", errors="ignore"))
            raise ConnectionError("expected 0x%02x, got 0x%02x" % (expected_type, rec[0]))

    @staticmethod
    def _try_decode_size(data):
        value = 0; shift = 0
        for i, b in enumerate(data[:5], start=1):
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                return value, i
            shift += 7
        if len(data) < 5:
            return None
        raise ValueError("NMF size too large")


NAMESPACES = {
    "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    "adlq": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery",
    "da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
    "soapenv": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://www.w3.org/2005/08/addressing",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wxf": "http://schemas.xmlsoap.org/ws/2004/09/transfer",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://www.w3.org/2005/08/addressing",
}

SOAP_ENUMERATE = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action><ad:instance>ldap:389</ad:instance><a:MessageID>urn:uuid:{uuid}</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To></s:Header><s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"><wsen:Enumerate><wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"><adlq:LdapQuery><adlq:Filter>{query}</adlq:Filter><adlq:BaseObject>{basedn}</adlq:BaseObject><adlq:Scope>Subtree</adlq:Scope></adlq:LdapQuery></wsen:Filter><ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">{attributes}</ad:Selection></wsen:Enumerate></s:Body></s:Envelope>'

SOAP_PULL = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action><ad:instance>ldap:389</ad:instance><a:MessageID>urn:uuid:{uuid}</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To></s:Header><s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><wsen:Pull><wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext><wsen:MaxElements>256</wsen:MaxElements></wsen:Pull></s:Body></s:Envelope>'

SOAP_RENEW = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"><s:Header><a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Renew</a:Action><ad:instance>ldap:389</ad:instance><a:MessageID>urn:uuid:{uuid}</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To></s:Header><s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"><wsen:Renew><wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext><wsen:Expires>{expires}</wsen:Expires></wsen:Renew></s:Body></s:Envelope>'


class ADWSError(Exception):
    pass

class _ADWSReferral(ADWSError):
    def __init__(self, target_dc):
        self.target_dc = target_dc
        super().__init__(f"LDAP referral to {target_dc}")

class ADWSConnection:
    def __init__(self, target, domain, port=ADWS_PORT, timeout=10):
        self._target = target
        self._domain = domain
        self._port = port
        self._timeout = timeout
        self._username = ""
        self._password = ""
        self._nt_hash = ""
        self._kdc_host = None
        self._use_kerberos = False
        self._nmf = None
        self._base_dn = None
        self._fqdn = self._resolve_fqdn()

    def _resolve_fqdn(self):
        try:
            fqdn, _, _ = socket.gethostbyaddr(self._target)
            if "." in fqdn:
                return fqdn
        except socket.herror:
            pass
        if self._domain:
            return self._domain
        return self._target

    @property
    def base_dn(self):
        return self._base_dn or ",".join("DC=%s" % p for p in self._domain.split("."))

    @base_dn.setter
    def base_dn(self, value):
        self._base_dn = value

    def _connect_endpoint(self, target, resource):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        sock.connect((target, self._port))
        nns = NNS(sock, fqdn=self._fqdn, domain=self._domain, username=self._username,
                  password=self._password if self._password else None,
                  nt=self._nt_hash if self._nt_hash else "",
                  auth_protocol="kerberos" if self._use_kerberos else "ntlm",
                  kdc_host=self._kdc_host)
        nmf = NMFConnection(nns, fqdn=self._fqdn)
        nmf.connect("Windows/%s" % resource)
        return nmf

    def login(self, username, password="", nt_hash="", use_kerberos=False,
              kdc_host="", resource="Enumeration"):
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._use_kerberos = use_kerberos
        self._kdc_host = kdc_host if kdc_host else None
        self._nmf = self._connect_endpoint(self._target, resource)

    def disconnect(self):
        if self._nmf:
            try:
                getattr(self._nmf, "_sock", type("", (), {"close": lambda s: None})()).close()
            except: pass
            self._nmf = None

    def _request(self, soap_xml, op=""):
        if not self._nmf:
            raise ADWSError("not connected")
        for retry in range(_REQUEST_RETRIES + 1):
            try:
                self._nmf.send(soap_xml)
                resp = self._nmf.recv()
                return self._handle_response(resp)
            except _ADWSReferral:
                raise
            except ADWSError as e:
                if not any(c in str(e) for c in _TRANSIENT_FAULTS): raise
                fail = e
            except OSError as e:
                fail = e
            if retry == _REQUEST_RETRIES: raise fail
            time.sleep(_RETRY_BASE_DELAY * (retry + 1))
        raise RuntimeError("unreachable")

    def _handle_response(self, xml_str):
        xml_str = _BARE_AMPERSAND_RE.sub("&amp;", xml_str)
        et = ElementTree.fromstring(xml_str)
        fault = et.find(".//soapenv:Fault", namespaces=NAMESPACES)
        if fault is None:
            return et
        reason = fault.find(".//soapenv:Text", namespaces=NAMESPACES)
        msg = reason.text if reason is not None and reason.text else "SOAP fault"
        detail_parts = []
        referral_dc = None
        for elem in fault.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag in ("Fault", "Reason", "Text", "Code", "Value", "Subcode"):
                continue
            if elem.text and elem.text.strip():
                detail_parts.append(f"{tag}={elem.text.strip()}")
                if tag == "Referral":
                    m = re.match(r"ldap://([^/]+)/", elem.text.strip())
                    if m:
                        referral_dc = m.group(1)
                if tag == "Win32ErrorCode" and elem.text.strip() == "8235" and referral_dc:
                    raise _ADWSReferral(referral_dc)
        if detail_parts:
            msg += " [" + "; ".join(detail_parts) + "]"
        log.debug(f"ADWS SOAP fault response: {xml_str[:2000]}")
        raise ADWSError(msg)

    def _format_selection(self, attrs):
        return "".join("<ad:SelectionProperty>addata:%s</ad:SelectionProperty>" % a for a in attrs) if attrs else ""

    def _follow_referral(self, target_dc):
        log.warning(f"Following LDAP referral to {target_dc}")
        try:
            target_ip = socket.gethostbyname(target_dc)
        except socket.gaierror:
            log.info(f"Cannot resolve {target_dc}, reconnecting to {self._target} with FQDN {target_dc}")
            target_ip = self._target
        self._fqdn = target_dc
        self._nmf = self._connect_endpoint(target_ip, "Enumeration")

    def enumerate(self, query, attributes, basedn=""):
        basedn = basedn or self.base_dn
        for _hop in range(3):
            xml = SOAP_ENUMERATE.format(uuid=str(uuid4()), fqdn=self._fqdn,
                                         query=query, basedn=basedn,
                                         attributes=self._format_selection(attributes))
            try:
                et = self._request(xml, "Enumerate")
                break
            except _ADWSReferral as ref:
                self._follow_referral(ref.target_dc)
        else:
            raise ADWSError("max referral hops reached")
        ctx = et.find(".//wsen:EnumerationContext", NAMESPACES)
        if ctx is None or not ctx.text:
            raise ADWSError("no enumeration context returned")
        enum_ctx = ctx.text
        results = []
        last_renew = time.monotonic()
        has_more = True
        while has_more:
            if time.monotonic() - last_renew >= _RENEW_INTERVAL:
                rxml = SOAP_RENEW.format(uuid=str(uuid4()), fqdn=self._fqdn,
                                          enum_ctx=enum_ctx, expires=_RENEW_DURATION)
                ret = self._request(rxml, "Renew")
                rc = ret.find(".//wsen:RenewResponse/wsen:EnumerationContext", NAMESPACES)
                if rc is not None and rc.text:
                    enum_ctx = rc.text
                last_renew = time.monotonic()
            pxml = SOAP_PULL.format(uuid=str(uuid4()), fqdn=self._fqdn, enum_ctx=enum_ctx)
            et = self._request(pxml, "Pull")
            has_more = et.find(".//wsen:EndOfSequence", namespaces=NAMESPACES) is None
            uc = et.find(".//wsen:PullResponse/wsen:EnumerationContext", NAMESPACES)
            if uc is not None and uc.text:
                enum_ctx = uc.text
            for items in et.findall(".//wsen:Items", namespaces=NAMESPACES):
                for obj in items.findall(".//ad:value/../..", namespaces=NAMESPACES):
                    parsed = self._parse_object(obj)
                    if parsed:
                        results.append(parsed)
        return results

    @staticmethod
    def _parse_object(item):
        obj = {}
        for part in item.findall(".//ad:value/..", namespaces=NAMESPACES):
            tag = part.tag.split("}")[-1] if "}" in part.tag else part.tag
            syntax = part.attrib.get("LdapSyntax", "")
            values = [v.text for v in part.findall(".//ad:value", namespaces=NAMESPACES) if v is not None and v.text]
            if not values:
                continue
            if syntax == "SidString":
                decoded = []
                for v in values:
                    try: decoded.append(LDAP_SID(data=b64decode(v)).formatCanonical())
                    except: decoded.append(v)
                obj[tag] = decoded if len(decoded) > 1 else decoded[0]
                continue
            if tag == "objectGUID":
                decoded = [str(UUID(bytes_le=b64decode(v))).upper() for v in values]
                obj[tag] = decoded if len(decoded) > 1 else decoded[0]
                continue
            obj[tag] = values if len(values) > 1 else values[0]
        return obj
