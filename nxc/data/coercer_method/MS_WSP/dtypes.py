########################################
#                                     
#  RedTeam Pentesting GmbH            
#  kontakt@redteam-pentesting.de      
#  https://www.redteam-pentesting.de/ 
#                                     
########################################


import struct
import uuid

from enum import IntEnum
from typing import Any
from dataclasses import dataclass, field


# based on https://github.com/samba-team/samba/blob/master/librpc/idl/wsp_data.idl

"""
* Use en-us as default locale
* see MS-LCID 'Section 2.2 LCID Structure
* for details of this and other language id(s)
"""
WSP_DEFAULT_LCID = 0x00000409

"""
* Max size of rows buffer in getrowsout response
* see MS-WSP 2.2.3.11
"""
MAX_ROW_BUFF_SIZE = 0x0004000

# values for guidPropertySet
DBPROPSET_FSCIFRMWRK_EXT = uuid.UUID("A9BD1526-6A80-11D0-8C9D-0020AF1D740E")
DBPROPSET_QUERYEXT = uuid.UUID("A7AC77ED-F8D7-11CE-A798-0020F8008025")
DBPROPSET_CIFRMWRKCORE_EXT = uuid.UUID("AFAFACA5-B5D1-11D0-8C62-00C04FC2DB8D")
DBPROPSET_MSIDXS_ROWSETEXT = uuid.UUID("AA6EE6B0-E828-11D0-B23E-00AA0047FC01")
NULL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")
ONE_UUID = uuid.UUID("00000000-0001-0000-0000-000000000000")

# Chapter and bookmark handle well known values
DB_NULL_HCHAPTER = 0x00000000
DBBMK_FIRST = 0xFFFFFFFC
DBBMK_LAST = 0xFFFFFFFD

# properties of DBPROPSET_FSCIFRMWRK_EXT propertyset
DBPROP_CI_CATALOG_NAME = 0x00000002
DBPROP_CI_INCLUDE_SCOPES = 0x00000003
DBPROP_CI_SCOPE_FLAGS = 0x00000004
DBPROP_CI_QUERY_TYPE = 0x00000007
DBPROP_GENERICOPTIONS_STRING = 0x00000006
DBPROP_USECONTENTINDEX = 0x00000002
DBPROP_IGNORENOISEONLYCLAUSES = 0x00000005
DBPROP_DEFERCATALOGVERIFICATION = 0x00000008
DBPROP_IGNORESBRI = 0x0000000E
DBPROP_GENERATEPARSETREE = 0x0000000A
DBPROP_FREETEXTANYTERM = 0x0000000C
DBPROP_FREETEXTUSESTEMMING = 0x0000000D

# properties of DBPROPSET_QUERYEXT propertyset
DBPROP_DEFERNONINDEXEDTRIMMING = 0x00000003
DBPROP_USEEXTENDEDDBTYPES = 0x00000004
DBPROP_FIRSTROWS = 0x00000007
DBPROP_ENABLEROWSETEVENTS = 0x00000010

# properties of DBPROPSET_MSIDXS_ROWSETEXT
MSIDXSPROP_ROWSETQUERYSTATUS = 0x02
MSIDXSPROP_COMMAND_LOCALE_STRING = 0x03
MSIDXSPROP_QUERY_RESTRICTION = 0x04
MSIDXSPROP_PARSE_TREE = 0x05
MSIDXSPROP_MAX_RANK = 0x06
MSIDXSPROP_RESULTS_FOUND = 0x07

# flags of DBPROP_CI_SCOPE_FLAGS property
QUERY_DEEP = 0x01
QUERY_VIRTUAL_PATH = 0x02

# query type for BPROP_CI_QUERY_TYPE property
CINORMAL = 0x00000000

# properties of DBPROPSET_CIFRMWRKCORE_EXT propertyset
DBPROP_MACHINE = 0x00000002
DBPROP_CLIENT_CLSID = 0x00000003

"""
* STAT bit constants
"""

# The asynchronous query is still running.
STAT_BUSY = 0x00000000

# The query is in an error state.
STAT_ERROR = 0x00000001

# The query is complete and rows can be requested.
STAT_DONE = 0x00000002

# The query is comp#
STAT_REFRESH = 0x00000003

"""
* Noise words were replaced by wildcard characters in the
* content query.
"""
STAT_NOISE_WORDS = 0x00000010

"""
* The results of the query might be incorrect because the
* query involved modified but unindexed files.
"""
STAT_CONTENT_OUT_OF_DATE = 0x00000020

"""
* The content query was too complex to complete or
* required enumeration instead of use of the content index.
"""
STAT_CONTENT_QUERY_INCOMPLETE = 0x00000080

"""
* The results of the query might be incorrect because the
* query execution reached the maximum allowable time.
"""
STAT_TIME_LIMIT_EXCEEDED = 0x00000100

"""
* a const to force an inline array to be evaluated at runtime to
* to get around an incomplete type error
"""
SINGLE_ITEM = 1


# WSP message types
class WspMessageType(IntEnum):
    # CPMConnectIn or CPMConnectOut
    CPMCONNECT = 0x000000C8

    # CPMDisconnect
    CPMDISCONNECT = 0x000000C9
    
    # CPMCreateQueryIn or CPMCreateQueryOut
    CPMCREATEQUERY = 0x000000CA
    
    # CPMFreeCursorIn or CPMFreeCursorOut
    CPMFREECURSOR = 0x000000CB
    
    # CPMGetRowsIn or CPMGetRowsOut
    CPMGETROWS = 0x000000CC
    
    # CPMRatioFinishedIn or CPMRatioFinishedOut
    CPMRATIOFINISHED = 0x000000CD
    
    # CPMCompareBmkIn or CPMCompareBmkOut
    CPMCOMPAREBMK = 0x000000CE
    
    # CPMGetApproximatePositionIn or CPMGetApproximatePositionOut
    CPMGETAPPROXIMATEPOSITION = 0x000000CF
    
    # CPMSetBindingsIn
    CPMSETBINDINGSIN = 0x000000D0
    
    # CPMGetNotify
    CPMGETNOTIFY = 0x000000D1
    
    # CPMSendNotifyOut
    CPMSENDNOTIFYOUT = 0x000000D2
    
    # CPMGetQueryStatusIn or CPMGetQueryStatusOut
    CPMGETQUERYSTATUS = 0x000000D7
    
    # CPMCiStateInOut
    CPMCISTATEOUT = 0x000000D9
    
    # CPMFetchValueIn or CPMFetchValueOut
    CPMFETCHVALUE = 0x000000E4
    
    # CPMGetQueryStatusExIn or CPMGetQueryStatusExOut
    CPMGETQUERYSTATUSEX = 0x000000E7
    
    # CPMRestartPositionIn
    CPMRESTARTPOSITIONIN = 0x000000E8
    
    # CPMSetCatStateIn is not support
    CPMSETCATSTATEIN = 0x000000EC
    
    # CPMGetRowsetNotifyIn or CPMGetRowsetNotifyOut
    CPMGETROWSETNOTIFY = 0x000000F1
    
    # CPMFindIndicesIn, or CPMFindIndicesOut
    CPMFINDINDICES = 0x000000F2
    
    # CPMSetScopePrioritizationIn or CPMSetScopePrioritizationOut
    CPMSETSCOPEPRIORITIZATION = 0x000000F3
    
    # CPMGetScopeStatisticsIn or CPMGetScopeStatisticsOut
    CPMGETSCOPESTATISTICS = 0x000000F4


class CDbColId_eKind_Values(IntEnum):
    DBKIND_GUID_NAME = 0x00000000
    DBKIND_GUID_PROPID = 0x00000001


PRSPEC_LPWSTR = 0x00000000
PRSPEC_PROPID = 0x00000001
# type constants for variant types


class CBaseStorageVariant_vType_Values(IntEnum):
    VT_EMPTY = 0x0000
    VT_NULL = 0x0001
    VT_I2 = 0x0002
    VT_I4 = 0x0003
    VT_R4 = 0x0004
    VT_R8 = 0x0005
    VT_CY = 0x0006
    VT_DATE = 0x0007
    VT_BSTR = 0x0008
    VT_I1 = 0x0010
    VT_UI1 = 0x0011
    VT_UI2 = 0x0012
    VT_UI4 = 0x0013
    VT_I8 = 0x0014
    VT_UI8 = 0x0015
    VT_INT = 0x0016
    VT_UINT = 0x0017
    VT_ERROR = 0x000A
    VT_BOOL = 0x000B
    VT_VARIANT = 0x000C
    VT_DECIMAL = 0x000E
    VT_FILETIME = 0x0040
    VT_BLOB = 0x0041
    VT_BLOB_OBJECT = 0x0046
    VT_CLSID = 0x0048
    VT_LPSTR = 0x001E
    VT_LPWSTR = 0x001F
    VT_COMPRESSED_LPWSTR = 0x0023
    VT_VECTOR = 0x1000
    VT_ARRAY = 0x2000


# restriction types
RTNONE = 0x00000000
RTAND = 0x00000001
RTOR = 0x00000002
RTNOT = 0x00000003
RTCONTENT = 0x00000004
RTPROPERTY = 0x00000005
RTPROXIMITY = 0x00000006
RTVECTOR = 0x00000007
RTNATLANGUAGE = 0x00000008
RTSCOPE = 0x00000009
RTREUSEWHERE = 0x00000011
RTINTERNALPROP = 0x00FFFFFA
RTPHRASE = 0x00FFFFFD
RTCOERCE_ADD = 0x0000000A
RTCOERCE_MULTIPLY = 0x0000000B
RTCOERCE_ABSOLUTE = 0x0000000C
RTPROB = 0x0000000D
RTFEEDBACK = 0x0000000E
RTRELDOC = 0x0000000F


# Row seek types
EROWSEEKNONE = 0x00000000
EROWSEEKNEXT = 0x00000001
EROWSEEKAT = 0x00000002
EROWSEEKATRATIO = 0x00000003
EROWSEEKBYBOOKMARK = 0x00000004

WINDOWS_7 = 0x00000700
WINDOWS_2008 = 0x00010700


# Relops
PRLT = 0x00000000
PRLE = 0x00000001
PRGT = 0x00000002
PRGE = 0x00000003
PREQ = 0x00000004
PRNE = 0x00000005
PRRE = 0x00000006
PRALLBITS = 0x00000007
PRSOMEBITS = 0x00000008
PRALL = 0x00000100
PRANY = 0x00000200

PROPAGATE_NONE = 0
PROPAGATE_ADD = 1
PROPAGATE_DELETE = 2
PROPAGATE_MODIFY = 3
PROPAGATE_ROWSET = 4

ROWSETEVENT_ITEMSTATE_NOTINROWSET = 0
ROWSETEVENT_ITEMSTATE_INROWSET = 1
ROWSETEVENT_ITEMSTATE_UNKNOWN = 2

ROWSETEVENT_TYPE_DATAEXPIRED = 0
ROWSETEVENT_TYPE_FOREGROUNDLOST = 1
ROWSETEVENT_TYPE_SCOPESTATISTICS = 2

DBCOMPARE_LT = 0x00000000
DBCOMPARE_EQ = 0x00000001
DBCOMPARE_GT = 0x00000002
DBCOMPARE_NE = 0x00000003
DBCOMPARE_NOTCOMPARABLE = 0x00000004

VECTOR_RANK_MIN = 0x00000000
VECTOR_RANK_MAX = 0x00000001
VECTOR_RANK_INNER = 0x00000002
VECTOR_RANK_DICE = 0x00000003
VECTOR_RANK_JACCARD = 0x00000004

DBAGGTTYPE_BYNONE = 0x00000000
DBAGGTTYPE_SUM = 0x00000001
DBAGGTTYPE_MAX = 0x00000002
DBAGGTTYPE_MIN = 0x00000003
DBAGGTTYPE_AVG = 0x00000004
DBAGGTTYPE_COUNT = 0x00000005
DBAGGTTYPE_CHILDCOUNT = 0x00000006
DBAGGTTYPE_BYFREQ = 0x00000007
DBAGGTTYPE_FIRST = 0x00000008
DBAGGTTYPE_DATERANGE = 0x00000009
DBAGGTTYPE_REPRESENTATIVEOF = 0x0000000A
DBAGGTTYPE_EDITDISTANCE = 0x0000000B

ESEQUENTIAL = 0x00000001
ELOCATEABLE = 0x00000003
ESCROLLABLE = 0x00000007
EASYNCHRONOUS = 0x00000008
EFIRSTROWS = 0x00000080
EHOLDROWS = 0x00000200
ECHAPTERED = 0x00000800
EUSECI = 0x00001000
EDEFERTRIMMING = 0x00002000
ENABLEROWSETEVENTS = 0x00800000
EDONOTCOMPUTEEXPENSIVEPROPS = 0x00400000

CI_STATE_SHADOW_MERGE = 0x00000001
CI_STATE_MASTER_MERGE = 0x00000002
CI_STATE_ANNEALING_MERGE = 0x00000008
CI_STATE_SCANNING = 0x00000010
CI_STATE_LOW_MEMORY = 0x00000080
CI_STATE_HIGH_IO = 0x00000100
CI_STATE_MASTER_MERGE_PAUSED = 0x00000200
CI_STATE_READ_ONLY = 0x00000400
CI_STATE_BATTERY_POWER = 0x00000800
CI_STATE_USER_ACTIVE = 0x00001000
CI_STATE_LOW_DISK = 0x00010000
CI_STATE_HIGH_CPU = 0x00020000

STORESTATUSOK = 0x00000000
STORESTATUSDEFERRED = 0x00000001
STORESTATUSNULL = 0x00000002

DB_S_ENDOFROWSET = 0x00040EC6

XOR_CONST = 0x59533959
E_UNEXPECTED = 0x8000FFFF
WIN_UPDATE_ERR = 0x80070003

QUERY_SORTASCEND = 0x00000000
QUERY_DESCEND = 0x00000001


def AlignWrite(buffer: bytearray, alignment: int):
    while len(buffer) % alignment != 0:
        buffer.extend(b"\x00")


def AddAlign(buffer: bytearray, t: bytes, alignment: int):
    AlignWrite(buffer, alignment)
    buffer.extend(t)


def CalculateChecksum(buffer: bytes, _msg: int):
    checksum = sum(
        int.from_bytes(buffer[i : i + 4], "little") for i in range(0, len(buffer), 4)
    )
    checksum ^= XOR_CONST
    checksum -= _msg
    return checksum & 0xFFFFFFFF


@dataclass
class WspMessageHeader:
    _msg: WspMessageType
    _status: int = 0
    _ulChecksum: int = 0
    _ulReserved2: int = 0

    def to_bytes(self) -> bytes:
        return struct.pack(
            "<IIII", self._msg, self._status, self._ulChecksum, self._ulReserved2
        )


@dataclass
class PropSpec:
    guid: uuid.UUID
    ulKind: int
    propid: int

    def to_bytes(self, buffer: bytearray):
        AddAlign(buffer, self.guid.bytes_le, 8)
        buffer.extend(struct.pack("<II", self.ulKind, self.propid))


@dataclass
class CColumnSet:
    indexes: list[int] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.indexes)))
        for i in self.indexes:
            buffer.extend(struct.pack("<I", i))


@dataclass
class CDbColId:
    eKind: CDbColId_eKind_Values = CDbColId_eKind_Values.DBKIND_GUID_PROPID
    GUID: uuid.UUID = NULL_UUID
    ulId: int = 0
    vString: str = ""

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.eKind))
        AddAlign(buffer, self.GUID.bytes_le, 8)
        buffer.extend(struct.pack("<I", self.ulId))
        if self.eKind == CDbColId_eKind_Values.DBKIND_GUID_NAME:
            raise NotImplementedError


@dataclass
class VT_LPSTR:
    _string: str

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self._string)))
        str_bytes = (self._string + "\0").encode("utf-16le")
        buffer.extend(str_bytes)


@dataclass
class VT_BSTR:
    _string: str

    def to_bytes(self, buffer: bytearray):
        str_bytes = (self._string + "\0").encode("utf-16le")
        buffer.extend(struct.pack("<I", len(str_bytes)))
        buffer.extend(str_bytes)


@dataclass
class VT_LPWSTR:
    _string: str

    def to_bytes(self, buffer: bytearray):
        if len(self._string) == 0:
            buffer.extend(struct.pack("<I", 0))
        else:
            str_bytes = (self._string + "\0").encode("utf-16le")
            buffer.extend(struct.pack("<I", len(self._string) + 1))
            buffer.extend(str_bytes)


def vType_to_bytes(vType, vValue, buffer: bytearray):
    if vType == CBaseStorageVariant_vType_Values.VT_I1:
        buffer.extend(struct.pack("<b", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI1:
        buffer.extend(struct.pack("<B", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_I2:
        buffer.extend(struct.pack("<h", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI2:
        buffer.extend(struct.pack("<H", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_BOOL:
        buffer.extend(struct.pack("<H", 0xFFFF if vValue else 0))
    elif vType == CBaseStorageVariant_vType_Values.VT_I4:
        buffer.extend(struct.pack("<i", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI4:
        buffer.extend(struct.pack("<I", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_R4:
        buffer.extend(struct.pack("<f", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_INT:
        buffer.extend(struct.pack("<i", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UINT or vType == CBaseStorageVariant_vType_Values.VT_ERROR:
        buffer.extend(struct.pack("<I", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_I8:
        buffer.extend(struct.pack("<l", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_UI8:
        buffer.extend(struct.pack("<L", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_R8:
        buffer.extend(struct.pack("<d", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_CY:
        buffer.extend(struct.pack("<l", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_DATE:
        buffer.extend(struct.pack("<d", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_FILETIME:
        buffer.extend(struct.pack("<l", vValue))
    elif vType == CBaseStorageVariant_vType_Values.VT_DECIMAL:
        vValue.to_bytes(buffer)
    elif vType == CBaseStorageVariant_vType_Values.VT_CLSID:
        buffer.extend(vValue.bytes_le)
    elif vType == CBaseStorageVariant_vType_Values.VT_BLOB or vType == CBaseStorageVariant_vType_Values.VT_BLOB_OBJECT or vType == CBaseStorageVariant_vType_Values.VT_BSTR or vType == CBaseStorageVariant_vType_Values.VT_LPSTR or vType == CBaseStorageVariant_vType_Values.VT_LPWSTR or vType == CBaseStorageVariant_vType_Values.VT_COMPRESSED_LPWSTR:
        vValue.to_bytes(buffer)
    else:
        print(hex(vType), vValue)
        raise NotImplementedError


@dataclass
class VT_ARRAY:
    vData: list
    vType: int

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<H", 1))  # dimesions
        buffer.extend(struct.pack("<H", 0))  # ffeatures

        temp_buffer = bytearray()
        # first_element
        _ = vType_to_bytes(
            self.vType ^ CBaseStorageVariant_vType_Values.VT_ARRAY,
            self.vData[0],
            temp_buffer,
        )
        buffer.extend(
            struct.pack("<I", len(temp_buffer))
        )  # cbelements (size of each element of the array)

        buffer.extend(struct.pack("<I", len(self.vData)))  # rgsaboundElements
        buffer.extend(struct.pack("<I", 0))  # rgsaboundIlBound
        for i in self.vData:
            vType_to_bytes(
                self.vType ^ CBaseStorageVariant_vType_Values.VT_ARRAY, i, buffer
            )


@dataclass
class CBaseStorageVariant:
    vType: int
    vValue: Any
    vData1: int = 0
    vData2: int = 0

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<H", self.vType))
        buffer.extend(struct.pack("<B", self.vData1))
        buffer.extend(struct.pack("<B", self.vData2))
        if self.vType & CBaseStorageVariant_vType_Values.VT_VECTOR:
            buffer.extend(struct.pack("<I", len(self.vValue)))
            for i in self.vValue:
                AlignWrite(buffer, 4)
                vType_to_bytes(
                    self.vType ^ CBaseStorageVariant_vType_Values.VT_VECTOR, i, buffer
                )
        elif self.vType & CBaseStorageVariant_vType_Values.VT_ARRAY:
            VT_ARRAY(self.vValue, self.vType).to_bytes(buffer)
        else:
            vType_to_bytes(self.vType, self.vValue, buffer)


@dataclass
class CProp:
    DBPROPID: int
    vValue: CBaseStorageVariant
    DBPROPOPTIONS: int = 0
    DBPROPSTATUS: int = 0
    colid: CDbColId = field(default_factory=CDbColId)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.DBPROPID))
        buffer.extend(struct.pack("<I", self.DBPROPOPTIONS))
        buffer.extend(struct.pack("<I", self.DBPROPSTATUS))
        self.colid.to_bytes(buffer)
        self.vValue.to_bytes(buffer)


@dataclass
class CPropSet:
    guidPropertySet: uuid.UUID
    aProps: list[CProp] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(self.guidPropertySet.bytes_le)
        AddAlign(buffer, struct.pack("<I", len(self.aProps)), 4)
        for prop in self.aProps:
            AlignWrite(buffer, 4)
            prop.to_bytes(buffer)


@dataclass
class CPropertyRestriction:
    relop: int
    Property: PropSpec
    prval: str  # VT_LPWSTR value
    lcid: int = WSP_DEFAULT_LCID

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.relop))
        self.Property.to_bytes(buffer)

        AlignWrite(buffer, 4)

        buffer.extend(struct.pack("<I", 0x1F))  # VT_LPWSTR type
        str_bytes = (self.prval + "\0").encode("utf-16le")
        str_len = len(str_bytes) // 2  # Length in characters (16-bit)
        buffer.extend(struct.pack("<I", str_len))  # String length
        buffer.extend(str_bytes)

        AddAlign(buffer, struct.pack("<I", self.lcid), 4)


@dataclass
class CRestriction:
    ulType: int = 0
    Weight: int = 0
    Restriction: Any = None

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", self.ulType))  # Type first
        buffer.extend(struct.pack("<I", self.Weight))  # Weight second
        if self.Restriction is not None:
            self.Restriction.to_bytes(buffer)


@dataclass
class CRestrictionArray:
    restrictions: list[CRestriction] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<B", len(self.restrictions)))
        buffer.extend(struct.pack("<B", 1 if len(self.restrictions) > 0 else 0))
        AlignWrite(buffer, 4)
        for restriction in self.restrictions:
            restriction.to_bytes(buffer)


@dataclass
class CSortSet:
    sortArray: list[int] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.sortArray)))
        for sort in self.sortArray:
            buffer.extend(struct.pack("<I", sort))


@dataclass
class CInGroupSortAggregSets:
    Reserved: int = 0
    SortSets: list[CSortSet] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<II", len(self.SortSets), self.Reserved))
        for sort_set in self.SortSets:
            sort_set.to_bytes(buffer)


@dataclass
class CCategSpec:
    def to_bytes(self, buffer):
        return b""


@dataclass
class CCategorizationSpec:
    csColumns: CColumnSet = field(default_factory=CColumnSet)
    Spec: CCategSpec = field(default_factory=CCategSpec)

    def to_bytes(self, buffer: bytearray):
        self.csColumns.to_bytes(buffer)
        self.Spec.to_bytes(buffer)


@dataclass
class CCategorizationSet:
    categories: list[CCategorizationSpec] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.categories)))
        for category in self.categories:
            category.to_bytes(buffer)


@dataclass
class CRowsetProperties:
    uBooleanOptions: int = 0x00000001
    ulMaxOpenRows: int = 0
    ulMemUsage: int = 0
    cMaxResults: int = 10
    cCmdTimeout: int = 30

    def to_bytes(self, buffer: bytearray):
        buffer.extend(
            struct.pack(
                "<IIIII",
                self.uBooleanOptions,
                self.ulMaxOpenRows,
                self.ulMemUsage,
                self.cMaxResults,
                self.cCmdTimeout,
            )
        )


@dataclass
class CPidMapper:
    PropSpecs: list[PropSpec] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.PropSpecs)))
        for prop_spec in self.PropSpecs:
            prop_spec.to_bytes(buffer)


@dataclass
class CColumnGroup:
    def to_bytes(self, buffer: bytearray):
        pass


@dataclass
class CColumnGroupArray:
    aGroupArray: list[CColumnGroup] = field(default_factory=list)

    def to_bytes(self, buffer: bytearray):
        buffer.extend(struct.pack("<I", len(self.aGroupArray)))
        for group in self.aGroupArray:
            group.to_bytes(buffer)


# Only the necessary strcuts are included for coercion
@dataclass
class CPMCreateQueryIn:
    target_uri: str

    def to_bytes(self) -> bytes:
        header = WspMessageHeader(_msg=WspMessageType.CPMCREATEQUERY)
        body = self._get_body_bytes()

        header._ulChecksum = CalculateChecksum(body, WspMessageType.CPMCREATEQUERY)

        return header.to_bytes() + body

    def _get_body_bytes(self) -> bytes:
        temp_buffer = bytearray()

        # length, will be updated later
        temp_buffer.extend(struct.pack("<I", 0))

        temp_buffer.append(0x01)  # CColumnSetPresent
        AlignWrite(temp_buffer, 4)
        CColumnSet().to_bytes(temp_buffer)

        temp_buffer.append(0x01)  # CRestrictionPresent
        restriction_array = CRestrictionArray(
            restrictions=[
                CRestriction(
                    ulType=RTPROPERTY,
                    Weight=1000,
                    Restriction=CPropertyRestriction(
                        relop=PREQ,
                        Property=PropSpec(
                            guid=uuid.UUID("b725f130-47ef-101a-a5f1-02608c9eebac"),
                            ulKind=PRSPEC_PROPID,
                            propid=0x16,
                        ),
                        prval=self.target_uri,
                    ),
                )
            ]
        )

        restriction_array.to_bytes(temp_buffer)

        temp_buffer.append(0x00)  # CSortSetPresent (not used)
        temp_buffer.append(0x00)  # CCategorizationSetPresent (not used)

        AlignWrite(temp_buffer, 4)

        rowset_props = CRowsetProperties(
            uBooleanOptions=0x00000001,
            ulMaxOpenRows=0,
            ulMemUsage=0,
            cMaxResults=10,
            cCmdTimeout=30,
        )
        rowset_props.to_bytes(temp_buffer)

        pid_mapper = CPidMapper(
            PropSpecs=[PropSpec(guid=NULL_UUID, ulKind=PRSPEC_PROPID, propid=0x16)]
        )
        pid_mapper.to_bytes(temp_buffer)

        CColumnGroupArray().to_bytes(temp_buffer)

        temp_buffer.extend(struct.pack("<I", WSP_DEFAULT_LCID))

        # Update size
        size = len(temp_buffer)
        temp_buffer[0:4] = struct.pack("<I", size)

        return bytes(temp_buffer)


@dataclass
class CPMConnectIn:
    MachineName: str
    UserName: str
    _iClientVersion: int = 0x00010700
    _fClientIsRemote: int = 0x00000001

    def default_extpropset4(self):
        return CPropSet(
            DBPROPSET_FSCIFRMWRK_EXT,
            [
                CProp(
                    DBPROPID=DBPROP_CI_CATALOG_NAME,
                    vValue=CBaseStorageVariant(
                        vType=CBaseStorageVariant_vType_Values.VT_BSTR,
                        vValue=VT_BSTR("Windows\\SYSTEMINDEX"),
                    ),
                )
            ],
        )

    def to_bytes(self) -> bytes:
        header = WspMessageHeader(_msg=WspMessageType.CPMCONNECT)
        body = self._get_body_bytes()

        # Calculate checksum
        header._ulChecksum = CalculateChecksum(body, WspMessageType.CPMCONNECT)

        return header.to_bytes() + body

    def _get_body_bytes(self) -> bytes:
        temp_buffer = bytearray()
        temp_buffer.extend(struct.pack("<I", self._iClientVersion))
        temp_buffer.extend(struct.pack("<I", self._fClientIsRemote))

        blob1_buffer = bytearray()
        blob1_buffer.extend(struct.pack("<I", 0))  # No default propsets
        temp_buffer.extend(struct.pack("<I", len(blob1_buffer)))

        blob2_buffer = bytearray()
        AddAlign(
            blob2_buffer, struct.pack("<I", 1), 8
        )  # only DBPROP_CI_CATALOG_NAME prop
        self.default_extpropset4().to_bytes(blob2_buffer)

        AddAlign(temp_buffer, struct.pack("<I", len(blob2_buffer)), 8)
        temp_buffer.extend(bytes(12))

        temp_buffer.extend((self.MachineName + "\0").encode("utf-16le"))
        temp_buffer.extend((self.UserName + "\0").encode("utf-16le"))

        AlignWrite(temp_buffer, 8)

        temp_buffer.extend(blob1_buffer)

        AlignWrite(temp_buffer, 8)

        temp_buffer.extend(blob2_buffer)

        temp_buffer.extend(bytes(4))

        return bytes(temp_buffer)


@dataclass
class CPMDisconnect:
    def to_bytes(self) -> bytes:
        header = WspMessageHeader(_msg=WspMessageType.CPMDISCONNECT)
        header._ulChecksum = CalculateChecksum(b"", WspMessageType.CPMDISCONNECT)
        # No body for disconnect message
        return header.to_bytes()
