import os
import random
import socket
import struct
import contextlib
from io import StringIO
from termcolor import colored


from nxc.config import process_secret
from nxc.connection import connection
from nxc.connection import requires_admin
from nxc.logger import NXCAdapter
from nxc.helpers.bloodhound import add_user_bh
from nxc.config import process_secret, host_info_colors
from nxc.helpers.ntlm_parser import parse_challenge
from nxc.helpers.powershell import create_ps_command
from nxc.protocols.mssql.mssqlexec import MSSQLEXEC

from impacket import tds, ntlm
from impacket.krb5.ccache import CCache
from impacket.dcerpc.v5.dtypes import SID
from impacket.tds import (
    SQLErrorException,
    TDS_PRE_LOGIN,
    TDS_LOGINACK_TOKEN,
    TDS_ERROR_TOKEN,
    TDS_ENVCHANGE_TOKEN,
    TDS_INFO_TOKEN,
    TDS_ENVCHANGE_VARCHAR,
    TDS_ENVCHANGE_DATABASE,
    TDS_ENVCHANGE_LANGUAGE,
    TDS_ENVCHANGE_CHARSET,
    TDS_ENVCHANGE_PACKETSIZE,
)

# Added by @Deft to support version enum and encryption via PRELOGIN
from impacket.tds import (
    TDS_PRELOGIN,        # Used to structure to initialize first packet to MSSQL
    TDS_ENCRYPT_OFF,     # Encryption is available but off
    TDS_ENCRYPT_ON,      # Encryption is available and on
    TDS_ENCRYPT_NOT_SUP, # Encryption is not available
    TDS_ENCRYPT_REQ      # Encryption is required
)

# This was taken from https://github.com/CompassSecurity/mssqlrelay/blob/main/mssqlrelay/commands/check.py 
# And added by @Deft_ to support version enum, thanks @sploutchy for the work!!
class MSSQL_VERSION:
    # from https://sqlserverbuilds.blogspot.com/
    VERSION_NAME = ("Microsoft SQL Server", {
        # Out of support
        6 : ("6", {
            0 : (".0", {
                121 : "RTM (no SP)",
                124 : "(SP1)",
                139 : "(SP2)",
                151 : "(SP3)",
            }),
            50 : (".5", {
                201 : "RTM (no SP)",
                213 : "(SP1)",
                240 : "(SP2)",
                258 : "(SP3)",
                281 : "(SP4)",
                416 : "(SP5)",
            }),
        }),
        7 : ("7", {
            0 : ("", {
                623 : "RTM (no SP)",
                699 : "(SP1)",
                842 : "(SP2)",
                961 : "(SP3)",
                1063 : "(SP4)",
            }),
        }),
        8 : ("2000", {
            0 : ("", {
                194 : "RTM (no SP)",
                384 : "(SP1)",
                532 : "(SP2)",
                760 : "(SP3)",
                2039 : "(SP4)",
            }),
        }),
        9 : ("2005", {
            0 : ("", {
                1399 : "RTM (no SP)",
                2047 : "(SP1)",
                3042 : "(SP2)",
                4035 : "(SP3)",
                5000 : "(SP4)",
            }),
        }),
        10 : ("2008", {
            0 : ("", {
                1600 : "RTM (no SP)",
                2531 : "(SP1)",
                4000 : "(SP2)",
                5500 : "(SP3)",
                6000 : "(SP4)",
            }),
            50 : (" R2", {
                1600 : "RTM (no SP)",
                2500 : "(SP1)",
                4000 : "(SP2)",
                6000 : "(SP3)",
            }),
        }),
        11 : ("2012", {
            0 : ("", {
                2100 : "RTM (no SP)",
                3000 : "(SP1)",
                5058 : "(SP2)",
                6020 : "(SP3)",
                7001 : "(SP4)",
            }),
        }),
        # Supported
        12 : ("2014", {
            0 : ("", {
                2000 : "RTM (no SP)",
                4100 : "(SP1)",
                5000 : "(SP2)",
                6024 : "(SP3)",
            }),
        }),
        13 : ("2016", {
            0 : ("", {
                1601 : "RTM (no SP)",
                4001 : "(SP1)",
                5026 : "(SP2)",
                6300 : "(SP3)",
            }),
        }),
        14 : ("2017", {
            0 : ("", {
                1000 : "RTM",
                3006 : "(CU1)",
                3008 : "(CU2)",
                3015 : "(CU3)",
                3022 : "(CU4)",
                3023 : "(CU5)",
                3025 : "(CU6)",
                3026 : "(CU7)",
                3029 : "(CU8)",
                3030 : "(CU9)",
                3037 : "(CU10)",
                3038 : "(CU11)",
                3045 : "(CU12)",
                3048 : "(CU13)",
                3076 : "(CU14)",
                3162 : "(CU15)",
                3223 : "(CU16)",
                3228 : "(CU17)",
                3257 : "(CU18)",
                3281 : "(CU19)",
                3294 : "(CU20)",
                3335 : "(CU21)",
                3356 : "(CU22)",
                3381 : "(CU23)",
                3391 : "(CU24)",
                3401 : "(CU25)",
                3411 : "(CU26)",
                3421 : "(CU27)",
                3430 : "(CU28)",
                3436 : "(CU29)",
                3451 : "(CU30)",
                3456 : "(CU31)",
            }),
        }),
        15 : ("2019", {
            0 : ("", {
                2000 : "RTM",
                4003 : "(CU1)",
                4013 : "(CU2)",
                4023 : "(CU3)",
                4033 : "(CU4)",
                4043 : "(CU5)",
                4053 : "(CU6)",
                4063 : "(CU7)",
                4073 : "(CU8)",
                4102 : "(CU9)",
                4123 : "(CU10)",
                4138 : "(CU11)",
                4153 : "(CU12)",
                4178 : "(CU13)",
                4188 : "(CU14)",
                4198 : "(CU15)",
                4223 : "(CU16)",
                4249 : "(CU17)",
                4261 : "(CU18)",
                4298 : "(CU19)",
                4312 : "(CU20)",
            }),
        }),
        16 : ("2022", {
            0 : ("", {
                1000 : "RTM",
                4003 : "(CU1)",
                4015 : "(CU2)",
                4025 : "(CU3)",
                4035 : "(CU4)",
            }),
        }),
    })

    def __init__(self, version):
        self.major, self.minor, self.build = struct.unpack_from('>bbH', version)

    @property
    def version_number(self):
        return "%i.%i.%i" % (self.major, self.minor, self.build)

    @property
    def version_name(self):
        try:
            string = MSSQL_VERSION.VERSION_NAME[0]
            string += " "
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][0]
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][1][self.minor][0]
            string += " "
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][1][self.minor][1][self.build]
        except KeyError:
            string += "(unknown)"
        finally:
            return string

    def __repr__(self):
        return self.version_number
    
class mssql(connection):
    def __init__(self, args, db, host):
        self.mssql_instances = []
        self.domain = ""
        self.targetDomain = ""
        self.server_os = None
        self.hash = None
        self.os_arch = None
        self.nthash = ""
        self.is_mssql = False

        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "MSSQL",
                "host": self.host,
                "port": self.port,
                "hostname": "None",
            }
        )

    def create_conn_obj(self):
        try:
            self.conn = tds.MSSQL(self.host, self.port, self.remoteName)
            # Default has not timeout option in tds.MSSQL.connect() function, let rewrite it.
            af, socktype, proto, canonname, sa = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)[0]
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(self.args.mssql_timeout)
            sock.connect(sa)
            self.conn.socket = sock
            if not self.is_mssql:
                self.conn.preLogin()
        except Exception as e:
            self.logger.debug(f"Error connecting to MSSQL service on host: {self.host}, reason: {e}")
            return False
        else:
            self.is_mssql = True
            return True

    def reconnect_mssql(func):
        def wrapper(self, *args, **kwargs):
            with contextlib.suppress(Exception):
                self.conn.disconnect()
            self.create_conn_obj()
            return func(self, *args, **kwargs)
        return wrapper

    def check_if_admin(self):
        self.admin_privs = False
        try:
            results = self.conn.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
            is_admin = int(results[0][""])
        except Exception as e:
            self.logger.fail(f"Error querying for sysadmin role: {e}")
        else:
            if is_admin:
                self.admin_privs = True

    # Added by @Deft_ from https://github.com/CompassSecurity/mssqlrelay/blob/main/mssqlrelay/commands/check.py
    def check_encryption(self):
        try:
            prelogin = TDS_PRELOGIN()
            prelogin['Version'] = b"\x08\x00\x01\x55\x00\x00"
            prelogin['Encryption'] = TDS_ENCRYPT_NOT_SUP
            prelogin['ThreadID'] = struct.pack('<L', random.randint(0, 65535))
            prelogin['Instance'] = b'MSSQLServer\x00'
            self.conn.sendTDS(TDS_PRE_LOGIN, prelogin.getData(), 0)
            tds = self.conn.recvTDS()
            response = TDS_PRELOGIN(tds['Data'])
            version = MSSQL_VERSION(response['Version'])
            return version, response['Encryption']
        except Exception as e:
            self.logger.error(f"Exception in mssql:check_encryption {str(e)}")
            return "", ""
    
    @reconnect_mssql
    def enum_host_info(self):
        challenge = None

        # Added by @Deft_ to enumerate MSSQL version and encryption option
        self.mssql_version, self.encryption = self.check_encryption()

        try:
            login = tds.TDS_LOGIN()
            login["HostName"] = ""
            login["AppName"] = ""
            login["ServerName"] = self.conn.server.encode("utf-16le")
            login["CltIntName"] = login["AppName"]
            login["ClientPID"] = random.randint(0, 1024)
            login["PacketSize"] = self.conn.packetSize
            login["OptionFlags2"] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON

            # NTLMSSP Negotiate
            auth = ntlm.getNTLMSSPType1("", "")
            login["SSPI"] = auth.getData()
            login["Length"] = len(login.getData())

            # Get number of mssql instance
            self.mssql_instances = self.conn.getInstances(0)

            # Send the NTLMSSP Negotiate or SQL Auth Packet
            self.conn.sendTDS(tds.TDS_LOGIN7, login.getData())

            tdsx = self.conn.recvTDS()
            challenge = tdsx["Data"][3:]
            self.logger.info(f"NTLM challenge: {challenge!s}")
        except Exception as e:
            self.logger.info(f"Failed to receive NTLM challenge, reason: {e!s}")
            return False
        else:
            ntlm_info = parse_challenge(challenge)
            self.targetDomain = self.domain = ntlm_info["domain"]
            self.hostname = ntlm_info["hostname"]
            self.server_os = ntlm_info["os_version"]
            self.logger.extra["hostname"] = self.hostname
            self.db.add_host(self.host, self.hostname, self.targetDomain, self.server_os, len(self.mssql_instances),)

        if self.args.domain:
            self.domain = self.args.domain
        if self.args.local_auth:
            self.domain = self.hostname

        self.remoteName = self.host if not self.kerberos else f"{self.hostname}.{self.domain}"

        if not self.kdcHost and self.domain:
            result = self.resolver(self.domain)
            self.kdcHost = result["host"] if result else None
            self.logger.info(f"Resolved domain: {self.domain} with dns, kdcHost: {self.kdcHost}")

    def print_host_info(self):
        encryption = colored("encryption:True", host_info_colors[0], attrs=["bold"]) if self.encryption != TDS_ENCRYPT_NOT_SUP else colored("encryption:False", host_info_colors[1], attrs=["bold"])
        self.logger.display(f"{self.server_os} (name:{self.hostname}) (domain:{self.targetDomain}) (mssql:{self.mssql_version}) ({encryption})")

    @reconnect_mssql
    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        self.username = username
        self.password = password
        self.domain = domain
        self.nthash = ""
        hashes = None
        if ntlm_hash:
            if ntlm_hash.find(":") != -1:
                self.nthash = ntlm_hash.split(":")[1]
                hashes = f":{self.nthash}"
            else:
                self.nthash = ntlm_hash
                hashes = f":{self.nthash}"

        kerb_pass = next(s for s in [self.nthash, password, aesKey] if s) if not all(s == "" for s in [self.nthash, password, aesKey]) else ""

        if useCache and kerb_pass == "":
            ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
            username = ccache.credentials[0].header["client"].prettyPrint().decode().split("@")[0]
            self.username = username

        used_ccache = " from ccache" if useCache else f":{process_secret(kerb_pass)}"
        try:
            res = self.conn.kerberosLogin(
                None,
                self.username,
                self.password,
                self.domain,
                hashes,
                aesKey,
                kdcHost=kdcHost,
                useCache=useCache,
            )
            if res is not True:
                raise
            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}{used_ccache} {self.mark_pwned()}")
            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", self.domain, self.logger, self.config)
            return True
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            return False
        except Exception:
            error_msg = self.handle_mssql_reply()
            self.logger.fail(f"{self.domain}\\{self.username}:{used_ccache} {error_msg if error_msg else ''}")
            return False

    @reconnect_mssql
    def plaintext_login(self, domain, username, password):
        self.password = password
        self.username = username
        self.domain = domain

        try:
            res = self.conn.login(None, self.username, self.password, self.domain, None, not self.args.local_auth)
            if res is not True:
                raise
            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.password)} {self.mark_pwned()}")
            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", self.domain, self.logger, self.config)
            return True
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            return False
        except Exception:
            error_msg = self.handle_mssql_reply()
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.password)} {error_msg if error_msg else ''}")
            return False

    @reconnect_mssql
    def hash_login(self, domain, username, ntlm_hash):
        self.username = username
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""

        if ntlm_hash.find(":") != -1:
            self.lmhash, self.nthash = ntlm_hash.split(":")
        else:
            self.nthash = ntlm_hash

        try:
            res = self.conn.login(None, self.username, "", self.domain, f"{self.lmhash}:{self.nthash}", not self.args.local_auth)
            if res is not True:
                raise
            self.check_if_admin()
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {self.mark_pwned()}")
            if not self.args.local_auth and self.username != "":
                add_user_bh(self.username, self.domain, self.logger, self.config)
            if self.admin_privs:
                add_user_bh(f"{self.hostname}$", self.domain, self.logger, self.config)
            return True
        except BrokenPipeError:
            self.logger.fail("Broken Pipe Error while attempting to login")
            return False
        except Exception:
            error_msg = self.handle_mssql_reply()
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(self.nthash)} {error_msg if error_msg else ''}")
            return False

    def mssql_query(self):
        if self.conn.lastError:
            # Invalid connection
            return None
        query = self.args.mssql_query
        self.logger.info(f"Query to run:\n{query}")
        try:
            raw_output = self.conn.sql_query(query)
            self.logger.info("Executed MSSQL query")
            self.logger.debug(f"Raw output: {raw_output}")
            for data in raw_output:
                if isinstance(data, dict):
                    for key, value in data.items():
                        if key:
                            self.logger.highlight(f"{key}:{value}")
                        else:
                            self.logger.highlight(f"{value}")
                else:
                    self.logger.fail("Unexpected output")
        except Exception as e:
            self.logger.exception(f"Failed to excuted MSSQL query, reason: {e}")
            return None
        return raw_output

    @requires_admin
    def execute(self, payload=None, get_output=False):
        payload = self.args.execute if not payload and self.args.execute else payload
        if not payload:
            self.logger.error("No command to execute specified!")
            return None

        get_output = True if not self.args.no_output else get_output
        self.logger.debug(f"{get_output=}")

        try:
            exec_method = MSSQLEXEC(self.conn, self.logger)
            output = exec_method.execute(payload)
            self.logger.debug(f"Output: {output}")
        except Exception as e:
            self.logger.fail(f"Execute command failed, error: {e!s}")
            return False
        else:
            self.logger.success("Executed command via mssqlexec")
            if output:
                output_lines = StringIO(output).readlines()
                for line in output_lines:
                    self.logger.highlight(line.strip())
        return output

    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, obfs=False, encode=False):
        payload = self.args.ps_execute if not payload and self.args.ps_execute else payload
        if not payload:
            self.logger.error("No command to execute specified!")
            return None

        response = []
        obfs = obfs if obfs else self.args.obfs
        encode = encode if encode else not self.args.no_encode
        force_ps32 = force_ps32 if force_ps32 else self.args.force_ps32
        get_output = True if not self.args.no_output else get_output

        self.logger.debug(f"Starting PS execute: {payload=} {get_output=} {methods=} {force_ps32=} {obfs=} {encode=}")
        amsi_bypass = self.args.amsi_bypass[0] if self.args.amsi_bypass else None
        self.logger.debug(f"AMSI Bypass: {amsi_bypass}")

        if os.path.isfile(payload):
            self.logger.debug(f"File payload set: {payload}")
            with open(payload) as commands:
                response = [self.execute(create_ps_command(c.strip(), force_ps32=force_ps32, obfs=obfs, custom_amsi=amsi_bypass, encode=encode), get_output) for c in commands]
        else:
            response = [self.execute(create_ps_command(payload, force_ps32=force_ps32, obfs=obfs, custom_amsi=amsi_bypass, encode=encode), get_output)]

        self.logger.debug(f"ps_execute response: {response}")
        return response

    @requires_admin
    def put_file(self):
        self.logger.display(f"Copy {self.args.put_file[0]} to {self.args.put_file[1]}")
        with open(self.args.put_file[0], "rb") as f:
            try:
                data = f.read()
                self.logger.display(f"Size is {len(data)} bytes")
                exec_method = MSSQLEXEC(self.conn, self.logger)
                exec_method.put_file(data, self.args.put_file[1])
                if exec_method.file_exists(self.args.put_file[1]):
                    self.logger.success("File has been uploaded on the remote machine")
                else:
                    self.logger.fail("File does not exist on the remote system... error during upload")
            except Exception as e:
                self.logger.fail(f"Error during upload : {e}")

    @requires_admin
    def get_file(self):
        remote_path = self.args.get_file[0]
        download_path = self.args.get_file[1]
        self.logger.display(f'Copying "{remote_path}" to "{download_path}"')

        try:
            exec_method = MSSQLEXEC(self.conn, self.logger)
            exec_method.get_file(self.args.get_file[0], self.args.get_file[1])
            self.logger.success(f'File "{remote_path}" was downloaded to "{download_path}"')
        except Exception as e:
            self.logger.fail(f'Error reading file "{remote_path}": {e}')
            if os.path.getsize(download_path) == 0:
                os.remove(download_path)

    # We hook these functions in the tds library to use nxc's logger instead of printing the output to stdout
    # The whole tds library in impacket needs a good overhaul to preserve my sanity
    def handle_mssql_reply(self):
        for keys in self.conn.replies:
            for _i, key in enumerate(self.conn.replies[keys]):
                if key["TokenType"] == TDS_ERROR_TOKEN:
                    error_msg = f"({key['MsgText'].decode('utf-16le')} Please try again with or without '--local-auth')"
                    self.conn.lastError = SQLErrorException(f"ERROR: Line {key['LineNumber']:d}: {key['MsgText'].decode('utf-16le')}")
                    return error_msg
                elif key["TokenType"] == TDS_INFO_TOKEN:
                    return f"({key['MsgText'].decode('utf-16le')})"
                elif key["TokenType"] == TDS_LOGINACK_TOKEN:
                    return f"(ACK: Result: {key['Interface']} - {key['ProgName'].decode('utf-16le')} ({key['MajorVer']:d}{key['MinorVer']:d} {key['BuildNumHi']:d}{key['BuildNumLow']:d}) )"
                elif key["TokenType"] == TDS_ENVCHANGE_TOKEN and key["Type"] in (
                    TDS_ENVCHANGE_DATABASE,
                    TDS_ENVCHANGE_LANGUAGE,
                    TDS_ENVCHANGE_CHARSET,
                    TDS_ENVCHANGE_PACKETSIZE,
                ):
                    record = TDS_ENVCHANGE_VARCHAR(key["Data"])
                    if record["OldValue"] == "":
                        record["OldValue"] = "None".encode("utf-16le")
                    elif record["NewValue"] == "":
                        record["NewValue"] = "None".encode("utf-16le")
                    if key["Type"] == TDS_ENVCHANGE_DATABASE:
                        _type = "DATABASE"
                    elif key["Type"] == TDS_ENVCHANGE_LANGUAGE:
                        _type = "LANGUAGE"
                    elif key["Type"] == TDS_ENVCHANGE_CHARSET:
                        _type = "CHARSET"
                    elif key["Type"] == TDS_ENVCHANGE_PACKETSIZE:
                        _type = "PACKETSIZE"
                    else:
                        _type = f"{key['Type']:d}"
                    return f"(ENVCHANGE({_type}): Old Value: {record['OldValue'].decode('utf-16le')}, New Value: {record['NewValue'].decode('utf-16le')})"

    def rid_brute(self, max_rid=None):
        entries = []
        if not max_rid:
            max_rid = int(self.args.rid_brute)

        try:
            # Query domain
            domain = self.conn.sql_query("SELECT DEFAULT_DOMAIN()")[0][""]

            # Query known group to determine raw SID & convert to canon
            raw_domain_sid = self.conn.sql_query(f"SELECT SUSER_SID('{domain}\\Domain Admins')")[0][""]
            domain_sid = SID(bytes.fromhex(raw_domain_sid.decode())).formatCanonical()[:-4]
        except Exception as e:
            self.logger.fail(f"Error parsing SID. Not domain joined?: {e}")

        so_far = 0
        simultaneous = 1000
        for _j in range(max_rid // simultaneous + 1):
            sids_to_check = (max_rid - so_far) % simultaneous if (max_rid - so_far) // simultaneous == 0 else simultaneous
            if sids_to_check == 0:
                break

            # Batch query multiple sids at a time
            sid_queries = [f"SELECT SUSER_SNAME(SID_BINARY(N'{domain_sid}-{i:d}'))" for i in range(so_far, so_far + sids_to_check)]
            raw_output = self.conn.sql_query(";".join(sid_queries))

            for n, item in enumerate(raw_output):
                username = item[""]
                if username == "NULL":
                    continue
                rid = so_far + n
                self.logger.highlight(f"{rid}: {username}")
                entries.append(
                    {
                        "rid": rid,
                        "domain": domain,
                        "username": username.split("\\")[1],
                    }
                )

            so_far += simultaneous
        return entries
