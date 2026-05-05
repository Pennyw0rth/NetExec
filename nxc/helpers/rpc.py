# DCE/RPC over SMB/TCP using the NXC connection's creds; reuse SMB when already
# logged in so Kerberos delegation (e.g. S4U2Proxy ST) applies to pipe RPC too.
import contextlib

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE


class NXCRPCConnection:
    def __init__(self, connection, force_tcp=False):
        self.connection = connection
        self.force_tcp = force_tcp
        self.dce = None
        self.rpc_transport = None

    def connect(self, named_pipe, interface_uuid, target_ip=None, auth_level=None, string_binding=None, set_remote_host=None, anonymous_rpc=False):
        if string_binding is not None:
            self.rpc_transport = self.create_from_string_binding(string_binding, target_ip, set_remote_host, anonymous_rpc)
        elif self.force_tcp:
            self.rpc_transport = self.create_tcp_transport(target_ip, anonymous_rpc)
        else:
            self.rpc_transport = self.create_smb_transport(named_pipe, target_ip)

        self.dce = self.rpc_transport.get_dce_rpc()

        if self.connection.kerberos and not anonymous_rpc:
            self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        self.dce.connect()

        if auth_level is not None:
            self.dce.set_auth_level(auth_level)

        self.dce.bind(interface_uuid)
        return self.dce

    def disconnect(self):
        if self.dce:
            with contextlib.suppress(Exception):
                self.dce.disconnect()
            self.dce = None

    @property
    def transport(self):
        return self.rpc_transport

    def get_smb_connection(self):
        if self.rpc_transport and hasattr(self.rpc_transport, "get_smb_connection"):
            return self.rpc_transport.get_smb_connection()
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def setup_credentials(self, rpc_transport, anonymous_rpc=False):
        conn = self.connection
        if anonymous_rpc:
            rpc_transport.set_credentials("", "", "", "", "", "")
            rpc_transport.set_kerberos(False, None)
        else:
            rpc_transport.set_credentials(conn.username, conn.password if conn.password else "", conn.domain, conn.lmhash, conn.nthash, conn.aesKey)
            if conn.kerberos:
                rpc_transport.set_kerberos(conn.kerberos, conn.kdcHost)

    def create_smb_transport(self, named_pipe, target_ip=None):
        conn = self.connection

        if conn.conn is not None:
            return transport.SMBTransport(conn.conn.getRemoteHost(), filename=named_pipe, smb_connection=conn.conn,)
        result = transport.SMBTransport(conn.remoteName, conn.port, named_pipe, conn.username, conn.password if conn.password else "", conn.domain, conn.lmhash, conn.nthash, conn.aesKey, doKerberos=conn.kerberos, kdcHost=conn.kdcHost)
        if target_ip or conn.host:
            result.setRemoteHost(target_ip or conn.host)
        return result

    def create_tcp_transport(self, target_ip=None, anonymous_rpc=False):
        conn = self.connection
        target = target_ip or conn.remoteName

        result = transport.DCERPCTransportFactory(rf"ncacn_ip_tcp:{target}")
        result.setRemoteHost(target)
        self.setup_credentials(result, anonymous_rpc)
        return result

    def create_from_string_binding(self, string_binding, target_ip=None, set_remote_host=None, anonymous_rpc=False):
        result = transport.DCERPCTransportFactory(string_binding)

        if target_ip is not None:
            result.setRemoteHost(target_ip)
        elif set_remote_host is not None:
            result.setRemoteHost(set_remote_host)

        self.setup_credentials(result, anonymous_rpc)
        return result
