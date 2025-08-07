
import time
from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError


class NXCModule:
    # Mainly based on pssrecon:https://github.com/slygoo/pssrecon

    name = "sccmrecon"
    description = "Gather infomation about a Distribution point of Primary Site Server through winreg"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        """"""

    def options(self, context, module_options):
        """"""

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        self.trigger_winreg(connection.conn, context)

        rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
        rpc.set_smb_connection(connection.conn)

        if connection.kerberos:
            rpc.set_kerberos(connection.kerberos, kdcHost=connection.kdcHost)
        dce = rpc.get_dce_rpc()
        if connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # Open HKEY_LOCAL_MACHINE
        ans = rrp.hOpenLocalMachine(dce)
        hRootKey = ans["phKey"]

        try:
            self.EnumerateSS(dce, hRootKey)
            try:
                self.EnumerateDB(dce, hRootKey)
            except DCERPCException:
                self.context.log.fail("No site Database found")
        except DCERPCException as e:
            if "rpc_s_access_denied" in str(e):
                self.context.log.fail(f"Probably not a primary site server or a distribution point: {e}")
            else:
                self.context.log.fail(f"Unexpected error: {e}")

        dce.disconnect()

    def EnumerateSS(self, dce, hRootKey):
        # Open the target registry key
        hkey = rrp.hBaseRegOpenKey(dce, hRootKey, "SOFTWARE\\Microsoft\\SMS")["phkResult"]

        # Enumerate subkeys
        dwIndex = 0
        subkeys = []
        while True:
            try:
                ans = rrp.hBaseRegEnumKey(dce, hkey, dwIndex) 
                subkeys.append(ans["lpNameOut"][:-1]) 
                dwIndex += 1
            except rrp.DCERPCSessionError as e:
                if "ERROR_NO_MORE_ITEMS" in str(e):  # Stop when no more subkeys
                    break
                else:
                    self.context.log.fail(f"Got unexpected exception: {e}")
        
        for subkey in subkeys:
            if subkey == "DP":
                self.context.log.success("Distribition Point Installed")
                self.EnumerateDP(dce, hRootKey)

            if subkey == "MP":
                self.context.log.success("Management Point Installed")
        
        # Check current logged user (probably sccm admin)
        hkey = rrp.hBaseRegOpenKey(dce, hRootKey, "SOFTWARE\\Microsoft\\SMS\\CurrentUser")["phkResult"]
        value = rrp.hBaseRegQueryValue(dce, hkey, "UserSID")
        self.context.log.success(f"Site Server Current User SID: {value[1][:-1]}")
        self.context.log.display(f"   Resolve with: --query '(objectSid={value[1][:-1]})' sAMAccountName")
          
    def EnumerateDP(self, dce, hRootKey):
        # Check distridution point info
        hkey = rrp.hBaseRegOpenKey(dce, hRootKey, "SOFTWARE\\Microsoft\\SMS\\DP")["phkResult"]

        value = rrp.hBaseRegQueryValue(dce, hkey, "SiteCode")
        self.context.log.display(f"   Site Code: {value[1][:-1]}")

        value = rrp.hBaseRegQueryValue(dce, hkey, "SiteServer")
        self.context.log.display(f"   Site Server: {value[1][:-1]}")

        value = rrp.hBaseRegQueryValue(dce, hkey, "ManagementPoints")
        for mp in value[1][:-1].split("*"):
            self.context.log.display(f"   Management Points: {mp}")

        value = rrp.hBaseRegQueryValue(dce, hkey, "IsPXE")
        if value[1] == 1:
            self.context.log.highlight("       PXE is installed - CRED-1")
        
        value = rrp.hBaseRegQueryValue(dce, hkey, "IsAnonymousAccessEnabled")
        if value[1] == 1:
            self.context.log.highlight("       Anonymous access to Distribution Point is enabled - CRED-6")
            self.context.log.display(f"       http://{self.connection.host}/sms_dp_smspkg$/datalib")
        else:
            self.context.log.display("       Anonymous access to Distribution Point is disabled")

    def EnumerateDB(self, dce, hRootKey):
        # Check for database site
        hkey = rrp.hBaseRegOpenKey(dce, hRootKey, "SOFTWARE\\Microsoft\\SMS\\COMPONENTS\\SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers")["phkResult"]
        
        # Enumerate subkeys
        dwIndex = 0
        subkeys = []
        while True:
            try:
                ans = rrp.hBaseRegEnumKey(dce, hkey, dwIndex)
                subkeys.append(ans["lpNameOut"][:-1]) 
                dwIndex += 1
            except rrp.DCERPCSessionError as e:
                if "ERROR_NO_MORE_ITEMS" in str(e):  # Stop when no more subkeys
                    break
                else:
                    self.context.log.fail(f"Got unexpected exception: {e}")
        
        nbSiteDB = len(subkeys)
        if nbSiteDB == 0:
            self.context.log.success("Local Site Database")
        else:
            for subkey in subkeys:
                self.context.log.success(f"Site Database : {subkey}")
                new_conn = SMBConnection(subkey, subkey)
                if new_conn.isSigningRequired():
                    self.context.log.display(f"       SMB signing: {new_conn.isSigningRequired()}")
                else:
                    self.context.log.highlight(f"       SMB signing: {new_conn.isSigningRequired()} - TAKEOVER-1/2")
                new_conn.close()
      
    def trigger_winreg(self, connection, context):
        # Original idea from https://twitter.com/splinter_code/status/1715876413474025704
        # Basically triggers the RemoteRegistry to start without admin privs
        tid = connection.connectTree("IPC$")
        try:
            connection.openFile(
                tid,
                r"\winreg",
                0x12019F,
                creationOption=0x40,
                fileAttributes=0x80,
            )
        except SessionError as e:
            # STATUS_PIPE_NOT_AVAILABLE error is expected
            context.log.debug(str(e))
        # Give remote registry time to start
        time.sleep(1)