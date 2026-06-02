from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY

# Modified by @Deft_ to add support for the MSSQL protocol


class NXCModule:
    name = "reg-query"
    description = "Performs a registry query on the machine"
    supported_protocols = ["smb", "mssql"]
    category = CATEGORY.ENUMERATION

    REG_TYPE_MAP = {
        rrp.REG_NONE: "REG_NONE",
        rrp.REG_SZ: "REG_SZ",
        rrp.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        rrp.REG_BINARY: "REG_BINARY",
        rrp.REG_DWORD: "REG_DWORD",
        rrp.REG_DWORD_BIG_ENDIAN: "REG_DWORD",
        rrp.REG_LINK: "REG_SZ",
        rrp.REG_MULTI_SZ: "REG_MULTI_SZ",
        rrp.REG_QWORD: "REG_QWORD",
    }
    REG_TYPE_MAP_INV = {v: k for k, v in REG_TYPE_MAP.items()}

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.delete = False
        self.type = None
        self.value = None
        self.key = None
        self.path = None

    def options(self, context, module_options):
        """
        PATH    Registry key path to query
        KEY     Registry key value to retrieve
        VALUE   Registry key value to set (only used for modification)
                Will add a new registry key if the registry key does not already exist
        TYPE    Type of registry to modify, add or delete. Default type : REG_SZ.
                Type supported: REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_LINK, REG_MULTI_SZ, REG_QWORD
        DELETE  If set to True, delete a registry key if it does exist
        """
        self.path = None
        self.key = None
        self.value = None
        self.type = None
        self.delete = False

        if module_options and "PATH" in module_options:
            self.path = module_options["PATH"]
        else:
            context.log.fail("Please provide the path of the registry to query (PATH)")
            return

        if module_options and "KEY" in module_options:
            self.key = module_options["KEY"]
        else:
            context.log.fail("Please provide the registry key to query (KEY)")
            return

        if "VALUE" in module_options:
            self.value = module_options["VALUE"]
            if "TYPE" in module_options:
                type_str = module_options["TYPE"]
                if "WORD" in type_str:
                    try:
                        self.value = int(self.value)
                    except Exception as e:
                        context.log.fail(f"Invalid registry value: {self.value}: {e}")
                        return
                if type_str in self.REG_TYPE_MAP_INV:
                    self.type = self.REG_TYPE_MAP_INV[type_str]
                else:
                    context.log.fail(f"Invalid registry value type specified: {type_str}")
                    return
            else:
                self.type = rrp.REG_SZ

        if module_options and "DELETE" in module_options and module_options["DELETE"].lower() == "true":
            self.delete = True

    def _parse_registry_path(self, full_path):
        hive_map = {
            "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
            "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
            "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
            "HKLM": "HKEY_LOCAL_MACHINE",
            "HKCU": "HKEY_CURRENT_USER",
            "HKCR": "HKEY_CLASSES_ROOT",
        }
        upper = full_path.upper()
        for prefix, full_hive in hive_map.items():
            if upper.startswith(prefix):
                subpath = full_path[len(prefix):].lstrip("\\")
                return full_hive, subpath
        return None, None

    def _registry_smb(self, context, connection, hive, subpath, key):
        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()
        try:
            hive_openers = {
                "HKEY_LOCAL_MACHINE": rrp.hOpenLocalMachine,
                "HKEY_CURRENT_USER": rrp.hOpenCurrentUser,
                "HKEY_CLASSES_ROOT": rrp.hOpenClassesRoot,
            }
            if hive not in hive_openers:
                context.log.fail(f"Unsupported registry hive: {hive}")
                return
            ans = hive_openers[hive](remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, subpath)
            key_handle = ans["phkResult"]

            if self.delete:
                try:
                    rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, key)
                except Exception as e:
                    context.log.fail(f"Registry key {key} does not exist: {e}")
                    return
                rrp.hBaseRegDeleteValue(remote_ops._RemoteOperations__rrp, key_handle, key)
                context.log.success(f"Registry key {key} has been deleted successfully")
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
                return

            if self.value is not None:
                try:
                    _, reg_value = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, key)
                    context.log.highlight(f"Key {key} exists with value {reg_value}")
                except Exception:
                    pass
                rrp.hBaseRegSetValue(remote_ops._RemoteOperations__rrp, key_handle, key, self.type, self.value)
                context.log.success(f"Key {key} has been set to {self.value}")
            else:
                try:
                    _, reg_value = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, key)
                    context.log.highlight(f"{key}: {reg_value}")
                except Exception:
                    if not self.delete:
                        context.log.fail(f"Registry key {key} does not exist")

            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
        except DCERPCException as e:
            context.log.fail(f"DCERPC Error: {e}")
        except Exception as e:
            context.log.fail(f"Error: {e}")
        finally:
            remote_ops.finish()

    def _registry_mssql(self, context, connection, hive, subpath, key):
        if self.delete:
            query = f"EXEC xp_regdeletevalue N'{hive}', N'{subpath}', N'{key}';"
            connection.conn.sql_query(query)
            if connection.conn.lastError:
                context.log.fail(f"Failed to call xp_regdeletevalue: {connection.conn.lastError}")
                return
            else:
                context.log.success(f"Registry key {key} has been deleted successfully")
            return

        if self.value is not None:
            type_str = self.REG_TYPE_MAP.get(self.type, "REG_SZ")
            query = f"EXEC xp_regwrite N'{hive}', N'{subpath}', N'{key}', N'{type_str}', N'{self.value!s}';"
            connection.conn.sql_query(query)
            if connection.conn.lastError:
                context.log.fail(f"Failed to call xp_regwrite: {connection.conn.lastError}")
                return
            else:
                context.log.success(f"Registry value {key} set to {self.value}")
            return

        query = f"EXEC xp_regread N'{hive}', N'{subpath}', N'{key}';"
        rows = connection.conn.sql_query(query)
        if connection.conn.lastError:
            context.log.fail(f"Failed to call xp_regread: {connection.conn.lastError}")
            return
        else:
            if not rows:
                context.log.fail(f"No result for {subpath}\\{key}")
                return
            for row in rows:
                value = row.get("Value")
                data = row.get("Data")
                context.log.highlight(f"{value}: {data}")

    def on_admin_login(self, context, connection):
        hive, subpath = self._parse_registry_path(self.path)
        if not hive:
            context.log.fail(f"Could not parse registry hive from path: {self.path}")
            return

        if context.protocol == "mssql":
            self._registry_mssql(context, connection, hive, subpath, self.key)
        elif context.protocol == "smb":
            self._registry_smb(context, connection, hive, subpath, self.key)
