from nxc.helpers.misc import CATEGORY
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5 import rrp
from impacket.smbconnection import SessionError
from configparser import ConfigParser


class NXCModule:
    """Module by @NeffIsBack
    Based on the paper "Onelogon: Taking over Active Directory Accounts via Netlogon": https://softsec.rub.de/files/pdf/woot2026-onelogon.pdf
    """

    name = "onelogon"
    description = "Scan GPOs and registry for machine accounts vulnerable to Onelogon"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        def output_callback(data):
            self.gpo_data += data

        found_dacls = []

        policies = connection.conn.listPath("SYSVOL", f"{connection.targetDomain}/Policies/*")
        for policy in policies:
            # Skip "." and ".." directory pointers to avoid path errors
            if policy.get_longname() in [".", ".."]:
                continue

            try:
                self.gpo_data = b""
                connection.conn.getFile("SYSVOL", f"{connection.targetDomain}/Policies/{policy.get_longname()}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf", output_callback)

                try:
                    decoded_data = self.gpo_data.decode("utf-8")
                except UnicodeDecodeError:
                    context.log.debug(f"Failed to decode GPO data for policy {policy.get_shortname()} as UTF-8, trying UTF-16...")
                    decoded_data = self.gpo_data.decode("utf-16")

                # Use strict=False and interpolation=None to safely handle Windows INI quirks and % variables.
                # Some sections (e.g. [Service General Setting]) use value-less CSV-style rows like:
                # "WinRM",2,""
                # which require allow_no_value=True to avoid ParsingError.
                config_parser = ConfigParser(strict=False, interpolation=None, allow_no_value=True)
                config_parser.read_string(decoded_data)

                for section in config_parser.sections():
                    for key, value in config_parser.items(section):
                        if key == "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\VulnerableChannelAllowList".lower():
                            context.log.debug(f"Found vulnerable channel allow list: {value}")
                            try:
                                # Strip the surrounding double quotes from the extracted string
                                found_dacls.append({"name": policy.get_shortname(), "data": value[2:].strip('"')})
                            except Exception as e:
                                context.log.error(f"Could not parse Registry Policy (error: {e}): {section} {key} {value}")
            except SessionError as e:
                # Catch and safely ignore expected "file not found" errors for policies without security settings
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "STATUS_NO_SUCH_FILE" in str(e):
                    pass
                else:
                    context.log.debug(f"SMB Session Error reading policy {policy.get_shortname()}: {e}")
            except Exception as e:
                context.log.error(f"Error parsing policy {policy.get_shortname()}, {e.__class__.__name__}: {e}")

        if found_dacls:
            context.log.success(f"Found {len(found_dacls)} matching policies in SYSVOL Share.")
            for dacl in found_dacls:
                context.log.success(f"Found vulnerable channel allow list in policy '{dacl['name']}': '{dacl['data']}'")
        else:
            context.log.error("No matching policies found in SYSVOL Share.")

    def on_admin_login(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            regHandle = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)["phKey"]
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters")["phkResult"]
            value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "VulnerableChannelAllowList")[1].rstrip("\x00")
            context.log.success(f"Found VulnerableChannelAllowList registry configuration: {value}")
        except Exception as e:
            context.log.error(f"Error while querying registry: {e}")
