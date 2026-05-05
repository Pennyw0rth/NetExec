import json
import ntpath
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from nxc.config import process_secret
from nxc.helpers.misc import CATEGORY
from nxc.helpers.ldap import parse_ldap_timestamp, query_ldap_gpos
from nxc.helpers.smb import get_share_security_descriptor, parse_dacl_aces
from nxc.paths import NXC_PATH
from nxc.protocols.smb.samrfunc import LSAQuery

GUID_PATTERN = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")


class NXCModule:
    """Module by @Marshall-Hallenbeck
    Do things with Group Policy Objects (GPOs) in Active Directory
    """

    name = "gpos"
    description = "Do things with Group Policy Objects (GPOs) in Active Directory"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.context = None
        self.module_options = None
        self.gpo_name = None
        self.fuzzy_search = False
        self.all_props = False
        self.download = True
        self.download_dest = "Retrieved_GPOs"
        self.list_permissions = False

    def options(self, context, module_options):
        """
        NAME        Name of the GPO (default retrieve all GPOs)
        FUZZY       Fuzzy search for name of GPOs (using wildcards)
        ALL_PROPS   Retrieve all properties of the GPO (default is name, guid, and sysfile path)
        DOWNLOAD    Download the GPOs to the local machine (default is True)
        DEST        Destination folder for downloaded GPOs (default is "Retrieved_GPOs")
        LIST_PERMISSIONS List permissions for the GPOs (default is False)
        """
        self.gpo_name = module_options.get("NAME")
        self.fuzzy_search = module_options.get("FUZZY", "False").lower() == "true"
        self.all_props = module_options.get("ALL_PROPS", "False").lower() == "true"
        self.download = module_options.get("DOWNLOAD", "True").lower() == "true"
        self.download_dest = module_options.get("DEST", "Retrieved_GPOs")
        self.list_permissions = module_options.get("LIST_PERMISSIONS", "False").lower() == "true"
        context.log.debug(f"Module options: {self.gpo_name=}, {self.fuzzy_search=}, {self.all_props=}, {self.download=}, {self.download_dest=}, {self.list_permissions=}")

    def on_login(self, context, connection):
        gpo_ldap_map = query_ldap_gpos(
            connection.host,
            connection.domain,
            connection.username,
            connection.password,
            connection.lmhash,
            connection.nthash,
            connection.aesKey,
            connection.kdcHost,
            connection.kerberos,
            context.log,
        )

        if gpo_ldap_map is not None:
            context.log.display(f"Queried {len(gpo_ldap_map)} GPOs via LDAP, enumerating SYSVOL via SMB")
        else:
            context.log.display("LDAP query failed, falling back to SMB-only (names may show as 'Unknown')")

        policies = connection.conn.listPath("SYSVOL", f"{connection.domain}\\Policies\\*")
        context.log.debug(f"Found policies path: {connection.domain}\\Policies")

        gpos_found = []

        for item in policies:
            item_name = item.get_longname()
            context.log.debug(f"Item: {item}, Item name: {item_name}")
            if item_name not in [".", ".."] and item.is_directory() and GUID_PATTERN.match(item_name):
                gpo_guid = item_name
                gpo_path = ntpath.join(f"{connection.domain}", "Policies", f"{gpo_guid}")

                ldap_data = gpo_ldap_map.get(gpo_guid.upper()) if gpo_ldap_map else None
                display_name = ldap_data["displayName"] if ldap_data else self.get_gpo_display_name_from_sysvol(context, connection, gpo_path)

                if self.gpo_name:
                    match = self.gpo_name.lower() in display_name.lower() if self.fuzzy_search else self.gpo_name.lower() == display_name.lower()
                    if not match:
                        continue

                gpos_found.append((gpo_guid, gpo_path, display_name, ldap_data))

                context.log.success(f"GPO Found: '{display_name}'")
                context.log.highlight(f"Display Name: {display_name}")
                context.log.highlight(f"GUID: {gpo_guid}")
                context.log.highlight(f"GPO Path: \\\\SYSVOL\\{gpo_path}")

                if self.all_props and ldap_data:
                    context.log.highlight(f"Version: {ldap_data['versionNumber']}")
                    context.log.highlight(f"Created: {parse_ldap_timestamp(ldap_data['whenCreated'])}")
                    context.log.highlight(f"Modified: {parse_ldap_timestamp(ldap_data['whenChanged'])}")

                if self.list_permissions:
                    self.get_folder_security_info(context, connection, gpo_guid, gpo_path)

                if self.download:
                    context.log.display(f"Downloading GPO {gpo_guid} from SYSVOL share")
                    gpo_dest = Path(self.download_dest) / gpo_guid
                    self.download_gpo(context, connection, gpo_path, gpo_dest, gpo_guid)

        context.log.success(f"GPOs Found: {len(gpos_found)}")

        if gpos_found:
            self.save_gpo_loot(context, connection, gpos_found)

    def save_gpo_loot(self, context, connection, gpos_found):
        """Save GPO information to the NXC loot directory in text and JSON format."""
        loot_dir = Path(NXC_PATH) / "modules" / "gpos" / connection.domain / connection.host
        loot_dir.mkdir(parents=True, exist_ok=True)

        all_gpos_json = []

        for gpo_guid, gpo_path, display_name, ldap_data in gpos_found:
            gpo_dir = loot_dir / gpo_guid
            gpo_dir.mkdir(parents=True, exist_ok=True)

            gpo_info = {
                "guid": gpo_guid,
                "displayName": display_name,
                "sysvolPath": f"\\\\SYSVOL\\{gpo_path}",
            }
            if ldap_data:
                gpo_info["versionNumber"] = ldap_data["versionNumber"]
                gpo_info["whenCreated"] = parse_ldap_timestamp(ldap_data["whenCreated"])
                gpo_info["whenChanged"] = parse_ldap_timestamp(ldap_data["whenChanged"])
                gpo_info["gPCFileSysPath"] = ldap_data["gPCFileSysPath"]

            all_gpos_json.append(gpo_info)

            json_path = gpo_dir / "info.json"
            with open(json_path, "w") as f:
                json.dump(gpo_info, f, indent=4)

            txt_path = gpo_dir / "info.txt"
            with open(txt_path, "w") as f:
                f.write(f"Display Name: {display_name}\n")
                f.write(f"GUID: {gpo_guid}\n")
                f.write(f"SYSVOL Path: \\\\SYSVOL\\{gpo_path}\n")
                if ldap_data:
                    f.write(f"Version: {ldap_data['versionNumber']}\n")
                    f.write(f"Created: {parse_ldap_timestamp(ldap_data['whenCreated'])}\n")
                    f.write(f"Modified: {parse_ldap_timestamp(ldap_data['whenChanged'])}\n")
                    f.write(f"gPCFileSysPath: {ldap_data['gPCFileSysPath']}\n")

        all_json_path = loot_dir / "gpos.json"
        with open(all_json_path, "w") as f:
            json.dump(all_gpos_json, f, indent=4)

        all_txt_path = loot_dir / "gpos.txt"
        with open(all_txt_path, "w") as f:
            f.write(f"GPOs enumerated from {connection.domain} ({connection.host})\n")
            f.write(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"Total: {len(all_gpos_json)}\n")
            f.write("=" * 60 + "\n\n")
            for gpo in all_gpos_json:
                f.write(f"Display Name: {gpo['displayName']}\n")
                f.write(f"GUID: {gpo['guid']}\n")
                f.write(f"SYSVOL Path: {gpo['sysvolPath']}\n")
                if "versionNumber" in gpo:
                    f.write(f"Version: {gpo['versionNumber']}\n")
                    f.write(f"Created: {gpo['whenCreated']}\n")
                    f.write(f"Modified: {gpo['whenChanged']}\n")
                f.write("-" * 60 + "\n\n")

        context.log.display(f"GPO info saved to {loot_dir}")

    def get_gpo_display_name_from_sysvol(self, context, connection, gpo_path):
        """Try to get the display name of a GPO by reading GPT.ini from SYSVOL via SMB"""
        try:
            ini_path = f"{gpo_path}\\GPT.ini"
            context.log.debug(f"GPT.ini path: {ini_path}")
            ini_content = bytearray()

            def callback(data):
                ini_content.extend(data)

            connection.conn.getFile("SYSVOL", ini_path, callback)
            ini_text = ini_content.decode("utf-8", errors="replace")

            for line in ini_text.splitlines():
                if line.lower().startswith("displayname="):
                    return line.strip().split("=", 1)[1]

            return "Unknown"
        except Exception as e:
            context.log.debug(f"Could not read GPO display name: {e}")
            return ntpath.basename(gpo_path)

    def download_gpo(self, context, smb_conn, sysvol_path, dest_folder, guid):
        """Download a GPO from the SYSVOL share using the appropriate method"""
        context.log.debug(f"Downloading GPO {guid} from {sysvol_path} to {dest_folder}")

        original_share = smb_conn.args.share

        try:
            smb_conn.args.share = "SYSVOL"
            smb_conn.download_folder(sysvol_path, dest_folder, recursive=True)
            context.log.success(f"GPO {guid} downloaded to {dest_folder}")
        except Exception as e:
            context.log.fail(f"Error downloading GPO {guid}: {e}")
            if Path(dest_folder).exists():
                try:
                    shutil.rmtree(dest_folder)
                except Exception as cleanup_error:
                    context.log.debug(f"Error cleaning up directory: {cleanup_error}")

            context.log.highlight("To manually download this GPO, use the following command:")
            context.log.highlight(f"nxc smb {smb_conn.host} -u '{smb_conn.username}' -p '{process_secret(smb_conn.password)}' --share SYSVOL --get-folder '{sysvol_path}' '{dest_folder}' --recursive")
        finally:
            smb_conn.args.share = original_share

    def get_folder_security_info(self, context, connection, gpo_guid, gpo_path):
        """Get security information for a GPO folder and analyze permissions."""
        context.log.debug(f"Getting security info for GPO path: {gpo_path}")

        sd = get_share_security_descriptor(connection, "SYSVOL", gpo_path)
        context.log.success("Retrieved security information")

        try:
            lsa_query = LSAQuery(
                connection.username,
                connection.password,
                connection.domain,
                connection.port,
                connection.host,
                connection.host,
                connection.kdcHost,
                connection.aesKey,
                connection.kerberos,
                logger=context.log,
            )
        except Exception as lsa_error:
            context.log.debug(f"Error creating LSAQuery: {lsa_error}")
            return

        def resolve_sid(sid):
            try:
                return lsa_query.lookup_sids([sid])[0]
            except DCERPCSessionError as e:
                context.log.debug(f"Error looking up SID {sid}: {e}")
                return "Unknown (potentially deleted user)"

        parsed = parse_dacl_aces(sd, sid_resolver=resolve_sid)
        if not parsed:
            return

        context.log.highlight(f"Security Descriptor for GPO {gpo_guid}:")

        if parsed["owner"]["sid"]:
            context.log.highlight(f"  Owner SID: {parsed['owner']['sid']} - {parsed['owner']['name']}")
        if parsed["group"]["sid"]:
            context.log.highlight(f"  Group SID: {parsed['group']['sid']} - {parsed['group']['name']}")

        if not parsed["aces"]:
            context.log.highlight("  No DACL found - no access restrictions")
            return

        context.log.highlight(f"  DACL: {len(parsed['aces'])} ACEs (Access Control Entries)")
        for i, ace in enumerate(parsed["aces"]):
            perm_str = ", ".join(ace["permissions"]) if ace["permissions"] else f"0x{ace['raw_mask']:08x}"
            context.log.highlight(f"    ACE {i + 1}: {ace['ace_type']}")
            context.log.highlight(f"         SID: {ace['sid']} - {ace['sid_name']}")
            context.log.highlight(f"         Permissions: {perm_str}")
