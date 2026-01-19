"""
NetExec module for RDP Bitmap Cache extraction and reconstruction.

Collects RDP cache files from remote Windows machines via SMB,
downloads them locally, and reconstructs bitmap tiles into viewable images.
Based on bmc-tools by ANSSI-FR (https://github.com/ANSSI-FR/bmc-tools)

Author: Based on bmc-tools by ANSSI-FR, adapted by Claude
License: MIT / CeCILL-2.1 (original bmc-tools)

Usage:
    nxc smb <target> -u <user> -p <pass> -M rdpcache
    nxc smb <target> -u <user> -p <pass> -M rdpcache -o ACTION=enum
    nxc smb <target> -u <user> -p <pass> -M rdpcache -o ACTION=dump
    nxc smb <target> -u <user> -p <pass> -M rdpcache -o ACTION=dump OUTPUT=/path/to/output
"""

import os
import re
import struct
import tempfile
from datetime import datetime
from io import BytesIO
from pathlib import Path

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# =============================================================================
# Embedded RLE Decompression (based on bmc-tools by ANSSI-FR)
# Full implementation with all RLE commands: FGBG_IMAGE, DITHERED_RUN, SET_FG
# =============================================================================

# Bit mask lookup table for FGBG operations
MASK_BIT = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]


def _parse_rle_command(cmd, data, offset):
    """
    Parse RLE command byte and extract command type, count, and extra bytes consumed.
    Returns: (command_type, count, extra_bytes_consumed)
    """
    # Special commands (0xF0-0xFF range)
    if cmd >= 0xF0:
        if cmd in [0xF5, 0xFB, 0xFC, 0xFF]:
            return (-1, 0, 0)  # Invalid/reserved
        elif cmd in [0xFD, 0xFE]:
            return (cmd, 1, 0)  # Single pixel (black/white)
        elif cmd in [0xF9, 0xFA]:
            return (cmd, 8, 0)  # Special FGBG with 8 pixels
        else:
            # 16-bit count follows
            if offset + 2 <= len(data):
                count = struct.unpack_from("<H", data, offset)[0]
                return (cmd, count, 2)
            return (-1, 0, 0)

    # Regular commands with embedded count
    if cmd < 0x40:
        # 0x00-0x3F: 5-bit count (0-31)
        cmd_type = cmd & 0xE0  # Upper 3 bits
        count = cmd & 0x1F
        if count == 0 and offset < len(data):
            count = data[offset] + 1
            return (cmd_type, count, 1)
        return (cmd_type, count, 0)
    elif cmd < 0x80:
        # 0x40-0x7F: 5-bit count
        cmd_type = cmd & 0xE0
        count = cmd & 0x1F
        if count == 0 and offset < len(data):
            count = data[offset] + 1
            return (cmd_type, count, 1)
        return (cmd_type, count, 0)
    else:
        # 0x80-0xEF: 4-bit count
        cmd_type = cmd & 0xF0
        count = cmd & 0x0F
        if count == 0 and offset < len(data):
            count = data[offset] + 1
            return (cmd_type, count, 1)
        return (cmd_type, count, 0)


def decompress_rle(data, width, height):
    """
    Decompress RLE-encoded bitmap data.
    Full implementation based on bmc-tools by ANSSI-FR.
    Supports all RLE command codes including FGBG_IMAGE, DITHERED_RUN, SET_FG.

    Returns: RGBA bytes
    """
    output_size = width * height * 3  # RGB output
    output = bytearray(output_size)
    row_size = width * 3  # Bytes per row

    src_offset = 0
    dst_offset = 0
    fg_color = bytearray([0xff, 0xff, 0xff])  # Default foreground (white)

    try:
        while src_offset < len(data) and dst_offset < output_size:
            cmd = data[src_offset]
            src_offset += 1

            # Parse command and count
            cmd_type, count, extra_bytes = _parse_rle_command(cmd, data, src_offset)
            src_offset += extra_bytes

            if cmd_type == -1:
                continue

            # BLACK (0xFE) - single black pixel
            if cmd == 0xFE:
                if dst_offset + 3 <= output_size:
                    output[dst_offset:dst_offset + 3] = b'\x00\x00\x00'
                    dst_offset += 3

            # WHITE (0xFD) - single white pixel
            elif cmd == 0xFD:
                if dst_offset + 3 <= output_size:
                    output[dst_offset:dst_offset + 3] = b'\xff\xff\xff'
                    dst_offset += 3

            # REGULAR_BG_RUN (0x00-0x1F) or MEGA_MEGA_BG_RUN (0xF0)
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

            # REGULAR_FG_RUN (0x20-0x3F) or MEGA_MEGA_FG_RUN (0xF1)
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

            # LITE_SET_FG_FG_RUN (0xC0-0xCF) or MEGA_MEGA_SET_FG_RUN (0xF6)
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

            # REGULAR_FGBG_IMAGE (0x40-0x5F) or MEGA_MEGA_FGBG_IMAGE (0xF2)
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

            # LITE_SET_FG_FGBG_IMAGE (0xD0-0xDF) or MEGA_MEGA_SET_FGBG_IMAGE (0xF7)
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

            # REGULAR_COLOR_RUN (0x60-0x6F) or MEGA_MEGA_COLOR_RUN (0xF3)
            elif cmd_type == 0x60 or cmd == 0xF3:
                if src_offset + 3 <= len(data):
                    color = data[src_offset:src_offset + 3]
                    src_offset += 3
                    for _ in range(count):
                        if dst_offset + 3 <= output_size:
                            output[dst_offset:dst_offset + 3] = color
                            dst_offset += 3

            # REGULAR_COLOR_IMAGE (0x80-0x8F) or MEGA_MEGA_COLOR_IMAGE (0xF4)
            elif cmd_type == 0x80 or cmd == 0xF4:
                for _ in range(count):
                    if src_offset + 3 <= len(data) and dst_offset + 3 <= output_size:
                        output[dst_offset:dst_offset + 3] = data[src_offset:src_offset + 3]
                        src_offset += 3
                        dst_offset += 3

            # LITE_DITHERED_RUN (0xE0-0xEF) or MEGA_MEGA_DITHERED_RUN (0xF8)
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

            # SPECIAL_FGBG_1 (0xF9) - 8-pixel mask
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

            # SPECIAL_FGBG_2 (0xFA) - 8-pixel mask
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

    # Convert RGB to RGBA
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
    """
    NetExec module to extract and reconstruct RDP Bitmap Cache from remote machines.

    RDP cache files contain 64x64 pixel bitmap tiles that can reveal:
    - Screen content from RDP sessions
    - File names, icons, and UI elements
    - Evidence of user activity and lateral movement
    """

    name = "rdpcache"
    description = "Enumerate RDP settings and extract Bitmap Cache from remote machines"
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
        self.collage_width = 64  # Same as bmc-tools default STRIPE_WIDTH
        self.smart_collage = False

    def options(self, context, module_options):
        """
        Define module options.

        ACTION      Action to perform: enum (default) or dump
                    - enum: Show RDP settings from registry and list users with cache
                    - dump: Download and extract cache files
        OUTPUT      Directory to save extracted cache files and images (default: ./rdpcache_output)
        USERS       Comma-separated list of usernames to target, or 'all' (default: all)
        COLLAGE     Create a collage image from extracted tiles (default: True)
        COLLAGE_WIDTH Number of tiles per row in collage (default: 64, same as bmc-tools)
        SMART       Smart collage ordering - group similar tiles together (default: False)
                    Options: color, edge, brightness, full (combines all methods)
        """
        self.action = module_options.get("ACTION", "enum").lower()
        self.output_dir = module_options.get("OUTPUT", "./rdpcache_output")
        self.target_users = module_options.get("USERS", "all")
        self.create_collage = module_options.get("COLLAGE", "True").lower() in ("true", "1", "yes")
        self.collage_width = int(module_options.get("COLLAGE_WIDTH", "64"))
        self.smart_collage = module_options.get("SMART", "").lower()

    def on_admin_login(self, context, connection):
        """
        Main execution callback when admin login is successful.
        """
        host = connection.host
        hostname = connection.hostname if hasattr(connection, 'hostname') else host

        if self.action == "enum":
            self._action_enum(context, connection, hostname)
        elif self.action == "dump":
            self._action_dump(context, connection, hostname, host)
        else:
            context.log.fail(f"Unknown action: {self.action}. Use 'enum' or 'dump'")

    def _action_enum(self, context, connection, hostname):
        """
        Enumerate RDP settings and list users with cache.
        """
        context.log.display(f"[RDP Cache Enumeration]")

        # Get RDP settings from registry
        rdp_settings = self._get_rdp_settings(context, connection)

        if rdp_settings:
            context.log.display("")
            context.log.display("RDP Client Settings:")
            context.log.display("-" * 50)

            for key, value in rdp_settings.items():
                if value is not None:
                    context.log.display(f"  {key}: {value}")

        # Get Terminal Server (RDP Server) settings
        ts_settings = self._get_terminal_server_settings(context, connection)

        if ts_settings:
            context.log.display("")
            context.log.display("RDP Server Settings:")
            context.log.display("-" * 50)

            for key, value in ts_settings.items():
                if value is not None:
                    context.log.display(f"  {key}: {value}")

        # Get RDP connection history
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

        # Enumerate users with cache
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
        context.log.highlight(f"To extract cache, run with: -o ACTION=dump")

    def _action_dump(self, context, connection, hostname, host):
        """
        Download and extract RDP cache files.
        """
        if not HAS_PIL:
            context.log.fail("Pillow library is required but not installed. Run: pip install Pillow")
            return

        context.log.info(f"Starting RDP cache extraction from {hostname}")

        # Create output directory
        host_output_dir = Path(self.output_dir) / f"{hostname}_{host}"
        host_output_dir.mkdir(parents=True, exist_ok=True)

        # Find user profiles with RDP cache
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

                    # Check file size before downloading (optional - proceed even if fails)
                    file_size = self._get_file_size(connection, cache_file)
                    if file_size == 0:
                        context.log.debug(f"  Skipping {cache_filename} (empty file)")
                        continue

                    size_str = self._format_size(file_size) if file_size else "unknown size"
                    context.log.info(f"  Downloading {cache_filename} ({size_str})...")

                    # Download cache file
                    cache_data = self._download_file(context, connection, cache_file)

                    if not cache_data:
                        context.log.fail(f"  Failed to download {cache_filename}")
                        continue

                    context.log.info(f"  Downloaded {len(cache_data)} bytes")

                    # Save raw cache file
                    raw_path = user_output_dir / "raw" / cache_filename
                    raw_path.parent.mkdir(parents=True, exist_ok=True)
                    raw_path.write_bytes(cache_data)
                    context.log.info(f"  Saved raw file to {raw_path}")

                    # Debug: show first bytes
                    header_hex = cache_data[:16].hex() if len(cache_data) >= 16 else cache_data.hex()
                    context.log.debug(f"  File header: {header_hex}")

                    # Parse and extract tiles using bmc-tools parser
                    tiles = self._parse_rdp_cache(cache_data, cache_filename)

                    if tiles:
                        context.log.success(f"  Extracted {len(tiles)} tiles from {cache_filename}")
                        all_tiles.extend(tiles)

                        # Save individual tiles
                        tiles_dir = user_output_dir / "tiles"
                        tiles_dir.mkdir(parents=True, exist_ok=True)

                        for idx, tile in enumerate(tiles):
                            tile_path = tiles_dir / f"{cache_filename}_{idx:05d}.bmp"
                            tile.save(str(tile_path), "BMP")
                    else:
                        context.log.fail(f"  No tiles extracted from {cache_filename} (format issue?)")

                except Exception as e:
                    import traceback
                    context.log.fail(f"  Error processing {cache_file}: {str(e)}")
                    context.log.debug(traceback.format_exc())

            # Create collage if enabled
            if self.create_collage and all_tiles:
                collage_path = user_output_dir / f"collage_{username}.png"
                smart_method = self.smart_collage if self.smart_collage else None
                self._create_collage(all_tiles, str(collage_path), smart_method)
                context.log.success(f"  Created collage: {collage_path}")

                # Create smart-sorted collage if requested
                if smart_method:
                    context.log.success(f"  Tiles sorted by: {smart_method}")

            total_tiles += len(all_tiles)

        context.log.success(f"Extraction complete. Total tiles: {total_tiles}")
        context.log.info(f"Output saved to: {host_output_dir}")

    def _get_rdp_settings(self, context, connection):
        """
        Get RDP client settings from registry via remote registry or reg.exe.
        """
        settings = {}

        # Try to read via reg query
        reg_keys = [
            # Terminal Server Client settings
            (r"HKCU\Software\Microsoft\Terminal Server Client", [
                ("BitmapCacheSize", "Bitmap Cache Size (KB)"),
                ("BitmapPersistCacheSize", "Persistent Cache Size (KB)"),
                ("DisableLicenseWarning", "Disable License Warning"),
            ]),
            # RDP-Tcp settings (server-side)
            (r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", [
                ("PortNumber", "RDP Port"),
                ("SecurityLayer", "Security Layer"),
                ("UserAuthentication", "NLA Required"),
                ("MinEncryptionLevel", "Min Encryption Level"),
            ]),
            # Terminal Server settings
            (r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", [
                ("fDenyTSConnections", "RDP Disabled"),
                ("fSingleSessionPerUser", "Single Session Per User"),
                ("AllowTSConnections", "Allow TS Connections"),
            ]),
        ]

        for reg_path, values in reg_keys:
            try:
                # Execute reg query via WMI or SMB exec
                output = self._exec_command(connection, f'reg query "{reg_path}" 2>nul')

                if output:
                    for value_name, display_name in values:
                        # Parse reg output
                        match = re.search(
                            rf'{value_name}\s+REG_(?:DWORD|SZ|EXPAND_SZ)\s+(.+)',
                            output,
                            re.IGNORECASE
                        )
                        if match:
                            val = match.group(1).strip()
                            # Convert hex to int for DWORD
                            if val.startswith("0x"):
                                val = int(val, 16)
                            settings[display_name] = val

            except Exception as e:
                context.log.debug(f"Failed to query {reg_path}: {e}")

        return settings

    def _get_terminal_server_settings(self, context, connection):
        """
        Get Terminal Server (RDP Server) settings.
        """
        settings = {}

        try:
            # Check if RDP is enabled
            output = self._exec_command(
                connection,
                r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections 2>nul'
            )

            if output:
                match = re.search(r'fDenyTSConnections\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    if val.startswith("0x"):
                        val = int(val, 16)
                    else:
                        val = int(val)
                    settings["RDP Enabled"] = "No" if val == 1 else "Yes"

            # Get RDP port
            output = self._exec_command(
                connection,
                r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber 2>nul'
            )

            if output:
                match = re.search(r'PortNumber\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    if val.startswith("0x"):
                        val = int(val, 16)
                    else:
                        val = int(val)
                    settings["RDP Port"] = val

            # Get NLA setting
            output = self._exec_command(
                connection,
                r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication 2>nul'
            )

            if output:
                match = re.search(r'UserAuthentication\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    if val.startswith("0x"):
                        val = int(val, 16)
                    else:
                        val = int(val)
                    settings["NLA Required"] = "Yes" if val == 1 else "No"

            # Get Security Layer
            output = self._exec_command(
                connection,
                r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer 2>nul'
            )

            if output:
                match = re.search(r'SecurityLayer\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)', output)
                if match:
                    val = match.group(1)
                    if val.startswith("0x"):
                        val = int(val, 16)
                    else:
                        val = int(val)
                    security_layers = {0: "RDP Security", 1: "Negotiate", 2: "TLS"}
                    settings["Security Layer"] = security_layers.get(val, f"Unknown ({val})")

        except Exception as e:
            context.log.debug(f"Failed to get TS settings: {e}")

        return settings

    def _get_rdp_history(self, context, connection):
        """
        Get RDP connection history (MRU - Most Recently Used servers).
        Queries HKU (HKEY_USERS) for all user profiles since HKCU doesn't work remotely.
        """
        history = {}  # {username: [servers]}

        try:
            # First, get list of user SIDs from HKU
            output = self._exec_command(
                connection,
                r'reg query "HKU" 2>nul'
            )

            if not output:
                return history

            # Find user SIDs (S-1-5-21-...)
            sids = re.findall(r'(S-1-5-21-[\d-]+)(?!_Classes)', output)

            for sid in sids:
                user_history = []

                # Query Default MRU for this user
                output = self._exec_command(
                    connection,
                    f'reg query "HKU\\{sid}\\Software\\Microsoft\\Terminal Server Client\\Default" 2>nul'
                )

                if output:
                    matches = re.findall(r'MRU\d+\s+REG_SZ\s+(.+)', output)
                    for match in matches:
                        server = match.strip()
                        if server and server not in user_history:
                            user_history.append(server)

                # Query Servers subkeys for this user
                output = self._exec_command(
                    connection,
                    f'reg query "HKU\\{sid}\\Software\\Microsoft\\Terminal Server Client\\Servers" 2>nul'
                )

                if output:
                    # Parse server names from subkeys
                    matches = re.findall(r'Servers\\([^\s\\]+)', output)
                    for match in matches:
                        server = match.strip()
                        if server and server not in user_history:
                            user_history.append(server)

                if user_history:
                    # Try to resolve SID to username
                    username = self._sid_to_username(connection, sid)
                    history[username or sid] = user_history

        except Exception as e:
            context.log.debug(f"Failed to get RDP history: {e}")

        return history

    def _sid_to_username(self, connection, sid):
        """
        Try to resolve SID to username via registry ProfileList.
        """
        try:
            output = self._exec_command(
                connection,
                f'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}" /v ProfileImagePath 2>nul'
            )

            if output:
                match = re.search(r'ProfileImagePath\s+REG_EXPAND_SZ\s+(.+)', output)
                if match:
                    path = match.group(1).strip()
                    # Extract username from path like C:\Users\username
                    if '\\' in path:
                        return path.split('\\')[-1]
        except Exception:
            pass

        return None

    def _exec_command(self, connection, command):
        """
        Execute a command on the remote machine.
        """
        try:
            # Try using connection's execute method
            if hasattr(connection, 'execute'):
                output = connection.execute(command, True)
                return output

            # Try wmiexec-style execution
            if hasattr(connection, 'wmi'):
                output = connection.wmi(command)
                return output

            # Fallback to smbexec
            if hasattr(connection, 'exec_method'):
                output = connection.exec_method(command)
                return output

            # Direct SMB execution via impacket
            from impacket.dcerpc.v5 import transport, scmr
            from impacket.smbconnection import SMBConnection

            # Use atexec or wmiexec style
            # This is a simplified version
            return None

        except Exception:
            return None

    def _get_file_size(self, connection, remote_path):
        """
        Get file size via SMB.
        """
        share = "C$"

        try:
            # List the file to get its info
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
        """
        Format file size to human readable.
        """
        if size is None:
            return "?"

        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"

    def _enumerate_users_with_cache(self, context, connection):
        """
        Enumerate user profiles and find those with RDP cache files.
        """
        users_with_cache = {}
        share = "C$"

        try:
            users_path = "Users"
            try:
                user_dirs = connection.conn.listPath(share, users_path + "\\*")
            except Exception as e:
                context.log.debug(f"Failed to list Users directory: {e}")
                return users_with_cache

            for entry in user_dirs:
                username = entry.get_longname()

                # Skip system directories
                if username in (".", "..", "All Users", "Default", "Default User", "Public", "desktop.ini"):
                    continue

                if not entry.is_directory():
                    continue

                # Check if we should process this user
                if self.target_users != "all":
                    target_list = [u.strip().lower() for u in self.target_users.split(",")]
                    if username.lower() not in target_list:
                        continue

                # Check for RDP cache directory
                cache_path = f"Users\\{username}\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache"

                try:
                    cache_files = connection.conn.listPath(share, cache_path + "\\*")

                    cache_file_paths = []
                    for cache_entry in cache_files:
                        filename = cache_entry.get_longname()

                        if filename.startswith("Cache") and filename.endswith(".bin"):
                            full_path = f"{cache_path}\\{filename}"
                            cache_file_paths.append(full_path)
                        elif filename.startswith("bcache") and filename.endswith(".bmc"):
                            full_path = f"{cache_path}\\{filename}"
                            cache_file_paths.append(full_path)

                    if cache_file_paths:
                        users_with_cache[username] = cache_file_paths

                except Exception:
                    pass

        except Exception as e:
            context.log.fail(f"Error enumerating users: {str(e)}")

        return users_with_cache

    def _download_file(self, context, connection, remote_path):
        """
        Download a file from the remote machine via SMB.
        """
        share = "C$"

        try:
            file_data = BytesIO()
            # SMB path should use backslashes and not start with backslash
            smb_path = remote_path.replace("/", "\\").lstrip("\\")
            context.log.debug(f"SMB download: \\\\{share}\\{smb_path}")
            connection.conn.getFile(share, smb_path, file_data.write)
            result = file_data.getvalue()
            if len(result) == 0:
                context.log.debug(f"File is empty: {smb_path}")
            return result
        except Exception as e:
            context.log.fail(f"SMB download error: {str(e)}")
            return None

    def _parse_rdp_cache(self, data, filename="", context=None):
        """
        Parse RDP Bitmap Cache file and extract tiles.
        Uses embedded full RLE decompression (based on bmc-tools).
        """
        tiles = []

        if len(data) < 12:
            return tiles

        # Debug: Print header info
        header_hex = data[:32].hex() if len(data) >= 32 else data.hex()
        header_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:32])
        print(f"  [DEBUG] File size: {len(data)} bytes")
        print(f"  [DEBUG] Header hex: {header_hex}")
        print(f"  [DEBUG] Header ASCII: {header_ascii}")

        # Detect format and parse
        if data[:8] == b"RDP8bmp\x00":
            print(f"  [DEBUG] Detected RDP8bmp format")
            version = struct.unpack_from("<I", data, 8)[0]
            print(f"  [DEBUG] Version: {version}")
            tiles = self._parse_bin_format(data)
        else:
            print(f"  [DEBUG] Trying BMC format (header not RDP8bmp)")
            tiles = self._parse_bmc_format(data)

        print(f"  [DEBUG] Tiles extracted: {len(tiles)}")
        return tiles

    def _parse_bin_format(self, data):
        """
        Parse RDP8bmp (BIN) cache format.
        Based on bmc-tools by ANSSI-FR - exact logic port.

        Key insight: bmc-tools outputs BMP files directly with bottom-up row order.
        The 256-byte chunk prepending in b_parse_rgb32b + BMP's bottom-up format
        results in correct display. For PIL (which expects top-down), we must
        flip the image after creation.
        """
        tiles = []

        if len(data) < 12:
            return tiles

        # BIN container header: "RDP8bmp\0" + 4-byte version
        signature = data[:8]
        if signature != b"RDP8bmp\x00":
            return tiles

        version = struct.unpack_from("<I", data, 8)[0]
        print(f"  [DEBUG] BIN format version {version}")

        # BIN tile header: key1(4) + key2(4) + width(2) + height(2) = 12 bytes
        tile_hdr_size = 12
        offset = 12  # After file header

        valid_tiles = 0
        empty_tiles = 0

        while offset + tile_hdr_size <= len(data):
            # Parse tile header (same as first 12 bytes of BMC header)
            key1, key2, t_width, t_height = struct.unpack_from("<LLHH", data, offset)
            offset += tile_hdr_size

            # Skip empty entries (key = 0)
            if key1 == 0 and key2 == 0:
                empty_tiles += 1
                continue

            # Validate dimensions
            if t_width == 0 or t_height == 0 or t_width > 256 or t_height > 256:
                print(f"  [DEBUG] Invalid dimensions {t_width}x{t_height}, stopping")
                break

            # BIN uses RGB32 (4 bytes per pixel), uncompressed
            byte_len = 4 * t_width * t_height

            if offset + byte_len > len(data):
                break

            raw_data = data[offset:offset + byte_len]
            offset += byte_len

            valid_tiles += 1
            if valid_tiles <= 5:
                print(f"  [DEBUG] Tile {valid_tiles}: {t_width}x{t_height}, key=0x{key2:08x}{key1:08x}")

            # Parse RGB32 using bmc-tools method for BIN containers
            # BIN format: process in 256-byte chunks, prepend each chunk (reverse order)
            # This is exact port from bmc-tools b_parse_rgb32b
            try:
                d_out = b""
                d_buf = b""

                i = 0
                while i < len(raw_data):
                    # File has BGR format, PIL expects RGB, so swap B and R
                    # raw_data[i:i+3] = B, G, R in file
                    # We need R, G, B for PIL
                    b = raw_data[i]
                    g = raw_data[i+1]
                    r = raw_data[i+2]
                    d_buf += bytes([r, g, b, 0xFF])

                    # When buffer reaches 256 bytes, prepend to output
                    if len(d_buf) == 256:
                        d_out = d_buf + d_out
                        d_buf = b""

                    i += 4

                # Handle remaining bytes (if any)
                if d_buf:
                    d_out = d_buf + d_out

                # Create image - PIL expects top-down data but BMP format is bottom-up
                # The 256-byte chunk reversal puts data in BMP order (bottom-up)
                # So we need to flip vertically for PIL
                img = Image.frombytes("RGBA", (t_width, t_height), d_out)
                img = img.transpose(Image.FLIP_TOP_BOTTOM)
                tiles.append(img)

            except Exception as e:
                if valid_tiles <= 5:
                    print(f"  [DEBUG] Image creation failed: {e}")

        print(f"  [DEBUG] BIN parse complete: {valid_tiles} tiles, {empty_tiles} empty")
        return tiles

    def _parse_bmc_format(self, data):
        """
        Parse BMC (bcache*.bmc) cache format.
        Based on bmc-tools by ANSSI-FR - exact logic port.

        BMC tile header (0x14 = 20 bytes):
        - key1: 4 bytes
        - key2: 4 bytes
        - width: 2 bytes
        - height: 2 bytes
        - t_len: 4 bytes (tile data length)
        - t_params: 4 bytes (flags, bit 0x08 = compressed)
        """
        tiles = []

        # BMC header: 0x14 = 20 bytes
        tile_hdr_size = 0x14  # 20 bytes
        offset = 0

        valid_tiles = 0
        empty_tiles = 0

        while offset + tile_hdr_size <= len(data):
            # Parse BMC tile header - first 12 bytes
            key1, key2, t_width, t_height = struct.unpack_from("<LLHH", data, offset)
            # Last 8 bytes of header: t_len (data size), t_params (flags)
            data_size, t_params = struct.unpack_from("<LL", data, offset + 12)
            offset += tile_hdr_size

            # Skip empty entries
            if key1 == 0 and key2 == 0:
                empty_tiles += 1
                continue

            # Validate dimensions
            if t_width == 0 or t_height == 0 or t_width > 256 or t_height > 256:
                continue

            if data_size == 0 or data_size > 10 * 1024 * 1024:
                continue

            if offset + data_size > len(data):
                break

            raw_data = data[offset:offset + data_size]
            offset += data_size

            # Skip empty tiles
            if raw_data[:16] == b'\x00' * 16:
                empty_tiles += 1
                continue

            valid_tiles += 1
            if valid_tiles <= 5:
                print(f"  [DEBUG] BMC tile {valid_tiles}: {t_width}x{t_height}, size={data_size}")

            # BMC format: determine pixel format from data size
            # Expected uncompressed: width * height * bpp
            expected_rgb32 = t_width * t_height * 4
            expected_rgb24 = t_width * t_height * 3
            expected_rgb16 = t_width * t_height * 2

            try:
                if data_size == expected_rgb32:
                    # RGB32 uncompressed - BMC format uses direct append (no chunk reversal)
                    # File is BGR, PIL expects RGB, so swap B and R
                    d_buf = b""
                    for i in range(0, len(raw_data), 4):
                        b = raw_data[i]
                        g = raw_data[i+1]
                        r = raw_data[i+2]
                        d_buf += bytes([r, g, b, 0xFF])
                    img = Image.frombytes("RGBA", (t_width, t_height), d_buf)

                elif data_size == expected_rgb24:
                    # RGB24 uncompressed - swap B and R for PIL
                    d_buf = b""
                    for i in range(0, len(raw_data), 3):
                        b = raw_data[i]
                        g = raw_data[i+1]
                        r = raw_data[i+2]
                        d_buf += bytes([r, g, b, 0xFF])
                    img = Image.frombytes("RGBA", (t_width, t_height), d_buf)

                elif data_size == expected_rgb16:
                    # RGB565 - _parse_rgb565 already handles channel order correctly
                    d_buf = self._parse_rgb565(raw_data, t_width, t_height)
                    img = Image.frombytes("RGBA", (t_width, t_height), d_buf)

                elif data_size < expected_rgb16:
                    # Compressed - use RLE decompression
                    d_buf = decompress_rle(raw_data, t_width, t_height)
                    img = Image.frombytes("RGBA", (t_width, t_height), d_buf)

                else:
                    # Unknown format, try RGB32 with BGR swap
                    d_buf = b""
                    for i in range(0, min(len(raw_data), expected_rgb32), 4):
                        b = raw_data[i]
                        g = raw_data[i+1]
                        r = raw_data[i+2]
                        d_buf += bytes([r, g, b, 0xFF])
                    # Pad if needed
                    while len(d_buf) < t_width * t_height * 4:
                        d_buf += b"\x00\x00\x00\xFF"
                    img = Image.frombytes("RGBA", (t_width, t_height), d_buf)

                tiles.append(img)

            except Exception as e:
                if valid_tiles <= 5:
                    print(f"  [DEBUG] BMC image failed: {e}")

        print(f"  [DEBUG] BMC parse complete: {valid_tiles} tiles, {empty_tiles} empty")
        return tiles

    def _parse_rgb565(self, data, width, height):
        """Parse RGB565 format - based on bmc-tools."""
        d_buf = b""
        for i in range(0, len(data) - 1, 2):
            pxl = struct.unpack_from("<H", data, i)[0]
            # Extract RGB channels from 565 format
            bl = ((pxl >> 8) & 0xF8) | ((pxl >> 13) & 0x07)
            gr = ((pxl >> 3) & 0xFC) | ((pxl >> 9) & 0x03)
            re = ((pxl << 3) & 0xF8) | ((pxl >> 2) & 0x07)
            d_buf += bytes([re, gr, bl, 0xFF])
        return d_buf

    def _bgr_to_rgba(self, data, width, height):
        """Convert BGR pixel data to RGBA."""
        size = width * height * 4
        rgba = bytearray(size)
        src_idx = 0
        dst_idx = 0

        for _ in range(width * height):
            if src_idx + 2 < len(data):
                rgba[dst_idx] = data[src_idx + 2]      # R
                rgba[dst_idx + 1] = data[src_idx + 1]  # G
                rgba[dst_idx + 2] = data[src_idx]      # B
                rgba[dst_idx + 3] = 255                 # A
            src_idx += 3
            dst_idx += 4

        return bytes(rgba)

    def _rgb565_to_rgba(self, data, width, height):
        """Convert RGB565 pixel data to RGBA."""
        size = width * height * 4
        rgba = bytearray(size)

        for i in range(0, len(data) - 1, 2):
            if i + 1 < len(data):
                pixel = struct.unpack_from("<H", data, i)[0]
                r = ((pixel >> 11) & 0x1F) << 3
                g = ((pixel >> 5) & 0x3F) << 2
                b = (pixel & 0x1F) << 3

                out_idx = (i // 2) * 4
                if out_idx + 3 < size:
                    rgba[out_idx] = r
                    rgba[out_idx + 1] = g
                    rgba[out_idx + 2] = b
                    rgba[out_idx + 3] = 255

        return bytes(rgba)

    def _bgra_to_rgba(self, data, width, height):
        """Convert BGRA pixel data to RGBA."""
        size = width * height * 4
        rgba = bytearray(size)

        for i in range(0, min(len(data), size), 4):
            if i + 3 < len(data):
                rgba[i] = data[i + 2]      # R <- B
                rgba[i + 1] = data[i + 1]  # G
                rgba[i + 2] = data[i]      # B <- R
                rgba[i + 3] = 255          # A

        return bytes(rgba)

    # =========================================================================
    # Smart Collage - Edge-based tile reconstruction
    # =========================================================================

    def _get_tile_edges(self, img):
        """
        Extract edge pixels from a tile for matching with neighbors.
        Returns dict with: right_edge, bottom_edge, left_edge, top_edge, avg_color, brightness
        """
        if img.mode != "RGB":
            img = img.convert("RGB")

        w, h = img.size
        pixels = list(img.getdata())

        # Extract edge strips (list of RGB tuples)
        right_edge = [pixels[y * w + (w - 1)] for y in range(h)]  # Rightmost column
        left_edge = [pixels[y * w] for y in range(h)]  # Leftmost column
        bottom_edge = [pixels[(h - 1) * w + x] for x in range(w)]  # Bottom row
        top_edge = [pixels[x] for x in range(w)]  # Top row

        # Average color
        n = len(pixels)
        avg_r = sum(p[0] for p in pixels) // n
        avg_g = sum(p[1] for p in pixels) // n
        avg_b = sum(p[2] for p in pixels) // n

        # Brightness
        brightness = (avg_r * 299 + avg_g * 587 + avg_b * 114) // 1000

        # Check if tile is mostly uniform (background/empty)
        color_variance = sum(
            (p[0] - avg_r) ** 2 + (p[1] - avg_g) ** 2 + (p[2] - avg_b) ** 2
            for p in pixels
        ) // n
        is_uniform = color_variance < 100  # Low variance = uniform tile

        return {
            "right_edge": right_edge,
            "left_edge": left_edge,
            "bottom_edge": bottom_edge,
            "top_edge": top_edge,
            "avg_color": (avg_r, avg_g, avg_b),
            "brightness": brightness,
            "is_uniform": is_uniform,
            "variance": color_variance
        }

    def _edge_match_score(self, edge1, edge2):
        """
        Calculate how well two edges match (lower = better match).
        edge1 and edge2 are lists of RGB tuples.
        """
        if len(edge1) != len(edge2):
            return float('inf')

        total_diff = 0
        for p1, p2 in zip(edge1, edge2):
            total_diff += abs(p1[0] - p2[0]) + abs(p1[1] - p2[1]) + abs(p1[2] - p2[2])

        return total_diff / len(edge1)

    def _color_distance(self, c1, c2):
        """Calculate color distance between two RGB tuples."""
        return ((c1[0] - c2[0]) ** 2 + (c1[1] - c2[1]) ** 2 + (c1[2] - c2[2]) ** 2) ** 0.5

    def _sort_tiles_by_similarity(self, tiles, method="full"):
        """
        Sort tiles to reconstruct original screen layout.

        Methods:
            - color: Sort by average color similarity
            - brightness: Sort by brightness
            - edge: Sort by edge density (text vs solid)
            - full: Edge-based reconstruction (tries to match tile edges)
        """
        if len(tiles) <= 1:
            return tiles

        print(f"    Analyzing {len(tiles)} tiles...")

        # Extract features for all tiles
        features = []
        for i, tile in enumerate(tiles):
            feat = self._get_tile_edges(tile)
            feat["index"] = i
            feat["tile"] = tile
            features.append(feat)

        # Sort based on method
        if method == "brightness":
            features.sort(key=lambda f: f["brightness"])
            return [f["tile"] for f in features]

        elif method == "edge":
            # Sort by variance (uniform tiles first, detailed tiles last)
            features.sort(key=lambda f: f["variance"])
            return [f["tile"] for f in features]

        elif method == "color":
            # Sort by hue
            def color_key(f):
                r, g, b = f["avg_color"]
                max_c = max(r, g, b)
                min_c = min(r, g, b)
                if max_c == min_c:
                    return (0, f["brightness"])
                elif max_c == r:
                    return (1, (g - b) / (max_c - min_c + 0.001))
                elif max_c == g:
                    return (2, (b - r) / (max_c - min_c + 0.001))
                else:
                    return (3, (r - g) / (max_c - min_c + 0.001))
            features.sort(key=color_key)
            return [f["tile"] for f in features]

        else:  # full - edge-based grid reconstruction
            return self._reconstruct_grid(features)

    def _find_taskbar_chain(self, content_tiles, threshold=60):
        """
        Try to find the Windows taskbar - a long horizontal chain of similar-colored tiles.
        Taskbar characteristics:
        - Usually dark/blue colored (Windows 10/11)
        - Spans full screen width
        - Tiles have similar colors and low variance
        - Located at bottom of screen
        """
        # Look for tiles that could be taskbar (dark, low variance, similar)
        taskbar_candidates = []
        for i, feat in enumerate(content_tiles):
            avg_r, avg_g, avg_b = feat["avg_color"]
            brightness = feat["brightness"]
            variance = feat["variance"]

            # Taskbar is usually dark (brightness < 80) or has specific Windows blue
            # Also relatively uniform (low variance)
            is_dark = brightness < 100
            is_uniform_ish = variance < 500

            if is_dark and is_uniform_ish:
                taskbar_candidates.append((i, feat))

        return taskbar_candidates

    def _build_chain_from_tile(self, start_feat, content_tiles, available, threshold=60):
        """Build a horizontal chain starting from a tile, extending both left and right."""
        chain = [start_feat]

        # Extend RIGHT
        while True:
            current = chain[-1]
            best_match = None
            best_score = float('inf')

            for idx in available:
                candidate = content_tiles[idx]
                score = self._edge_match_score(current["right_edge"], candidate["left_edge"])
                # Also check color similarity for taskbar
                color_diff = self._color_distance(current["avg_color"], candidate["avg_color"])
                combined = score + color_diff * 0.3
                if combined < best_score:
                    best_score = combined
                    best_match = idx

            if best_match is not None and best_score < threshold:
                chain.append(content_tiles[best_match])
                available.remove(best_match)
            else:
                break

        # Extend LEFT
        while True:
            current = chain[0]
            best_match = None
            best_score = float('inf')

            for idx in available:
                candidate = content_tiles[idx]
                score = self._edge_match_score(candidate["right_edge"], current["left_edge"])
                color_diff = self._color_distance(current["avg_color"], candidate["avg_color"])
                combined = score + color_diff * 0.3
                if combined < best_score:
                    best_score = combined
                    best_match = idx

            if best_match is not None and best_score < threshold:
                chain.insert(0, content_tiles[best_match])
                available.remove(best_match)
            else:
                break

        return chain

    def _reconstruct_grid(self, features):
        """
        Reconstruct original tile grid by matching edges.

        Algorithm:
        1. Try to find taskbar (long uniform horizontal strip) to determine screen width
        2. Build horizontal chains by matching right/left edges
        3. Remove duplicate chains (from different screen states)
        4. Assemble vertically with taskbar at bottom
        """
        if not features:
            return []

        print(f"    Analyzing tiles for screen reconstruction...")

        # Separate uniform (background) tiles from content tiles
        content_tiles = [f for f in features if not f["is_uniform"]]
        uniform_tiles = [f for f in features if f["is_uniform"]]

        print(f"    Content tiles: {len(content_tiles)}, Background tiles: {len(uniform_tiles)}")

        if not content_tiles:
            return [f["tile"] for f in features]

        # Step 1: Try to find taskbar to determine screen width
        taskbar_candidates = self._find_taskbar_chain(content_tiles)
        print(f"    Found {len(taskbar_candidates)} potential taskbar tiles")

        available = set(range(len(content_tiles)))
        all_chains = []

        # First, try to build chains from taskbar candidates
        taskbar_chain = None
        if taskbar_candidates:
            # Sort by brightness (darkest first - more likely taskbar)
            taskbar_candidates.sort(key=lambda x: x[1]["brightness"])

            for idx, feat in taskbar_candidates:
                if idx not in available:
                    continue

                available.remove(idx)
                chain = self._build_chain_from_tile(feat, content_tiles, available, threshold=50)

                # Taskbar should be long (at least 10 tiles for typical screen)
                if len(chain) >= 10:
                    if taskbar_chain is None or len(chain) > len(taskbar_chain):
                        if taskbar_chain:
                            all_chains.append(taskbar_chain)
                        taskbar_chain = chain
                        print(f"    Potential taskbar found: {len(chain)} tiles")
                else:
                    all_chains.append(chain)

        # Step 2: Build remaining horizontal chains
        while available:
            start_idx = min(available)
            available.remove(start_idx)
            chain = self._build_chain_from_tile(
                content_tiles[start_idx], content_tiles, available, threshold=70
            )
            all_chains.append(chain)

        # Determine screen width from taskbar or longest chain
        if taskbar_chain:
            screen_width_tiles = len(taskbar_chain)
            print(f"    Screen width from taskbar: {screen_width_tiles} tiles ({screen_width_tiles * 64} px)")
        else:
            # Use longest chain as estimate
            all_chains.sort(key=lambda c: len(c), reverse=True)
            screen_width_tiles = len(all_chains[0]) if all_chains else 30
            print(f"    Estimated screen width: {screen_width_tiles} tiles")

        # Update collage width to match detected screen
        self.collage_width = max(screen_width_tiles, 20)

        # Step 3: Remove near-duplicate chains (same screen region from different times)
        def chains_similar(c1, c2):
            """Check if two chains are visually similar (duplicates from different screen states)."""
            if abs(len(c1) - len(c2)) > 3:
                return False

            # Compare average colors
            avg1 = [sum(f["avg_color"][i] for f in c1) / len(c1) for i in range(3)]
            avg2 = [sum(f["avg_color"][i] for f in c2) / len(c2) for i in range(3)]
            color_diff = sum(abs(a - b) for a, b in zip(avg1, avg2))

            return color_diff < 50

        # Deduplicate chains, keeping longest/best
        unique_chains = []
        for chain in sorted(all_chains, key=lambda c: len(c), reverse=True):
            is_duplicate = False
            for existing in unique_chains:
                if chains_similar(chain, existing):
                    is_duplicate = True
                    break
            if not is_duplicate:
                unique_chains.append(chain)

        print(f"    After deduplication: {len(unique_chains)} unique chains (was {len(all_chains)})")

        # Step 4: Assemble chains vertically
        def calc_vertical_match(top_chain, bottom_chain):
            """Calculate vertical alignment score between two chains."""
            best_score = float('inf')
            best_offset = 0
            max_offset = max(len(top_chain), len(bottom_chain))

            for offset in range(-max_offset + 1, max_offset):
                score = 0
                matches = 0

                for i, top_tile in enumerate(top_chain):
                    j = i + offset
                    if 0 <= j < len(bottom_chain):
                        bottom_tile = bottom_chain[j]
                        edge_score = self._edge_match_score(
                            top_tile["bottom_edge"],
                            bottom_tile["top_edge"]
                        )
                        score += edge_score
                        matches += 1

                if matches > 0:
                    avg_score = score / matches - matches * 2  # Bonus for more overlap
                    if avg_score < best_score:
                        best_score = avg_score
                        best_offset = offset

            return best_score, best_offset

        # Start assembly - put taskbar at end (bottom of screen)
        if taskbar_chain and unique_chains:
            # Remove taskbar from regular chains if it got added
            unique_chains = [c for c in unique_chains if c is not taskbar_chain]

        if not unique_chains:
            unique_chains = [taskbar_chain] if taskbar_chain else []

        if len(unique_chains) <= 1:
            result = []
            for chain in unique_chains:
                for feat in chain:
                    result.append(feat["tile"])
            if taskbar_chain and taskbar_chain not in unique_chains:
                for feat in taskbar_chain:
                    result.append(feat["tile"])
            for feat in uniform_tiles:
                result.append(feat["tile"])
            return result

        # Greedy vertical assembly
        assembled = [unique_chains[0]]
        remaining = unique_chains[1:]

        while remaining:
            current_bottom = assembled[-1]
            best_idx = 0
            best_score = float('inf')

            for i, candidate in enumerate(remaining):
                score, _ = calc_vertical_match(current_bottom, candidate)
                if score < best_score:
                    best_score = score
                    best_idx = i

            assembled.append(remaining.pop(best_idx))

        # Add taskbar at the end (bottom)
        if taskbar_chain:
            assembled.append(taskbar_chain)

        print(f"    Assembled {len(assembled)} rows")

        # Build result
        result = []
        for chain in assembled:
            for feat in chain:
                result.append(feat["tile"])

        # Add uniform/background tiles at the end
        for feat in uniform_tiles:
            result.append(feat["tile"])

        print(f"    Reconstructed {len(result)} tiles (screen: {self.collage_width}x? tiles)")
        return result

    def _create_collage(self, tiles, output_path, smart_method=None, reverse_order=False):
        """
        Create a collage image from extracted tiles.
        Based on bmc-tools collage creation logic.

        Args:
            tiles: List of PIL Image tiles
            output_path: Output file path
            smart_method: If set, sort tiles by visual similarity
                         Options: 'color', 'brightness', 'edge', 'full'
            reverse_order: If True, reverse tile order in each row (for BIN format)
        """
        if not tiles:
            return

        # Apply smart sorting if requested
        if smart_method:
            print(f"  Sorting tiles by visual similarity ({smart_method})...")
            tiles = self._sort_tiles_by_similarity(tiles, smart_method)

        tile_size = 64
        cols = self.collage_width

        # Pad tiles list to fill last row completely (like bmc-tools)
        remainder = len(tiles) % cols
        if remainder != 0:
            padding_needed = cols - remainder
            # Create white padding tiles
            for _ in range(padding_needed):
                pad_tile = Image.new("RGB", (tile_size, tile_size), (255, 255, 255))
                tiles.append(pad_tile)

        rows = len(tiles) // cols

        collage_width = cols * tile_size
        collage_height = rows * tile_size

        # Create collage with white background (like bmc-tools)
        collage = Image.new("RGB", (collage_width, collage_height), (255, 255, 255))

        for idx, tile in enumerate(tiles):
            row = idx // cols
            col = idx % cols

            # For BIN format, bmc-tools reverses tile order in each row
            if reverse_order:
                col = cols - 1 - col

            x = col * tile_size
            y = row * tile_size

            # Convert to RGB if needed
            if tile.mode == "RGBA":
                # Paste with white background for transparency
                bg = Image.new("RGB", tile.size, (255, 255, 255))
                bg.paste(tile, mask=tile.split()[3] if len(tile.split()) == 4 else None)
                tile = bg
            elif tile.mode != "RGB":
                tile = tile.convert("RGB")

            # Handle non-64x64 tiles by padding (not resizing to preserve quality)
            if tile.size != (tile_size, tile_size):
                padded = Image.new("RGB", (tile_size, tile_size), (255, 255, 255))
                # Center the tile
                paste_x = (tile_size - tile.size[0]) // 2
                paste_y = (tile_size - tile.size[1]) // 2
                padded.paste(tile, (paste_x, paste_y))
                tile = padded

            collage.paste(tile, (x, y))

        # Save as BMP for maximum quality (like bmc-tools), or PNG if requested
        if output_path.lower().endswith('.bmp'):
            collage.save(output_path, "BMP")
        else:
            # PNG with no compression for quality
            collage.save(output_path, "PNG", compress_level=0)


# Standalone usage for testing
if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="RDP Bitmap Cache Parser with full RLE decompression",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rdpcache.py Cache0001.bin
  python rdpcache.py Cache0001.bin -o ./output
  python rdpcache.py Cache0001.bin --smart full
  python rdpcache.py Cache0001.bin --smart color --cols 30

Smart collage options:
  color      - Group by similar colors (hue-based sorting)
  brightness - Sort from dark to light
  edge       - Sort by edge density (solid -> detailed)
  full       - Combined similarity (greedy nearest-neighbor)
        """
    )

    parser.add_argument("cache_file", help="RDP cache file to parse (Cache*.bin or bcache*.bmc)")
    parser.add_argument("-o", "--output", default="./rdpcache_extracted",
                        help="Output directory (default: ./rdpcache_extracted)")
    parser.add_argument("--smart", choices=["color", "brightness", "edge", "full"],
                        help="Smart collage ordering method")
    parser.add_argument("--cols", type=int, default=64,
                        help="Tiles per row in collage (default: 64, same as bmc-tools)")
    parser.add_argument("--no-collage", action="store_true",
                        help="Don't create collage, only extract tiles")

    args = parser.parse_args()

    if not HAS_PIL:
        print("Error: Pillow library required. Install with: pip install Pillow")
        sys.exit(1)

    cache_file = args.cache_file
    output_dir = args.output
    cache_filename = os.path.basename(cache_file)

    with open(cache_file, "rb") as f:
        data = f.read()

    print(f"Parsing {cache_file} ({len(data)} bytes)...")
    print("Using embedded full RLE decompression (based on bmc-tools)")

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
            if args.smart:
                # Smart collage - width will be auto-detected for 'full' mode
                smart_collage_path = os.path.join(output_dir, f"collage_smart_{args.smart}.bmp")
                module._create_collage(tiles, smart_collage_path, args.smart)
                print(f"Created smart collage ({args.smart}): {smart_collage_path}")
                print(f"  (detected width: {module.collage_width} tiles)")
            else:
                # Regular collage - use BMP for maximum quality like bmc-tools
                collage_path = os.path.join(output_dir, "collage.bmp")
                module._create_collage(tiles, collage_path)
                print(f"Created collage: {collage_path}")
