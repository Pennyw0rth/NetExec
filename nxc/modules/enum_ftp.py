from ftplib import FTP
import os

class NXCModule:
    """
    Module by: @m7arm4n
    """
    name = "enum_ftp"
    description = "Advance FTP enumeration - Custom search filter"
    supported_protocols = ["ftp"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        DEPTH     = Max recursion depth (default: 5)
        PATH      = Starting path (default: /)
        PERM      = Filter by octal (600,644,777,700+ etc.)
        TEXT      = Search filename (pass,db,.php,wallet etc.)
        DOWNLOAD  = yes/no → auto-download matching files (default: no)
        """
        self.max_depth = int(module_options.get("DEPTH", "5"))
        self.start_path = module_options.get("PATH", "/").strip()
        if self.start_path != "/":
            self.start_path = self.start_path.rstrip("/")

        # Filters
        perm_filter = module_options.get("PERM", "").strip()
        self.allowed_perms = set()
        if perm_filter:
            if "+" in perm_filter:
                base = int(perm_filter.replace("+", ""), 8)
                for p in range(base, 0o1000):
                    self.allowed_perms.add(f"{p:03o}")
            else:
                for p in [x.strip() for x in perm_filter.split(",") if x.strip()]:
                    self.allowed_perms.add(f"{int(p, 8):03o}")

        text_filter = module_options.get("TEXT", "").strip()
        self.search_terms = [term.strip().lower() for term in text_filter.replace(",", " ").split() if term.strip()]

        # DOWNLOAD option
        self.download = module_options.get("DOWNLOAD", "no").lower() in ("yes", "y", "1", "true")

        # Build filter message
        filters = []
        if self.allowed_perms: filters.append(f"PERM={','.join(sorted(self.allowed_perms))}")
        if self.search_terms:  filters.append(f"TEXT={','.join(self.search_terms)}")
        if self.download:      filters.append("DOWNLOAD=ON")
        self._filter_msg = f"[Filter] {' | '.join(filters) if filters else 'No filters'}"

    def on_login(self, context, connection):
        user = context.username[0] if isinstance(context.username, list) else context.username
        pwd  = context.password[0] if isinstance(context.password, list) else (context.password or "")


        connection.logger.highlight(self._filter_msg)

        host = connection.host
        port = connection.port or 21

        # Create loot directory
        if self.download:
            self.loot_dir = os.path.join("loot", "ftp", host)
            os.makedirs(self.loot_dir, exist_ok=True)
            connection.logger.highlight(f"[Loot] Saving files → {self.loot_dir}/")

        ftp = FTP()
        try:
            ftp.connect(host, port, timeout=15)
            ftp.login(user, pwd)
            connection.logger.highlight("Starting enumeration + looting")
        except Exception as e:
            connection.logger.fail(f"Reconnect failed: {e}")
            return True

        header = f"{'Permissions':<10} {'Octal':>5} {'Size':>12} {'Type':<4} {'Full Path'}"
        connection.logger.highlight(header)
        connection.logger.highlight("-" * 90)

        self.downloaded_count = 0
        try:
            self._enum(ftp, connection.logger, connection.host, self.start_path, depth=0)
        except Exception as e:
            connection.logger.fail(f"Error: {e}")
        finally:
            if self.download:
                connection.logger.highlight(f"[Loot] Downloaded {self.downloaded_count} file(s) → {self.loot_dir}/")
            connection.logger.highlight(f"[Done] Finished • Depth: {self.max_depth}")
            try: ftp.quit()
            except: pass

        return True

    def _enum(self, ftp, logger, host, current_path, depth):
        if depth >= self.max_depth:
            return

        try:
            ftp.cwd(current_path)
        except Exception:
            logger.highlight(f"[Access Denied] {current_path}")
            return

        lines = []
        try:
            ftp.retrlines("LIST", lines.append)
        except Exception:
            logger.highlight(f"[LIST failed] {current_path}")
            return

        for line in lines:
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue

            perms = parts[0]
            size  = parts[4]
            name  = parts[8]
            full_path = f"/{name}" if current_path == "/" else f"{current_path}/{name}".replace("//", "/")
            octal = self._to_octal(perms)
            ftype = "DIR" if perms.startswith('d') else "FILE"

            name_lower = name.lower()

            # Apply filters
            perm_match = not self.allowed_perms or octal in self.allowed_perms
            text_match = not self.search_terms or any(term in name_lower for term in self.search_terms)

            if perm_match and text_match:
                logger.highlight(
                    f"{perms:<10} {octal:>5} {size:>12} {ftype:<4} {full_path}{'/' if ftype=='DIR' else ''}"
                )

                # === AUTO DOWNLOAD FILES ===
                if self.download and ftype == "FILE":
                    safe_name = name.replace("/", "_").replace("\\", "_")
                    local_path = os.path.join(self.loot_dir, safe_name)

                    try:
                        with open(local_path, "wb") as f:
                            ftp.retrbinary(f"RETR {full_path}", f.write)
                        logger.highlight(f" → DOWNLOADED → {local_path}")
                        self.downloaded_count += 1
                    except Exception as e:
                        logger.highlight(f" → DOWNLOAD FAILED {full_path}: {e}")

            # Recurse into dirs
            if ftype == "DIR" and name not in (".", ".."):
                if depth + 1 < self.max_depth:
                    self._enum(ftp, logger, host, full_path, depth + 1)

        if current_path != "/":
            try: ftp.cwd("..")
            except: pass

    def _to_octal(self, perms):
        if len(perms) < 10: return "???"
        val = 0
        for c in perms[1:10]:
            val = (val << 1) | (1 if c != '-' else 0)
        return f"{val:03o}"