class NXCModule:
    name = "presence"
    description = "Traces Domain and Enterprise Admin presence in the target over SMB"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        """There are no module options."""

    def on_login(self, context, connection):
        results = {
            "netbios_name": None,
            "admin_users": set(),
            "matched_dirs": [],
            "matched_tasks": []
        }

        # Get NetBIOS name
        results["netbios_name"] = self.get_netbios_name(context, connection)
        context.log.debug(f"Target NetBIOS Name: {results['netbios_name']}")

        # Collect Domain & Enterprise Admins
        for group in ["Domain Admins", "Enterprise Admins"]:
            command = f'net group "{group}" /domain'
            output = connection.execute(command, True, methods=["smbexec"])
            context.log.debug(f"Raw output for {group}: {output}")
            if output:
                results["admin_users"].update(self.parse_admins(output))
            else:
                context.log.error(f"Failed to retrieve {group} members")

        if not results["admin_users"]:
            context.log.error("No admin users found, stopping execution.")
            return False

        # Check presence in C:\Users
        results["matched_dirs"] = self.check_users_directory(context, connection, results["admin_users"])

        # Check presence in tasklist
        results["matched_tasks"] = self.check_tasklist(context, connection, results["admin_users"], results["netbios_name"])

        # Log all findings together
        self.print_grouped_results(context, connection, results)
        return True

    def get_netbios_name(self, context, connection):
        """Retrieves the NetBIOS name of the target machine."""
        command = "hostname"
        output = connection.execute(command, True, methods=["smbexec"]).strip()
        return output if output else None

    def parse_admins(self, output):
        """Extracts admin usernames from 'net group' command output."""
        lines = output.splitlines()
        users = set()
        capture = False

        for line in lines:
            line = line.strip()
            if "Members" in line:
                capture = True
                continue
            if not line or "The command completed successfully" in line:
                break
            if capture and not any(k in line for k in ["---", "Group name", "Comment"]):
                for user in line.split():
                    users.add(user)
        return users

    def check_users_directory(self, context, connection, admin_users):
        """Checks for admin user folders in both C:\\Users and C:\\Documents and Settings"""
        matched_dirs = []
        admin_users_lower = {user.lower() for user in admin_users}

        for base_path in ["C:\\Users", "C:\\Documents and Settings"]:
            command = f'dir "{base_path}"'
            output = connection.execute(command, True, methods=["smbexec"])
            context.log.debug(f"Raw output for directory {base_path}:\n{output}")

            if not output:
                continue

            for line in output.splitlines():
                parts = line.split()
                if len(parts) > 3:
                    folder_name = parts[-1]
                    folder_name_lower = folder_name.lower()

                    # Match Administrator.* (but not just "Administrator")
                    if folder_name_lower.startswith("administrator.") and folder_name_lower != "administrator":
                        matched_dirs.append(folder_name)
                        continue

                    for user in admin_users_lower:
                        if user != "administrator":
                            if folder_name_lower == user or folder_name_lower.startswith(user + "."):
                                matched_dirs.append(folder_name)

        return matched_dirs

    def check_tasklist(self, context, connection, admin_users, netbios_name):
        """Checks 'tasklist /v' output for admin user presence, excluding local machine Administrator."""
        command = 'tasklist /v'
        output = connection.execute(command, True, methods=["smbexec"])
        context.log.debug(f"Raw output for tasklist:\n{output}")

        matched_tasks = []

        for user in admin_users:
            if user == "Administrator":
                pattern = fr"(?i)^(?!.*{re.escape(netbios_name)}\\Administrator\b).*\\Administrator\b"
                if re.search(pattern, output, re.MULTILINE):
                    matched_tasks.append("Administrator")
            else:
                if user in output:
                    matched_tasks.append(user)

        return matched_tasks

    def print_grouped_results(self, context, connection, results):
        """Logs all results grouped per host in order"""
        host_info = f"{connection.host}    {connection.port}    {results['netbios_name']}"

        if results["admin_users"]:
            context.log.success(f"Identified Admin Users: {', '.join(results['admin_users'])}")

        if results["matched_dirs"]:
            context.log.success(f"Found users in directories:")
            context.log.highlight(', '.join(results['matched_dirs']))
            
        if results["matched_tasks"]:
            context.log.success(f"Found users in tasklist:")
            context.log.highlight(', '.join(results['matched_tasks']))

        if not results["matched_dirs"] and not results["matched_tasks"]:
            context.log.success(f"No matches found in users directory or tasklist.")
